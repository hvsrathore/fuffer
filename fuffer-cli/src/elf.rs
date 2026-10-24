use anyhow::{bail, Context, Result};
use object::{
    read::elf::FileHeader,
    Endianness, Object, ObjectSection, ObjectSymbol, SymbolKind,
};
use std::fs;
use std::path::{Path, PathBuf};

/* resolved target symbol containing name, virtual address, and binary file offset */
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    /* raw mangled symbol name from symbol table */
    pub name: String,
    /* demangled human-readable symbol name */
    pub demangled_name: String,
    /* virtual memory address defined in symbol table */
    #[allow(dead_code)]
    pub address: u64,
    /* file offset required by linux uprobe kernel subsystem */
    pub file_offset: u64,
}

/* parse target ELF file to resolve symbols and calculate uprobe file offsets
 *
 * educational systems detail:
 * linux uprobes attach to file offsets, not virtual runtime memory addresses.
 * for position independent executables (PIE) and shared libraries (ET_DYN),
 * the kernel needs the exact offset within the on-disk ELF binary.
 * we calculate this by locating the PT_LOAD segment or section enclosing the
 * symbol's virtual address (st_value) and applying the transformation:
 * file_offset = st_value - segment.p_vaddr + segment.p_offset
 *
 * if symbol_pattern is None, every callable function symbol is matched.
 */
pub fn resolve_symbols(
    binary_path: &Path,
    symbol_pattern: Option<&str>,
) -> Result<Vec<ResolvedSymbol>> {
    let data = fs::read(binary_path)
        .with_context(|| format!("failed to read binary file at {}", binary_path.display()))?;

    let elf_file = object::File::parse(&*data)
        .with_context(|| format!("failed to parse ELF file at {}", binary_path.display()))?;

    let is_pie = match elf_file {
        object::File::Elf64(ref elf) => {
            /* ET_DYN (value 3) indicates shared library or position-independent executable */
            elf.elf_header().e_type(Endianness::Little) == object::elf::ET_DYN
        }
        object::File::Elf32(ref elf) => {
            elf.elf_header().e_type(Endianness::Little) == object::elf::ET_DYN
        }
        _ => false,
    };

    let mut matches = Vec::new();

    /* inspect both static symbols and dynamic symbols (dynsym) */
    let symbols = elf_file.symbols().chain(elf_file.dynamic_symbols());

    for symbol in symbols {
        /* filter for functions or code symbols */
        if symbol.kind() != SymbolKind::Text && symbol.kind() != SymbolKind::Unknown {
            continue;
        }

        if let Ok(name) = symbol.name() {
            if name.is_empty() {
                continue;
            }

            let matches_pattern = match symbol_pattern {
                Some(pat) if pat == "*" || pat.is_empty() => true,
                Some(pat) if pat.ends_with('*') => {
                    let prefix = &pat[..pat.len() - 1];
                    name.starts_with(prefix)
                }
                Some(pat) => name == pat || name.contains(pat),
                /* sniff all functions if no pattern is specified */
                None => true,
            };

            if matches_pattern {
                let address = symbol.address();
                if address == 0 {
                    continue;
                }

                /* compute file offset using enclosing section metadata */
                let file_offset = if is_pie {
                    if let Some(section) = symbol.section_index().and_then(|idx| elf_file.section_by_index(idx).ok()) {
                        let sec_addr = section.address();
                        let (sec_offset, _) = section.file_range().unwrap_or((0, 0));
                        address - sec_addr + sec_offset
                    } else {
                        address
                    }
                } else {
                    /* for non-PIE executables, calculate file offset from file range */
                    if let Some(section) = symbol.section_index().and_then(|idx| elf_file.section_by_index(idx).ok()) {
                        let sec_addr = section.address();
                        let (sec_offset, _) = section.file_range().unwrap_or((0, 0));
                        address.saturating_sub(sec_addr) + sec_offset
                    } else {
                        address
                    }
                };

                if file_offset == 0 {
                    continue;
                }

                /* deduplicate by file offset so multiple aliases to the same instruction do not conflict */
                if !matches.iter().any(|s: &ResolvedSymbol| s.file_offset == file_offset) {
                    let demangled = demangle_symbol(name);
                    matches.push(ResolvedSymbol {
                        name: name.to_string(),
                        demangled_name: demangled,
                        address,
                        file_offset,
                    });
                }
            }
        }
    }

    if matches.is_empty() {
        if let Some(pat) = symbol_pattern {
            bail!(
                "symbol '{}' not found in ELF binary '{}'",
                pat,
                binary_path.display()
            );
        } else {
            bail!(
                "no callable function symbols found in ELF binary '{}'",
                binary_path.display()
            );
        }
    }

    Ok(matches)
}

/* demangle C++ and Rust function signatures into clean human-readable names */
pub fn demangle_symbol(raw_name: &str) -> String {
    /* attempt rust demangling first */
    let rust_demangled = format!("{:#}", rustc_demangle::demangle(raw_name));
    if rust_demangled != raw_name {
        return rust_demangled;
    }

    /* attempt C++ itanium ABI demangling (e.g. for Qt, Hyprland, Chromium) */
    if let Ok(sym) = cpp_demangle::Symbol::new(raw_name) {
        if let Ok(demangled) = sym.demangle() {
            return demangled;
        }
    }

    raw_name.to_string()
}

/* discover target binary path from PID via /proc/<PID>/exe symlink */
pub fn find_binary_for_pid(pid: u32) -> Result<PathBuf> {
    let proc_path = format!("/proc/{}/exe", pid);
    let resolved = fs::read_link(&proc_path)
        .with_context(|| format!("failed to resolve /proc/{}/exe symlink. is the process alive?", pid))?;
    Ok(resolved)
}

/* locate standard C library path on system across common distribution locations */
pub fn find_default_libc() -> Option<PathBuf> {
    let candidates = [
        "/usr/lib/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/lib/libc.so.6",
    ];

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/* inspect a target path to verify it is an ELF binary, automatically unwrapping shell script wrappers
 *
 * educational systems detail:
 * commands in /usr/bin (like google-chrome-stable, firefox, code) are frequently
 * shell wrapper scripts rather than compiled ELF binaries. uprobes attach to
 * machine instructions at binary inode offsets and cannot hook shell scripts.
 * this helper checks for the \x7fELF magic header and, if a shebang script is found,
 * parses exec lines to resolve the actual underlying ELF executable.
 */
pub fn resolve_elf_binary(path: &Path) -> Result<PathBuf> {
    resolve_elf_binary_depth(path, 0)
}

fn resolve_elf_binary_depth(path: &Path, depth: usize) -> Result<PathBuf> {
    if depth > 5 {
        bail!("exceeded maximum recursion depth unwrapping wrapper scripts for '{}'", path.display());
    }

    let meta = fs::metadata(path)
        .with_context(|| format!("failed to access target path '{}'", path.display()))?;

    if !meta.is_file() {
        bail!("target path '{}' is not a regular file", path.display());
    }

    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open file at '{}'", path.display()))?;

    use std::io::Read;
    let mut magic = [0u8; 4];
    let bytes_read = file.read(&mut magic).unwrap_or(0);

    /* check for standard ELF magic header (0x7F, 'E', 'L', 'F') */
    if bytes_read >= 4 && &magic == b"\x7fELF" {
        return Ok(path.to_path_buf());
    }

    /* check for shebang script header ('#', '!') */
    if bytes_read >= 2 && &magic[..2] == b"#!" {
        let content = fs::read_to_string(path).unwrap_or_default();
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let dir_str = dir.to_string_lossy();

        /* replace common script variables like $HERE */
        let substituted = content
            .replace("$HERE", &dir_str)
            .replace("${HERE}", &dir_str);

        for line in substituted.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("exec ") || trimmed.contains(" exec ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                for part in parts {
                    let clean = part.trim_matches(|c| c == '"' || c == '\'' || c == ';');
                    if clean.starts_with('/') {
                        let candidate = PathBuf::from(clean);
                        if candidate.exists() {
                            if let Ok(elf) = resolve_elf_binary_depth(&candidate, depth + 1) {
                                return Ok(elf);
                            }
                        }
                    }
                }
            }
        }

        bail!(
            "target '{}' is a shell script wrapper (starts with '#!'), not an ELF binary.\n\
             eBPF uprobes require a compiled machine-code ELF executable.\n\
             please supply the underlying binary path (e.g. for chrome, use '/opt/google/chrome/chrome')",
            path.display()
        );
    }

    bail!(
        "target '{}' is not an ELF binary (unknown magic header {:?}). eBPF uprobes require a compiled ELF executable.",
        path.display(),
        &magic[..bytes_read]
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /* test elf symbol resolution on host binary */
    fn test_resolve_symbols_on_current_exe() {
        let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/bin/sh"));
        /* test searching for wildcard pattern or all symbols when None */
        let result = resolve_symbols(&current_exe, None);
        assert!(result.is_ok(), "failed to parse host ELF binary");
        let symbols = result.unwrap();
        assert!(!symbols.is_empty(), "expected symbols in binary");
    }

    #[test]
    /* test C++ and Rust symbol demangling */
    fn test_demangle() {
        let cpp_mangled = "_ZN6Layout5Tiled21CScrollTapeController9setOffsetEd";
        let demangled = demangle_symbol(cpp_mangled);
        assert!(demangled.contains("setOffset"), "expected C++ demangling");
    }

    #[test]
    /* test wrapper script unwrap to ELF binary */
    fn test_resolve_elf_binary() {
        let chrome_wrapper = PathBuf::from("/usr/bin/google-chrome-stable");
        if chrome_wrapper.exists() {
            let resolved = resolve_elf_binary(&chrome_wrapper);
            assert!(resolved.is_ok(), "failed to resolve chrome wrapper");
            assert!(resolved.unwrap().ends_with("chrome"));
        }

        let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/bin/sh"));
        assert!(resolve_elf_binary(&current_exe).is_ok());
    }
}
