use anyhow::{bail, Context, Result};
use object::{
    read::elf::FileHeader,
    Endianness, Object, ObjectSection, ObjectSymbol, SymbolKind,
};
use std::fs;
use std::path::Path;

/* resolved target symbol containing name, virtual address, and binary file offset */
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    /* demangled or raw symbol name */
    pub name: String,
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
 */
pub fn resolve_symbols(binary_path: &Path, symbol_pattern: &str) -> Result<Vec<ResolvedSymbol>> {
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
            let matches_pattern = if symbol_pattern.ends_with('*') {
                let prefix = &symbol_pattern[..symbol_pattern.len() - 1];
                name.starts_with(prefix)
            } else {
                name == symbol_pattern || name.contains(symbol_pattern)
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

                /* avoid duplicates if symbol is present in both symtab and dynsym */
                if !matches.iter().any(|s: &ResolvedSymbol| s.name == name && s.file_offset == file_offset) {
                    matches.push(ResolvedSymbol {
                        name: name.to_string(),
                        address,
                        file_offset,
                    });
                }
            }
        }
    }

    if matches.is_empty() {
        bail!(
            "symbol '{}' not found in ELF binary '{}'",
            symbol_pattern,
            binary_path.display()
        );
    }

    Ok(matches)
}

/* discover target binary path from PID via /proc/<PID>/exe symlink */
pub fn find_binary_for_pid(pid: u32) -> Result<std::path::PathBuf> {
    let proc_path = format!("/proc/{}/exe", pid);
    let resolved = fs::read_link(&proc_path)
        .with_context(|| format!("failed to resolve /proc/{}/exe symlink. is the process alive?", pid))?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    /* test elf symbol resolution on host binary */
    fn test_resolve_symbols_on_current_exe() {
        let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/bin/sh"));
        /* test searching for wildcard pattern or common symbols */
        let result = resolve_symbols(&current_exe, "*");
        assert!(result.is_ok(), "failed to parse host ELF binary");
        let symbols = result.unwrap();
        assert!(!symbols.is_empty(), "expected symbols in binary");
    }
}
