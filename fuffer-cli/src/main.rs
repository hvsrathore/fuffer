mod args;
mod elf;
mod loader;
mod printer;

use anyhow::{bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use fuffer_common::FunctionEvent;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = args::CliArgs::parse();

    /* verify required privileges before attempting BPF system operations */
    if !has_required_privileges() {
        eprintln!(
            "{} {}",
            "error:".red().bold(),
            "fuffer requires root privileges (CAP_SYS_ADMIN and CAP_BPF) to load eBPF bytecode and attach probes."
        );
        eprintln!(
            "{} {}",
            "hint:".yellow().bold(),
            "please run with sudo: 'sudo fuffer [options]'"
        );
        std::process::exit(1);
    }

    /* raise file descriptor resource limits to support thousands of concurrent uprobe links */
    raise_fd_limit();

    /* determine target process ID and binary path */
    let mut target_pid = args.pid;
    let mut child_process = None;

    if let Some(ref cmd_str) = args.command {
        println!(
            "/* launching target command: '{}' */",
            cmd_str.bold()
        );
        let child = Command::new("sh")
            .arg("-c")
            .arg(cmd_str)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn child command: {}", cmd_str))?;

        target_pid = Some(child.id());
        child_process = Some(child);
        println!("/* target child PID: {} */", target_pid.unwrap());
    }

    let mut tracer = loader::Tracer::new(args.ebpf_obj.as_deref())
        .context("failed to initialize eBPF tracer")?;

    /* configure target PID filter */
    tracer
        .set_target_pid(target_pid)
        .context("failed to configure target PID filter")?;

    let mut attached_probes_count = 0;

    /* attach uprobes if no kernel probe requested or if explicit binary/symbol given */
    if args.kernel.is_none() || args.sym.is_some() || args.bin.is_some() {
        let target_raw_path: PathBuf = if let Some(ref path) = args.bin {
            path.clone()
        } else if let Some(pid) = target_pid {
            elf::find_binary_for_pid(pid)
                .with_context(|| format!("could not resolve executable path for PID {}", pid))?
        } else {
            elf::find_default_libc()
                .context("could not locate standard C library on system. please supply --bin <PATH>")?
        };

        /* automatically unwrap shell wrapper scripts (e.g. /usr/bin/google-chrome-stable) */
        let binary_path = elf::resolve_elf_binary(&target_raw_path)?;
        if binary_path != target_raw_path {
            println!(
                "/* '{}' is a wrapper script -> resolved underlying ELF binary: {} */",
                target_raw_path.display(),
                binary_path.display().to_string().cyan().bold()
            );
        }

        let sym_pattern_opt = args.sym.as_deref();
        if let Some(pat) = sym_pattern_opt {
            println!(
                "/* inspecting ELF binary: {} for symbol pattern: '{}' */",
                binary_path.display(),
                pat.cyan()
            );
        } else {
            println!(
                "/* inspecting ELF binary: {} (sniffing all function calls) */",
                binary_path.display().to_string().cyan()
            );
        }

        let mut resolved_symbols = elf::resolve_symbols(&binary_path, sym_pattern_opt)
            .with_context(|| format!("failed to resolve symbols in '{}'", binary_path.display()))?;

        /* apply optional user-defined probe limit */
        if let Some(max) = args.max_probes {
            resolved_symbols.truncate(max);
        }

        let total = resolved_symbols.len();
        println!(
            "/* discovered {} function symbols to hook */",
            total.to_string().bold()
        );

        for (idx, sym) in resolved_symbols.iter().enumerate() {
            if total > 50 && (idx + 1) % 500 == 0 {
                println!("/* attaching probes: {}/{}... */", idx + 1, total);
            }

            match tracer.attach_uprobes(&binary_path, &sym.demangled_name, sym.file_offset, target_pid) {
                Ok(()) => {
                    attached_probes_count += 1;
                }
                Err(err) => {
                    if args.verbose {
                        eprintln!(
                            "/* skipping unhookable symbol '{}' at offset 0x{:x}: {} */",
                            sym.name, sym.file_offset, err
                        );
                    }
                }
            }
        }
    }

    /* attach kprobes if kernel symbol is provided */
    if let Some(ref kernel_sym) = args.kernel {
        println!(
            "/* attaching kprobe/kretprobe to kernel symbol: '{}' */",
            kernel_sym.cyan()
        );
        tracer
            .attach_kprobes(kernel_sym)
            .with_context(|| format!("failed to attach kprobes to kernel function {}", kernel_sym))?;
        attached_probes_count += 1;
    }

    if attached_probes_count == 0 {
        bail!("no probes were successfully attached to target binary or kernel");
    }

    println!(
        "/* successfully attached {} probes */",
        attached_probes_count.to_string().green().bold()
    );

    /* extract BPF ring buffer
     *
     * educational systems detail:
     * registering the file descriptor with tokio's AsyncFd allows the runtime to
     * epoll the BPF ring buffer file descriptor asynchronously without busy-waiting.
     */
    let ring_buf = tracer.take_ring_buf()?;
    let mut async_ring_buf = unsafe {
        AsyncFd::register_with_interest(ring_buf, tokio::io::Interest::READABLE)
    }
    .context("failed to register AsyncFd for BPF ring buffer")?;

    println!(
        "/* fuffer active: listening on BPF ring buffer (press Ctrl+C to exit) */\n"
    );

    printer::print_header();

    let symbol_map = Arc::new(tracer.symbol_map);
    let verbose = args.verbose;

    /* live ring buffer consumption loop */
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n/* received termination signal, detaching probes and exiting */");
                break;
            }
            guard = async_ring_buf.readable_mut() => {
                let mut guard = guard.context("error polling ring buffer readiness")?;
                let inner = guard.get_inner_mut();

                while let Some(item) = inner.next() {
                    if item.len() >= std::mem::size_of::<FunctionEvent>() {
                        let event = unsafe { &*(item.as_ptr() as *const FunctionEvent) };
                        let sym_name = if let Some(name) = symbol_map.get(&event.cookie) {
                            name.as_str()
                        } else if let Some(first) = symbol_map.values().next() {
                            first.as_str()
                        } else {
                            "unknown"
                        };

                        printer::print_event(event, sym_name);

                        if verbose && event.payload_len > 0 {
                            let len = (event.payload_len as usize).min(event.payload.len());
                            printer::print_hex_dump(&event.payload[..len]);
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    /* wait for child process if spawned */
    if let Some(mut child) = child_process {
        let _ = child.kill();
        let _ = child.wait();
    }

    Ok(())
}

/* check whether effective user has root privileges (UID 0) */
fn has_required_privileges() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/* raise file descriptor resource limits to prevent EMFILE when hooking thousands of symbols */
fn raise_fd_limit() {
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            let target_limit = 1048576.min(rlim.rlim_max.max(65536));
            rlim.rlim_cur = target_limit;
            rlim.rlim_max = target_limit;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
    }
}
