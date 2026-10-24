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

    /* attach uprobes if symbol pattern is provided */
    if let Some(ref sym_pattern) = args.sym {
        let binary_path: PathBuf = if let Some(ref path) = args.bin {
            path.clone()
        } else if let Some(pid) = target_pid {
            elf::find_binary_for_pid(pid)
                .with_context(|| format!("could not resolve executable path for PID {}", pid))?
        } else {
            /* default to standard C library if no binary specified */
            PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6")
        };

        println!(
            "/* inspecting ELF binary: {} for symbol pattern: '{}' */",
            binary_path.display(),
            sym_pattern
        );

        let resolved_symbols = elf::resolve_symbols(&binary_path, sym_pattern)
            .with_context(|| format!("failed to resolve symbols matching '{}'", sym_pattern))?;

        for sym in &resolved_symbols {
            println!(
                "/* attaching uprobe/uretprobe: symbol='{}' offset=0x{:x} */",
                sym.name.cyan(),
                sym.file_offset
            );
            tracer
                .attach_uprobes(&binary_path, &sym.name, sym.file_offset, target_pid)
                .with_context(|| format!("failed to attach probe for symbol {}", sym.name))?;
            attached_probes_count += 1;
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
        bail!("no probes specified. please supply --sym <SYMBOL> or --kernel <FUNCTION>");
    }

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
