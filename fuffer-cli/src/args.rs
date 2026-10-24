use clap::Parser;
use std::path::PathBuf;

/* command line argument specification for fuffer execution tracer */
#[derive(Parser, Debug, Clone)]
#[command(
    name = "fuffer",
    author = "fuffer developers",
    version = "0.1.0",
    about = "Real-time user-space and kernel-space function and argument sniffer using eBPF",
    long_about = "fuffer hooks into Linux execution paths via uprobes, uretprobes, kprobes, and kretprobes, intercepting function arguments, return values, and memory payloads without ptrace slowdowns."
)]
pub struct CliArgs {
    /* target process ID to filter and trace */
    #[arg(short, long, help = "Process ID (PID) to trace")]
    pub pid: Option<u32>,

    /* execute a child command and attach probes to it */
    #[arg(short = 'c', long = "cmd", help = "Command and arguments to execute and trace")]
    pub command: Option<String>,

    /* optional symbol name or pattern to hook (sniffs all functions in binary if omitted) */
    #[arg(
        short,
        long,
        help = "Target symbol name or pattern (e.g. 'malloc', 'SSL_*'). Sniffs all functions if omitted"
    )]
    pub sym: Option<String>,

    /* path to target ELF binary or shared object (e.g. /usr/bin/Hyprland or libc.so) */
    #[arg(
        short,
        long,
        help = "Path to target binary or shared library (defaults to /proc/<PID>/exe if PID given, or system libc)"
    )]
    pub bin: Option<PathBuf>,

    /* optional cap on the number of functions to hook when sniffing all symbols */
    #[arg(
        long,
        help = "Maximum number of functions to attach when sniffing all symbols in a binary"
    )]
    pub max_probes: Option<usize>,

    /* kernel symbol name to attach kprobe / kretprobe to (e.g. do_sys_open, tcp_connect) */
    #[arg(short, long, help = "Kernel function name to attach kprobe / kretprobe to")]
    pub kernel: Option<String>,

    /* custom path to compiled eBPF object file (defaults to embedded or target release build) */
    #[arg(long, help = "Optional custom path to compiled fuffer-ebpf bytecode object")]
    pub ebpf_obj: Option<PathBuf>,

    /* verbose logging output */
    #[arg(short, long, help = "Enable verbose debug logs")]
    pub verbose: bool,
}
