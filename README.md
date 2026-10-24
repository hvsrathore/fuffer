# fuffer 🔍

<div align="center">

**The "Wireshark for Software Execution"**

*Real-time user-space and kernel-space function call and argument sniffer powered by eBPF in 100% pure Rust.*

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-stable%20%7C%20nightly-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-aya-red.svg)](https://aya-rs.dev/)
[![Linux](https://img.shields.io/badge/kernel-5.8%2B-green.svg)](https://kernel.org/)

</div>

---

Just as a network packet sniffer captures raw Ethernet frames on a network interface card, **`fuffer`** hooks directly into the Linux kernel's tracing subsystem (`uprobes`, `uretprobes`, `kprobes`, `kretprobes`) to intercept function entry points, incoming CPU register arguments, return values, and memory payloads in real time—**without the crippling stop-the-world overhead of `ptrace` debuggers.**

```text
TIME         PID/TID    EVENT   FUNCTION                         ARGUMENTS / PAYLOAD                           RETURN / DURATION
-------------------------------------------------------------------------------------------------------------------------------------
13:28:40.102 4321/4321  ENTER   SSL_read                         0x7f8a100, 0x7ffd000, 0x1000 | "GET /status" -
13:28:40.103 4321/4321  EXIT    SSL_read                         args=[0x7f8a100, 0x7ffd000]                   -> 0x144 (124.2µs)
13:28:41.015 8820/8820  ENTER   Layout::Tiled::setOffset(double) 0x55f9a20, 0x3ff0000, 0x0                     -
13:28:41.015 8820/8820  EXIT    Layout::Tiled::setOffset(double) args=[0x55f9a20, 0x3ff0000]                   -> 0x0 (14.8µs)
13:28:41.512 4321/4325  ENTER   openat                           0xffffff9c, 0x7ffd040, 0x0 | "/etc/hosts"    -
13:28:41.513 4321/4325  EXIT    openat                           args=[0xffffff9c, 0x7ffd040]                  -> 0x3 (18.5µs)
```

---

## Why fuffer?

Traditional execution tracers (`strace`, `ltrace`, `gdb`, `frida`) rely on `ptrace(2)` or code injection. Every single breakpoint incurs multiple full context switches between user and kernel space, frequently slowing target processes down by **10× to 100×**.

| Feature | `ptrace` (`strace` / `gdb`) | `fuffer` (eBPF + Aya) |
| :--- | :--- | :--- |
| **Execution Overhead** | Severe (stops process on each call) | **Near-zero** (kernel JIT hook) |
| **Context Switching** | 4 context switches per trap | **0 context switches** per probe |
| **Safety** | High risk of hanging or crashing target | **Kernel-enforced bytecode safety** |
| **Threading** | Frequent race conditions under high concurrency | **Atomic thread correlation (`pid_tgid`)** |
| **Kernel & User Space** | Primarily user space (`strace` = syscalls only) | **Unified user (`uprobe`) & kernel (`kprobe`)** |
| **Target Toolchain** | Requires debuggers / C compiler | **No toolchain needed on target** |

---

## Architecture

```
+-------------------------------------------------------+
|                    Target Process                     |
|  [ user space function: SSL_write(ssl, buf, len) ]    |
+---------------------------+---------------------------+
                            | (uprobe / uretprobe hit)
                            v
+-------------------------------------------------------+
|                   Linux Kernel (eBPF)                 |
|  1. Read System V AMD64 ABI registers (RDI, RSI, etc.)|
|  2. Correlate entry in BPF Hash Map keyed by PID/TID  |
|  3. On return, capture RAX & elapsed kernel duration  |
|  4. Stream event to lock-free BPF Ring Buffer         |
+---------------------------+---------------------------+
                            | (Zero-Copy Ring Buffer Stream)
                            v
+-------------------------------------------------------+
|                  fuffer CLI (User Space)              |
|  1. Auto-unwraps wrapper scripts (e.g. chrome, code)  |
|  2. Calculates PIE/shared library file offsets        |
|  3. Demangles C++ (Itanium) and Rust function names   |
|  4. Renders live table & ASCII/HEX inspection dumps   |
+-------------------------------------------------------+
```

---

## Key Features

- **Sniff Everything or Filter by Symbol:**
  Leave `--sym` empty to sniff **every single function call** inside a binary, or provide a symbol pattern (`--sym "SSL_*"` or `--sym malloc`).
- **Automatic Script Wrapper Unwrapping:**
  Desktop apps (Chrome, Firefox, VS Code, Discord) are often launched via shell scripts in `/usr/bin`. `fuffer` automatically detects shebang wrapper scripts, follows `exec` paths, and attaches directly to the real underlying ELF binary.
- **Thread-Safe State Correlation:**
  Uses `bpf_get_current_pid_tgid()` to index entry arguments and exit return values in a kernel BPF hash map, preventing race conditions across multi-threaded applications.
- **Zero-Copy BPF Ring Buffer:**
  Streams telemetry lock-free over `BPF_MAP_TYPE_RINGBUF` using Tokio's asynchronous `AsyncFd` notification loop.
- **Dynamic C++ and Rust Demangling:**
  Automatically demangles complex mangled signatures (e.g. `_ZN6Layout5Tiled...`) into clean, readable function signatures.
- **Memory Payload Inspection:**
  Safely reads string arguments and byte buffers directly out of user memory using `bpf_probe_read_user_str_bytes`, rendering optional ASCII/HEX inspection tables with `--verbose`.
- **High-Capacity Probe Scaling:**
  Automatically elevates process file descriptor limits (`RLIMIT_NOFILE`) to safely attach thousands of concurrent uprobes without hitting `EMFILE`.

---

## Workspace Layout

Following the guidelines in [`AGENTS.md`](AGENTS.md), `fuffer` is organized into focused crates:

```text
fuffer/
├── Cargo.toml                  /* workspace manifest */
├── xtask/                      /* build automation orchestrating dual-target compilation */
├── fuffer-common/              /* #[repr(C)] memory-aligned shared ABI structures */
├── fuffer-ebpf/                /* kernel-space eBPF programs (bpfel-unknown-none) */
├── fuffer-cli/                 /* user-space host CLI tool (tokio + aya + clap) */
│   └── src/
│       ├── args.rs             /* CLI arguments parsing */
│       ├── elf.rs              /* ELF parser, script unwrapper, and demangler */
│       ├── loader.rs           /* aya eBPF loader, probe attacher, and map manager */
│       ├── printer.rs          /* live ANSI formatter and HEX payload inspector */
│       └── main.rs             /* privilege check, resource limits, and event loop */
└── README.md
```

---

## Prerequisites

1. **Linux Kernel:** 5.8 or newer (required for BPF Ring Buffer).
2. **Rust Toolchain:**
   - Stable Rust (for the user-space CLI)
   - Nightly Rust with `rust-src` (for compiling eBPF bytecode):
     ```bash
     rustup toolchain install nightly --component rust-src
     ```
3. **bpf-linker:**
   ```bash
   curl -L -o /tmp/bpf-linker.tar.zst https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
   tar --zstd -xvf /tmp/bpf-linker.tar.zst -C ~/.cargo/bin/
   ```
4. **Privileges:** Root access (`sudo`) or `CAP_SYS_ADMIN` and `CAP_BPF` capabilities.

---

## Building

Compile both the eBPF bytecode and the host CLI binary in one command via `xtask`:

```bash
cargo xtask build --release
```

The compiled binary with embedded eBPF bytecode is located at:
`target/release/fuffer-cli`

---

## Usage Guide

### 1. Sniff Every Function Call in a Binary (No `--sym`)
Omit `--sym` to resolve and hook every callable function:
```bash
# Automatically unwraps script wrappers down to the real machine-code ELF:
sudo ./target/release/fuffer-cli --bin /usr/bin/google-chrome-stable

# Sniff every function call inside a compositor or GUI app:
sudo ./target/release/fuffer-cli --bin /usr/bin/Hyprland
```

### 2. Sniff an Active Process by PID
Hook into an already running process:
```bash
# Sniff all function calls made by PID 4321:
sudo ./target/release/fuffer-cli --pid 4321

# Or target specific functions:
sudo ./target/release/fuffer-cli --pid 4321 --sym malloc
```

### 3. Spawn and Sniff a Command
Launch a new command and immediately intercept its calls:
```bash
sudo ./target/release/fuffer-cli --cmd "curl -s https://example.com" --sym "SSL_*" -v
```

### 4. Trace Shared Libraries
Attach to functions inside dynamic shared objects:
```bash
sudo ./target/release/fuffer-cli --bin /usr/lib/libc.so.6 --sym "open*"
```

### 5. Sniff Kernel Functions
Hook kernel-space execution points:
```bash
sudo ./target/release/fuffer-cli --kernel do_sys_open
```

### 6. Inspect Raw Payload Buffers
Pass `-v` / `--verbose` to inspect argument strings and memory buffers as hex dumps:
```bash
sudo ./target/release/fuffer-cli --cmd "cat /etc/hosts" --sym "read*" -v
```

```text
  --- Payload Inspection (HEX & ASCII) ---
  0000: 31 32 37 2e 30 2e 30 2e 31 20 6c 6f 63 61 6c 68  |127.0.0.1 localh|
  0010: 6f 73 74 0a 3a 3a 31 20 20 20 20 20 6c 6f 63 61  |ost.::1     loca|
```

---

## Under the Hood: Systems Engineering

### 1. Register Interception (System V AMD64 ABI)
On x86_64 Linux, arguments are passed in specific hardware registers:
- `arg0`: `RDI`
- `arg1`: `RSI`
- `arg2`: `RDX`
- `arg3`: `RCX`
- `arg4`: `R8`
- `arg5`: `R9`
- `retval`: `RAX`

`fuffer-ebpf` intercepts the saved CPU trap frame (`pt_regs`) directly at function entry before the prologue modifies incoming arguments.

### 2. Uprobe File Offsets & PIE Binaries
Uprobes attach to file offsets within an on-disk binary inode, not runtime virtual memory addresses. For Position Independent Executables (PIE) and shared libraries (`ET_DYN`), `fuffer-cli` computes:

$$\text{file\_offset} = \text{st\_value} - \text{section.sh\_addr} + \text{section.sh\_offset}$$

### 3. Return Trampolines (`uretprobe`)
When a function returns, its return value is in `RAX`. A `uretprobe` modifies the return address on the stack to point to an eBPF return trampoline. When the function returns, control passes to the trampoline which computes latency, extracts `RAX`, and pushes the exit event to the ring buffer before resuming normal execution flow.

---

## Testing

Run unit tests unprivileged:
```bash
cargo test --workspace --exclude fuffer-ebpf
```

---

## License

Dual-licensed under either of:
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
