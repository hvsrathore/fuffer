# fuffer 🔍

> **The "Wireshark for Software Execution"** — Real-time user-space and kernel-space function and argument sniffer powered by eBPF in pure Rust.

Just as a network packet sniffer captures raw frames on a network interface card, **`fuffer`** taps directly into the Linux kernel's tracing infrastructure to intercept function invocations, incoming CPU register arguments, return values, and memory payloads in real time—**without the crippling latency and stop-the-world overhead of `ptrace` or standard debuggers.**

---

## Architecture

```
+-------------------------------------------------------+
|                    Target Process                     |
|      [ user space function: SSL_write(ssl, buf, len) ]|
+---------------------------+---------------------------+
                            | (uprobe / uretprobe hit)
                            v
+-------------------------------------------------------+
|                   Linux Kernel (eBPF)                 |
|  1. Intercept ABI registers (RDI, RSI, RDX, etc.)     |
|  2. Stash entry args in BPF Hash Map keyed by PID/TID |
|  3. On return, capture RAX & duration                 |
|  4. Stream event to lock-free BPF Ring Buffer         |
+---------------------------+---------------------------+
                            | (Zero-Copy Ring Buffer Stream)
                            v
+-------------------------------------------------------+
|                  fuffer CLI (User Space)              |
|  1. Async event ingestion via tokio AsyncFd           |
|  2. ELF symbol table & offset resolution              |
|  3. Live Wireshark-like stream & ASCII/HEX dump       |
+-------------------------------------------------------+
```

---

## Live Stream Output

```text
TIME         PID/TID    EVENT   FUNCTION     ARGUMENTS / PAYLOAD                           RETURN / DURATION
-------------------------------------------------------------------------------------------------------------
13:28:40.102 4321/4321  ENTER   SSL_read     0x7f8a100, 0x7ffd000, 0x1000 | "GET /status" -
13:28:40.103 4321/4321  EXIT    SSL_read     args=[0x7f8a100, 0x7ffd000]                   -> 0x144 (124.2µs)
13:28:41.512 4321/4325  ENTER   openat       0xffffff9c, 0x7ffd040, 0x0 | "/etc/hosts"    -
13:28:41.513 4321/4325  EXIT    openat       args=[0xffffff9c, 0x7ffd040]                  -> 0x3 (18.5µs)
```

With `--verbose`, payloads are rendered as full ASCII/HEX dumps:

```text
  --- Payload Inspection (HEX & ASCII) ---
  0000: 47 45 54 20 2f 61 70 69 2f 76 31 2f 73 74 61 74  |GET /api/v1/stat|
  0010: 75 73 20 48 54 54 50 2f 31 2e 31 0d 0a            |us HTTP/1.1..   |
```

---

## Key Features

- **Near-Zero Overhead:** Uses Linux `uprobes`, `uretprobes`, `kprobes`, and `kretprobes` instead of `ptrace` breakpoints. Target threads continue executing at native speed.
- **Thread-Safe Call State Correlation:** Uses `bpf_get_current_pid_tgid()` to index function invocations across concurrent threads in a BPF Hash Map, correlating entry arguments with exit return values and latencies.
- **Lock-Free Ring Buffer:** Ships events from kernel to userspace via `BPF_MAP_TYPE_RINGBUF`, polled asynchronously with `tokio`'s `AsyncFd`.
- **Dynamic ELF Resolution:** Automatically resolves function addresses to exact file offsets for Position Independent Executables (PIE) and shared libraries (`ET_DYN`).
- **Memory Payload Inspection:** Safely copies string arguments and byte buffers directly out of user memory using `bpf_probe_read_user_str_bytes`.
- **Pure Rust Stack:** Built using [`aya`](https://github.com/aya-rs/aya) and `aya-ebpf` without requiring `clang` or C toolchains on the host.

---

## Workspace Structure

Following the workspace architecture detailed in [`AGENTS.md`](AGENTS.md):

* **[`fuffer-ebpf`](fuffer-ebpf/)**: Low-level kernel programs (`no_std`, `no_main`) compiled to BPF bytecode (`bpfel-unknown-none`).
* **[`fuffer-cli`](fuffer-cli/)**: User-space host CLI tool built with `tokio`, `clap`, and `aya`.
* **[`fuffer-common`](fuffer-common/)**: Shared, `#[repr(C)]` memory-aligned structs ensuring ABI parity across kernel and user space.
* **[`xtask`](xtask/)**: Cargo build automation orchestrating dual-target compilation.

---

## Prerequisites

1. **Linux Kernel:** 5.8 or higher (required for BPF Ring Buffer support).
2. **Rust Toolchain:**
   - Rust stable (for host CLI)
   - Rust nightly + `rust-src` component (for compiling eBPF bytecode):
     ```bash
     rustup toolchain install nightly --component rust-src
     ```
3. **bpf-linker:**
   ```bash
   # Prebuilt musl static binary from aya-rs:
   curl -L -o /tmp/bpf-linker.tar.zst https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
   tar --zstd -xvf /tmp/bpf-linker.tar.zst -C ~/.cargo/bin/
   ```
4. **Privileges:** `sudo` access or `CAP_SYS_ADMIN` and `CAP_BPF` capabilities.

---

## Build

Compile both the eBPF kernel bytecode and the host CLI binary in one command:

```bash
cargo xtask build --release
```

The resulting CLI binary is placed at `target/release/fuffer-cli` with the release eBPF bytecode embedded directly into the binary.

---

## Usage Examples

### 1. Sniff Every Function Call in a Process (No --sym)
Omit `--sym` to resolve and sniff every function in the binary:
```bash
# Sniffs every function call happening inside Hyprland:
sudo ./target/release/fuffer-cli --bin /usr/bin/Hyprland

# Or target an active PID and sniff all its function calls:
sudo ./target/release/fuffer-cli --pid 1234
```

### 2. Trace Specific Symbols or Wildcards
Filter for specific function names or wildcard patterns:
```bash
sudo ./target/release/fuffer-cli --pid 1234 --sym malloc
```

### 3. Spawn and Sniff a Command
Launch a new process and hook into matching functions immediately:
```bash
sudo ./target/release/fuffer-cli --cmd "curl -s https://example.com" --sym "SSL_*" -v
```

### 4. Trace Shared Library Functions with Wildcards
Hook symbols in a specific dynamic library:
```bash
sudo ./target/release/fuffer-cli --bin /usr/lib/libc.so.6 --sym "open*"
```

### 5. Trace Kernel Functions
Intercept kernel execution (e.g. `do_sys_open`):
```bash
sudo ./target/release/fuffer-cli --kernel do_sys_open
```

---

## Under the Hood: Systems Engineering

### Calling Convention (System V AMD64 ABI)
On x86_64 Linux, function arguments are passed inside processor registers:
- `arg0`: `RDI`
- `arg1`: `RSI`
- `arg2`: `RDX`
- `arg3`: `RCX`
- `arg4`: `R8`
- `arg5`: `R9`
- `retval`: `RAX`

`fuffer-ebpf` inspects the saved trap frame registers (`pt_regs`) directly at the entry breakpoint.

### Uprobe File Offsets & PIE
Linux `uprobes` hook into on-disk binary inodes via file offsets, not runtime virtual memory addresses. For Position Independent Executables (PIE) and shared libraries (`ET_DYN`), `fuffer-cli` resolves the target symbol within the ELF symbol tables (`symtab` and `dynsym`) and transforms the virtual address into an exact file offset:

$$\text{file\_offset} = \text{st\_value} - \text{section.sh\_addr} + \text{section.sh\_offset}$$

### Trampoline Returns
A `uretprobe` replaces the caller's return address on the stack with a kernel trampoline. When the function returns, CPU control transfers to the trampoline which executes `fuffer-ebpf`'s exit handler to capture `RAX` and compute execution latency before resuming normal program execution.

---

## Testing

Run unit tests unprivileged:
```bash
cargo test --workspace --exclude fuffer-ebpf
```

---

## License

Dual-licensed under MIT or Apache-2.0.
