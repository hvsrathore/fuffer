use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, RingBuf},
    programs::{
        kprobe::KProbe,
        uprobe::{UProbe, UProbeAttachLocation, UProbeAttachPoint, UProbeScope},
        ProgramError,
    },
    Ebpf, EbpfLoader,
};
use std::{
    collections::HashMap as StdHashMap,
    fs,
    num::NonZeroU32,
    path::Path,
};

/* embedded release eBPF bytecode compiled by xtask */
pub static EMBEDDED_EBPF_BYTECODE: &[u8] = include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../target/bpfel-unknown-none/release/fuffer-ebpf")
);

/* tracer context managing loaded BPF programs, active links, and symbol lookup */
pub struct Tracer {
    pub bpf: Ebpf,
    pub symbol_map: StdHashMap<u64, String>,
}

impl Tracer {
    /* initialize and load the eBPF bytecode */
    pub fn new(custom_ebpf_path: Option<&Path>) -> Result<Self> {
        let bytecode = if let Some(path) = custom_ebpf_path {
            fs::read(path).with_context(|| format!("failed to read custom eBPF object at {}", path.display()))?
        } else {
            EMBEDDED_EBPF_BYTECODE.to_vec()
        };

        let bpf = EbpfLoader::new()
            .load(&bytecode)
            .context("failed to load eBPF bytecode into kernel")?;

        Ok(Self {
            bpf,
            symbol_map: StdHashMap::new(),
        })
    }

    /* configure target PID filter inside eBPF hash map */
    pub fn set_target_pid(&mut self, pid: Option<u32>) -> Result<()> {
        let target_pid = pid.unwrap_or(0);
        let mut pid_map: HashMap<_, u32, u32> = HashMap::try_from(
            self.bpf
                .map_mut("TARGET_PID")
                .context("failed to locate TARGET_PID BPF map")?,
        )?;

        pid_map
            .insert(0u32, target_pid, 0)
            .context("failed to set target PID filter in BPF map")?;

        Ok(())
    }

    /* attach uprobe and uretprobe to target binary and file offset
     *
     * educational systems detail:
     * an eBPF program only needs to be verified and loaded into the kernel ONCE.
     * after loading, the same loaded program file descriptor can be attached to
     * multiple probe points by creating separate perf event / BPF links.
     * we attach with a cookie containing the symbol's file_offset so the eBPF
     * runtime knows exactly which function was intercepted.
     */
    pub fn attach_uprobes(
        &mut self,
        binary_path: &Path,
        symbol_name: &str,
        file_offset: u64,
        target_pid: Option<u32>,
    ) -> Result<()> {
        let scope = match target_pid.and_then(NonZeroU32::new) {
            Some(pid) => UProbeScope::OneProcess(pid),
            None => UProbeScope::AllProcesses,
        };

        /* ensure entry probe program is loaded in kernel (ignore AlreadyLoaded for multiple symbols) */
        let uprobe: &mut UProbe = self
            .bpf
            .program_mut("fuffer_uprobe")
            .context("failed to find fuffer_uprobe program")?
            .try_into()?;
        match uprobe.load() {
            Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
            Err(e) => return Err(e).context("failed to load fuffer_uprobe into kernel"),
        }

        let attach_point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(file_offset),
            cookie: Some(file_offset),
        };

        uprobe
            .attach(
                attach_point,
                binary_path,
                scope,
            )
            .with_context(|| {
                format!(
                    "failed to attach uprobe to {} at offset 0x{:x}",
                    symbol_name, file_offset
                )
            })?;

        /* ensure return probe program is loaded in kernel */
        let uretprobe: &mut UProbe = self
            .bpf
            .program_mut("fuffer_uretprobe")
            .context("failed to find fuffer_uretprobe program")?
            .try_into()?;
        match uretprobe.load() {
            Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
            Err(e) => return Err(e).context("failed to load fuffer_uretprobe into kernel"),
        }

        let ret_attach_point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(file_offset),
            cookie: Some(file_offset),
        };

        uretprobe
            .attach(
                ret_attach_point,
                binary_path,
                scope,
            )
            .with_context(|| {
                format!(
                    "failed to attach uretprobe to {} at offset 0x{:x}",
                    symbol_name, file_offset
                )
            })?;

        /* register symbol in lookup table */
        self.symbol_map.insert(file_offset, symbol_name.to_string());
        Ok(())
    }

    /* attach kprobe and kretprobe to kernel symbol */
    pub fn attach_kprobes(&mut self, kernel_function: &str) -> Result<()> {
        let kprobe: &mut KProbe = self
            .bpf
            .program_mut("fuffer_kprobe")
            .context("failed to find fuffer_kprobe program")?
            .try_into()?;
        match kprobe.load() {
            Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
            Err(e) => return Err(e).context("failed to load fuffer_kprobe into kernel"),
        }
        kprobe
            .attach(kernel_function, 0)
            .with_context(|| format!("failed to attach kprobe to kernel symbol '{}'", kernel_function))?;

        let kretprobe: &mut KProbe = self
            .bpf
            .program_mut("fuffer_kretprobe")
            .context("failed to find fuffer_kretprobe program")?
            .try_into()?;
        match kretprobe.load() {
            Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
            Err(e) => return Err(e).context("failed to load fuffer_kretprobe into kernel"),
        }
        kretprobe
            .attach(kernel_function, 0)
            .with_context(|| format!("failed to attach kretprobe to kernel symbol '{}'", kernel_function))?;

        self.symbol_map.insert(0, kernel_function.to_string());
        Ok(())
    }

    /* extract the BPF ring buffer for live event streaming */
    pub fn take_ring_buf(&mut self) -> Result<RingBuf<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("EVENTS")
            .context("failed to take EVENTS ring buffer from BPF object")?;
        RingBuf::try_from(map).context("failed to initialize RingBuf wrapper")
    }
}
