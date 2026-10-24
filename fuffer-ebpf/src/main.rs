#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{kprobe, kretprobe, map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use aya_ebpf_bindings::helpers::bpf_get_attach_cookie;
use fuffer_common::{
    EntryState, FunctionEvent, EVENT_TYPE_ENTER, EVENT_TYPE_EXIT, MAX_PAYLOAD_SIZE,
};

/* BPF ring buffer for streaming live events to user space with minimal locking */
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/* state storage tracking function entry arguments keyed by 64-bit PID and TID */
#[map]
static ENTRY_STORAGE: HashMap<u64, EntryState> = HashMap::with_max_entries(10240, 0);

/* target PID filter (0 means capture all processes) */
#[map]
static TARGET_PID: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/* uprobe hook: intercepted on entry point of target function */
#[uprobe]
pub fn fuffer_uprobe(ctx: ProbeContext) -> u32 {
    match try_fuffer_uprobe(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/* internal probe logic capturing ABI registers and string payloads
 *
 * educational systems detail:
 * on x86_64 System V AMD64 ABI, function arguments are passed in registers:
 * arg0: RDI, arg1: RSI, arg2: RDX, arg3: RCX, arg4: R8, arg5: R9.
 * we read these registers directly from the trap frame (pt_regs).
 * we also read the attach cookie to correlate which symbol triggered this uprobe.
 */
fn try_fuffer_uprobe(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    /* check target PID filter */
    let filter_key = 0u32;
    if let Some(&filter_pid) = unsafe { TARGET_PID.get(&filter_key) } {
        if filter_pid != 0 && filter_pid != pid {
            return Ok(0);
        }
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let cookie = unsafe { bpf_get_attach_cookie(ctx.as_ptr()) };

    /* capture ABI registers */
    let arg0: u64 = ctx.arg(0).unwrap_or(0);
    let arg1: u64 = ctx.arg(1).unwrap_or(0);
    let arg2: u64 = ctx.arg(2).unwrap_or(0);
    let arg3: u64 = ctx.arg(3).unwrap_or(0);
    let arg4: u64 = ctx.arg(4).unwrap_or(0);
    let arg5: u64 = ctx.arg(5).unwrap_or(0);

    let state = EntryState {
        start_ns: timestamp_ns,
        cookie,
        args: [arg0, arg1, arg2, arg3, arg4, arg5],
    };

    /* stash entry state in BPF map keyed by PID/TID to correlate with return */
    let _ = ENTRY_STORAGE.insert(&pid_tgid, &state, 0);

    /* allocate event in ring buffer */
    if let Some(mut slot) = EVENTS.reserve::<FunctionEvent>(0) {
        let event = slot.as_mut_ptr();
        unsafe {
            (*event).timestamp_ns = timestamp_ns;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).cookie = cookie;
            (*event).event_type = EVENT_TYPE_ENTER;
            (*event).args = [arg0, arg1, arg2, arg3, arg4, arg5];
            (*event).retval = 0;
            (*event).duration_ns = 0;
            (*event).payload_len = 0;

            /* inspect pointer argument as null-terminated string payload if non-null */
            if arg0 != 0 {
                let payload_slice = core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!((*event).payload) as *mut u8,
                    MAX_PAYLOAD_SIZE,
                );
                if let Ok(read_bytes) = bpf_probe_read_user_str_bytes(arg0 as *const u8, payload_slice) {
                    (*event).payload_len = read_bytes.len() as u32;
                }
            } else if arg1 != 0 {
                /* check secondary argument (common for buffer pointers like in SSL_write) */
                let payload_slice = core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!((*event).payload) as *mut u8,
                    MAX_PAYLOAD_SIZE,
                );
                if let Ok(read_bytes) = bpf_probe_read_user_str_bytes(arg1 as *const u8, payload_slice) {
                    (*event).payload_len = read_bytes.len() as u32;
                }
            }
        }
        slot.submit(0);
    }

    Ok(0)
}

/* uretprobe hook: intercepted when target function returns to caller */
#[uretprobe]
pub fn fuffer_uretprobe(ctx: RetProbeContext) -> u32 {
    match try_fuffer_uretprobe(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/* educational systems detail:
 * on x86_64, integer and pointer return values are placed in the RAX register.
 * uretprobe replaces the return address on the stack with a trampoline; when the
 * function executes RET, control transfers to the trampoline which fires our eBPF
 * program before resuming original execution flow.
 */
fn try_fuffer_uretprobe(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    /* check target PID filter */
    let filter_key = 0u32;
    if let Some(&filter_pid) = unsafe { TARGET_PID.get(&filter_key) } {
        if filter_pid != 0 && filter_pid != pid {
            return Ok(0);
        }
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let retval: u64 = ctx.ret();

    /* lookup correlated entry state stashed during uprobe */
    let mut duration_ns = 0u64;
    let mut cookie = 0u64;
    let mut args = [0u64; 6];
    if let Some(entry_state) = unsafe { ENTRY_STORAGE.get(&pid_tgid) } {
        if timestamp_ns >= entry_state.start_ns {
            duration_ns = timestamp_ns - entry_state.start_ns;
        }
        cookie = entry_state.cookie;
        args = entry_state.args;
        let _ = ENTRY_STORAGE.remove(&pid_tgid);
    }

    /* emit exit event to ring buffer */
    if let Some(mut slot) = EVENTS.reserve::<FunctionEvent>(0) {
        let event = slot.as_mut_ptr();
        unsafe {
            (*event).timestamp_ns = timestamp_ns;
            (*event).pid = pid;
            (*event).tid = tid;
            (*event).cookie = cookie;
            (*event).event_type = EVENT_TYPE_EXIT;
            (*event).args = args;
            (*event).retval = retval;
            (*event).duration_ns = duration_ns;
            (*event).payload_len = 0;
        }
        slot.submit(0);
    }

    Ok(0)
}

/* kprobe hook for kernel function interception */
#[kprobe]
pub fn fuffer_kprobe(ctx: ProbeContext) -> u32 {
    match try_fuffer_uprobe(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/* kretprobe hook for kernel function returns */
#[kretprobe]
pub fn fuffer_kretprobe(ctx: RetProbeContext) -> u32 {
    match try_fuffer_uretprobe(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
