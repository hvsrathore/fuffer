#![no_std]

/* maximum byte length for intercepted string and memory buffer payloads */
pub const MAX_PAYLOAD_SIZE: usize = 256;

/* maximum symbol length stored in ring buffer events */
pub const MAX_SYM_SIZE: usize = 64;

/* function entry event identifier */
pub const EVENT_TYPE_ENTER: u8 = 0;

/* function return/exit event identifier */
pub const EVENT_TYPE_EXIT: u8 = 1;

/* intermediate entry invocation state stashed in BPF hash map */
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EntryState {
    /* kernel timestamp when function entry was intercepted (nanoseconds) */
    pub start_ns: u64,
    /* attach cookie or symbol identifier (e.g. file offset) */
    pub cookie: u64,
    /* registers capturing function arguments (System V AMD64 ABI: RDI, RSI, RDX, RCX, R8, R9) */
    pub args: [u64; 6],
}

/* live execution event sent across the BPF ring buffer to user space */
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FunctionEvent {
    /* monotonic timestamp recorded in kernel space (nanoseconds) */
    pub timestamp_ns: u64,
    /* user-space process ID (thread group identifier) */
    pub pid: u32,
    /* user-space thread ID (task identifier) */
    pub tid: u32,
    /* attach cookie or symbol identifier (e.g. file offset) */
    pub cookie: u64,
    /* event direction: 0 = ENTER, 1 = EXIT */
    pub event_type: u8,
    /* explicit padding to maintain 8-byte alignment for 64-bit register array */
    pub _pad: [u8; 7],
    /* function arguments captured from architecture registers */
    pub args: [u64; 6],
    /* return value retrieved from RAX register on return */
    pub retval: u64,
    /* execution elapsed time in nanoseconds (populated on EXIT events) */
    pub duration_ns: u64,
    /* null-terminated symbol name intercepted by probe */
    pub symbol: [u8; MAX_SYM_SIZE],
    /* actual length of payload buffer copied from user space */
    pub payload_len: u32,
    /* explicit padding to ensure alignment */
    pub _pad2: [u8; 4],
    /* raw payload inspection buffer (e.g. string contents or packet data) */
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

impl Default for EntryState {
    fn default() -> Self {
        Self {
            start_ns: 0,
            cookie: 0,
            args: [0; 6],
        }
    }
}

impl Default for FunctionEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            cookie: 0,
            event_type: EVENT_TYPE_ENTER,
            _pad: [0; 7],
            args: [0; 6],
            retval: 0,
            duration_ns: 0,
            symbol: [0; MAX_SYM_SIZE],
            payload_len: 0,
            _pad2: [0; 4],
            payload: [0; MAX_PAYLOAD_SIZE],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /* verify memory alignment and sizing for zero-copy ABI transfers */
    fn test_struct_alignment_and_size() {
        assert_eq!(core::mem::align_of::<FunctionEvent>(), 8);
        assert_eq!(core::mem::size_of::<EntryState>(), 64);
        assert_eq!(core::mem::size_of::<FunctionEvent>(), 424);
    }
}
