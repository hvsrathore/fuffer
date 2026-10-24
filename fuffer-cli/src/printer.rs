use colored::Colorize;
use fuffer_common::{FunctionEvent, EVENT_TYPE_ENTER, EVENT_TYPE_EXIT};

/* print column headers for the live event streaming display */
pub fn print_header() {
    let header = format!(
        "{:<12} {:<10} {:<7} {:<32} {:<36} {:<14}",
        "TIME", "PID/TID", "EVENT", "FUNCTION", "ARGUMENTS / PAYLOAD", "RETURN / DURATION"
    );
    println!("{}", header.bold());
    println!("{}", "-".repeat(117).dimmed());
}

/* format and print an individual intercepted execution event
 *
 * educational systems detail:
 * function entry captures incoming registers (RDI, RSI, etc.) before the callee
 * modifies them. function exit captures the returned value (RAX) and calculates
 * the elapsed kernel execution time between the matching uprobe and uretprobe.
 */
pub fn print_event(event: &FunctionEvent, symbol_name: &str) {
    let now = chrono::Local::now();
    let time_str = now.format("%H:%M:%S%.3f").to_string();

    let pid_tid = format!("{}/{}", event.pid, event.tid);

    let event_type_str = if event.event_type == EVENT_TYPE_ENTER {
        "ENTER".green().bold()
    } else if event.event_type == EVENT_TYPE_EXIT {
        "EXIT".yellow().bold()
    } else {
        "EVENT".cyan()
    };

    let func_display = if symbol_name.len() > 31 {
        format!("{}…", &symbol_name[..30])
    } else {
        symbol_name.to_string()
    };

    let mut arg_payload_str = String::new();

    if event.event_type == EVENT_TYPE_ENTER {
        /* format arguments passed in registers */
        arg_payload_str.push_str(&format!(
            "0x{:x}, 0x{:x}, 0x{:x}",
            event.args[0], event.args[1], event.args[2]
        ));

        /* append string payload if captured by eBPF probe */
        if event.payload_len > 0 {
            let len = (event.payload_len as usize).min(event.payload.len());
            let payload_slice = &event.payload[..len];
            let sanitized: String = payload_slice
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();

            if !sanitized.is_empty() {
                arg_payload_str.push_str(&format!(" | \"{}\"", sanitized.cyan()));
            }
        }
    } else {
        /* on exit, show summary of cached arguments */
        arg_payload_str.push_str(&format!("args=[0x{:x}, 0x{:x}]", event.args[0], event.args[1]));
    }

    let return_str = if event.event_type == EVENT_TYPE_EXIT {
        let duration_us = (event.duration_ns as f64) / 1000.0;
        let dur_formatted = if duration_us >= 1000.0 {
            format!("{:.2}ms", duration_us / 1000.0)
        } else {
            format!("{:.1}µs", duration_us)
        };
        format!("-> 0x{:x} ({})", event.retval, dur_formatted.dimmed())
    } else {
        "-".to_string()
    };

    println!(
        "{:<12} {:<10} {:<16} {:<32} {:<45} {:<14}",
        time_str.dimmed(),
        pid_tid,
        event_type_str,
        func_display.bold(),
        arg_payload_str,
        return_str
    );
}

/* format a binary payload buffer as an ASCII and HEX dump inspection table */
pub fn print_hex_dump(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    println!("  {}", "--- Payload Inspection (HEX & ASCII) ---".dimmed());
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut hex_part = String::new();
        let mut ascii_part = String::new();

        for byte in chunk {
            hex_part.push_str(&format!("{:02x} ", byte));
            if byte.is_ascii_graphic() || *byte == b' ' {
                ascii_part.push(*byte as char);
            } else {
                ascii_part.push('.');
            }
        }

        println!(
            "  {:04x}: {:<48} |{}|",
            i * 16,
            hex_part,
            ascii_part.dimmed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /* test event formatting does not panic on various edge cases */
    fn test_print_event_smoke() {
        let mut event = FunctionEvent::default();
        event.pid = 1234;
        event.tid = 1234;
        event.args[0] = 0x7ffd;
        event.args[1] = 0x1000;
        print_event(&event, "test_func");

        event.event_type = EVENT_TYPE_EXIT;
        event.retval = 42;
        event.duration_ns = 1500;
        print_event(&event, "test_func");
    }

    #[test]
    /* test hex dump formatting logic */
    fn test_print_hex_dump() {
        let buffer = b"GET /status HTTP/1.1\r\n";
        print_hex_dump(buffer);
    }
}
