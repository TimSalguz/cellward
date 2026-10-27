#![no_main]
use libfuzzer_sys::fuzz_target;
use vpn_zone::pulse_filter as pulse;

fuzz_target!(|bytes: &[u8]| {
    let _ = pulse::frame_len(bytes);
    let _ = pulse::command_of(bytes);
    if let Some(items) = pulse::parse(bytes) {
        let _ = pulse::record_refused(&items);
    }
    // The actual frame path parses its payload after the 20-byte descriptor.
    if let Some(body) = bytes.get(20..) {
        if let Some(items) = pulse::parse(body) {
            let _ = pulse::cut_properties(bytes, &items);
            let _ = pulse::record_refused(&items);
        }
    }
});
