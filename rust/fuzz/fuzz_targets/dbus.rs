#![no_main]
use libfuzzer_sys::fuzz_target;
use vpn_zone::dbus_wire as wire;

fuzz_target!(|bytes: &[u8]| {
    let _ = wire::message_len(bytes);
    if let Ok(h) = wire::parse_header(bytes) {
        let _ = wire::portal_call(bytes, &h);
        let _ = wire::portal_call_fds(bytes, &h);
        let _ = wire::body_string(bytes, &h);
        let _ = wire::plain_args(bytes, &h);
        let _ = wire::fd_array(bytes, &h, 64);
        let _ = wire::string_array(bytes, &h, 128);
        let _ = wire::sanitized_notify(bytes, &h);
        let _ = wire::sanitized_portal_notification(bytes, &h);
        let _ = wire::sanitized_screencast_sources(bytes, &h, false);
        let _ = wire::item_properties_call(bytes, &h);
    }
});
