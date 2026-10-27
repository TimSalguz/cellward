#![no_main]
use libfuzzer_sys::fuzz_target;
use vpn_zone::type_input::{Plan, Request};

fuzz_target!(|bytes: &[u8]| {
    if let Some(request) = Request::parse(bytes) {
        let encoded = request.bytes();
        assert_eq!(
            Request::parse(&encoded)
                .expect("encoded request must parse")
                .bytes(),
            encoded
        );
        if let Request::Type { text, mode, .. } = request {
            let _ = Plan::new(&text, mode);
        }
    }
});
