#![no_main]
use libfuzzer_sys::fuzz_target;
use std::{io::Write, os::unix::net::UnixStream, rc::Rc};
use wl_proxy::{
    baseline::Baseline,
    protocols::{
        wayland::{
            wl_display::{WlDisplay, WlDisplayHandler},
            wl_registry::WlRegistry,
        },
        ObjectInterface,
    },
    state::State,
};

struct Display;
impl WlDisplayHandler for Display {
    fn handle_get_registry(&mut self, _: &Rc<WlDisplay>, registry: &Rc<WlRegistry>) {
        registry.send_global(1, ObjectInterface::WlCompositor, 6);
        registry.send_global(2, ObjectInterface::WlShm, 1);
        registry.send_global(3, ObjectInterface::WlSeat, 7);
    }
}

fuzz_target!(|bytes: &[u8]| {
    let state = State::builder(Baseline::V5)
        .without_server()
        .with_logging(false)
        .build()
        .unwrap();
    state.set_default_forward_to_server(false);
    let (client, fd) = state.connect().unwrap();
    client.display().set_handler(Display);
    let mut writer = UnixStream::from(fd);
    // Keep each sample bounded and nonblocking, including incomplete frames.
    let _ = writer.write(&bytes[..bytes.len().min(4096)]);
    for _ in 0..8 {
        match state.dispatch_available() {
            Ok(true) => (),
            _ => break,
        }
    }
    client.disconnect();
    state.destroy();
});
