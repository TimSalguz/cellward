//! Trusted host toggles for PipeWire recording of the focused root surface.
use super::*;
use std::io::{Read, Write};
use std::time::Duration;

fn toggle(pid: i32, stop: bool) -> bool {
    let path = crate::wl_proxy::ask_path(&crate::broker::runtime_dir(), pid);
    let Ok(mut socket) = std::os::unix::net::UnixStream::connect(path) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
    let mut request = if stop {
        b"\0record-pipewire-stop".to_vec()
    } else {
        b"\0record-pipewire".to_vec()
    };
    let mut frame = (request.len() as u16).to_le_bytes().to_vec();
    frame.append(&mut request);
    let mut answer = [0];
    socket.write_all(&frame).is_ok()
        && socket.read_exact(&mut answer).is_ok()
        && answer[0] == crate::wl_proxy::ASK_YES
}

pub(crate) fn run(_tools: &Tools, args: &[OsString]) -> u8 {
    let (pid, stop) = match args {
        [flag, pid] if flag == "--pid" => (pid.to_str(), false),
        [flag, pid, stop] if flag == "--pid" && stop == "--stop" => (pid.to_str(), true),
        _ => (None, false),
    };
    let Some(pid) = pid
        .and_then(|arg| arg.parse::<i32>().ok())
        .filter(|pid| *pid > 1)
    else {
        return 2;
    };
    if crate::sys::pidfd_open(pid).is_none() {
        return 1;
    }
    if !stop && paste::Target::focused(pid).is_none() {
        eprintln!("window-record: the launch has no focused root surface");
        return 1;
    }
    u8::from(!toggle(pid, stop))
}
