//! Sandbox lifecycle and the length-prefixed stdio transport protocol.
//!
//! No host network, home, routes or firewall are granted. A closed control
//! channel stops the adapter; malformed frames and timeouts are errors.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use crate::tools::Tools;
use crate::transport::{AdapterSession, Capabilities, Frame};

pub const MAX_PAYLOAD: usize = 1024 * 1024;
const HEADER: usize = 16;
const TIMEOUT: Duration = Duration::from_secs(3);

pub fn bwrap_args(run: &Path, fake: bool) -> Vec<OsString> {
    let mut args = vec![
        "--unshare-all".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "HOME".into(),
        "/homeless".into(),
        "--setenv".into(),
        "XDG_RUNTIME_DIR".into(),
        "/runtime".into(),
        "--ro-bind".into(),
        "/nix/store".into(),
        "/nix/store".into(),
        "--ro-bind-try".into(),
        "/run/current-system".into(),
        "/run/current-system".into(),
        "--ro-bind".into(),
        "/etc".into(),
        "/etc".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--tmpfs".into(),
        "/homeless".into(),
        "--tmpfs".into(),
        "/runtime".into(),
        "--ro-bind".into(),
        run.as_os_str().to_owned(),
        run.as_os_str().to_owned(),
        "--".into(),
        run.as_os_str().to_owned(),
    ];
    if fake {
        args.push("_transport-fake".into());
    }
    args
}

pub fn write_frame(out: &mut impl Write, frame: &Frame) -> io::Result<()> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let len = u32::try_from(HEADER + frame.payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(&frame.session_id.to_be_bytes())?;
    out.write_all(&frame.sequence.to_be_bytes())?;
    out.write_all(&frame.payload)?;
    out.flush()
}

pub fn read_frame(input: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if !(HEADER..=HEADER + MAX_PAYLOAD).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let payload_len = len - HEADER;
    let mut metadata = [0u8; HEADER];
    input.read_exact(&mut metadata)?;
    let session_id = u64::from_be_bytes(metadata[..8].try_into().unwrap());
    let sequence = u64::from_be_bytes(metadata[8..].try_into().unwrap());
    let mut payload = vec![0u8; payload_len];
    input.read_exact(&mut payload)?;
    Ok(Some(Frame {
        session_id,
        sequence,
        payload,
    }))
}

fn ready() -> Frame {
    Frame {
        session_id: 0,
        sequence: 0,
        payload: b"ready".to_vec(),
    }
}

pub struct ProcessAdapter {
    capabilities: Capabilities,
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Frame>,
}

impl ProcessAdapter {
    pub fn start(tools: &Tools, name: &str) -> Result<Self, String> {
        let adapter = crate::transport::inventory(&tools.config)?
            .into_iter()
            .find(|adapter| adapter.name == name)
            .ok_or_else(|| format!("no external transport {name}"))?;
        if adapter.kind != crate::transport::Kind::Plugin {
            return Err(format!("{name} is built in, not an external process"));
        }
        let run = adapter
            .run
            .as_ref()
            .ok_or("external transport has no Run")?;
        let mut command = Command::new(&tools.bwrap);
        command
            .args(bwrap_args(run, adapter.fake))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start {name}: {e}"))?;
        let input = child.stdin.take().ok_or("adapter has no stdin")?;
        let mut output = child.stdout.take().ok_or("adapter has no stdout")?;
        let (tx, frames) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Ok(Some(frame)) = read_frame(&mut output) {
                if tx.send(frame).is_err() {
                    break;
                }
            }
        });
        let mut adapter_process = Self {
            capabilities: adapter.capabilities,
            child,
            input: Some(input),
            frames,
        };
        let handshake = adapter_process.recv_frame();
        if handshake != Ok(ready()) {
            let description = match handshake {
                Ok(frame) => format!("unexpected adapter handshake: {frame:?}"),
                Err(error) => format!("adapter handshake failed: {error}"),
            };
            adapter_process.stop();
            return Err(description);
        }
        Ok(adapter_process)
    }

    pub fn recv_frame(&mut self) -> Result<Frame, String> {
        match self.frames.recv_timeout(TIMEOUT) {
            Ok(frame) => Ok(frame),
            Err(RecvTimeoutError::Timeout) => Err("adapter response timed out".to_owned()),
            Err(RecvTimeoutError::Disconnected) => Err("adapter control channel closed".to_owned()),
        }
    }

    pub fn stop(&mut self) {
        self.input.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl AdapterSession for ProcessAdapter {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn send(&mut self, frame: Frame) -> Result<(), String> {
        let input = self.input.as_mut().ok_or("adapter is stopped")?;
        write_frame(input, &frame).map_err(|e| format!("cannot send adapter frame: {e}"))
    }

    fn recv(&mut self) -> Option<Frame> {
        self.recv_frame().ok()
    }
}

impl Drop for ProcessAdapter {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The deterministic external adapter used by lifecycle tests.
pub fn fake_main() -> u8 {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    if write_frame(&mut output, &ready()).is_err() {
        return 2;
    }
    loop {
        match read_frame(&mut input) {
            Ok(Some(frame)) => {
                if write_frame(&mut output, &frame).is_err() {
                    return 2;
                }
            }
            Ok(None) => return 0,
            Err(_) => return 2,
        }
    }
}

/// Start a sandboxed adapter and require one frame back, without publishing a route.
pub fn selftest(tools: &Tools, name: &str) -> Result<Frame, String> {
    let mut adapter = ProcessAdapter::start(tools, name)?;
    let expected = Frame {
        session_id: 42,
        sequence: 1,
        payload: b"lifecycle".to_vec(),
    };
    adapter.send(expected.clone())?;
    let actual = adapter.recv_frame()?;
    if actual != expected {
        return Err(format!("adapter returned the wrong frame: {actual:?}"));
    }
    adapter.stop();
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_format_round_trips_and_rejects_bad_lengths() {
        let frame = Frame {
            session_id: 7,
            sequence: 11,
            payload: vec![1, 2, 3],
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(frame));
        assert_eq!(read_frame(&mut [].as_slice()).unwrap(), None);
        assert!(read_frame(&mut u32::MAX.to_be_bytes().as_slice()).is_err());
    }

    #[test]
    fn the_sandbox_has_no_network_or_real_home() {
        let args = bwrap_args(Path::new("/core"), true);
        let text = format!("{args:?}");
        assert!(text.contains("--unshare-all"));
        assert!(text.contains("--die-with-parent"));
        assert!(text.contains("/homeless"));
        assert_eq!(args.last(), Some(&OsString::from("_transport-fake")));
    }
}
