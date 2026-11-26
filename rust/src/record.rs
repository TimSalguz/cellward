//! Bounded raw-frame recording from a dedicated proxy channel to host ffmpeg.
//! No compositor capture, clipboard access or output-path overwrite.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CAPTURE: u8 = b'P';
const CAPTURE_OK: u8 = b'Q';
const CAPTURE_ERR: u8 = b'R';
const MAX_FRAME_BYTES: usize = 64 << 20;
const REPLY_TIMEOUT_MS: i32 = 2_000;

struct Args {
    fd: RawFd,
    ffmpeg: PathBuf,
    output: PathBuf,
    frames: u32,
    fps: u32,
}

impl Args {
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut fd = None;
        let mut ffmpeg = None;
        let mut output = None;
        let mut frames = None;
        let mut fps = None;
        let mut words = args.iter();
        while let Some(word) = words.next() {
            let Some(value) = words.next() else {
                return Err(format!("{word:?} needs a value"));
            };
            match word.to_str() {
                Some("--fd") => fd = value.to_str().and_then(|v| v.parse::<RawFd>().ok()),
                Some("--ffmpeg") => ffmpeg = Some(PathBuf::from(value)),
                Some("--output") => output = Some(PathBuf::from(value)),
                Some("--frames") => frames = value.to_str().and_then(|v| v.parse::<u32>().ok()),
                Some("--fps") => fps = value.to_str().and_then(|v| v.parse::<u32>().ok()),
                _ => return Err(format!("unknown option {word:?}")),
            }
        }
        let fd = fd.filter(|fd| *fd >= 0).ok_or("a valid --fd is required")?;
        let ffmpeg = ffmpeg
            .filter(|p| p.is_absolute())
            .ok_or("absolute --ffmpeg is required")?;
        let output = output
            .filter(|p| p.is_absolute())
            .ok_or("absolute --output is required")?;
        let frames = frames
            .filter(|n| (1..=100_000).contains(n))
            .ok_or("--frames must be 1..100000")?;
        let fps = fps
            .filter(|n| (1..=60).contains(n))
            .ok_or("--fps must be 1..60")?;
        Ok(Self {
            fd,
            ffmpeg,
            output,
            frames,
            fps,
        })
    }
}

struct Frame {
    width: i32,
    height: i32,
    stride: i32,
    format: i32,
    bytes: Vec<u8>,
}

impl Frame {
    fn layout(&self) -> Result<(usize, usize), String> {
        if self.width <= 0 || self.height <= 0 || !matches!(self.format, 0 | 1) {
            return Err("invalid frame metadata".into());
        }
        let row = self.width.checked_mul(4).ok_or("frame width overflows")?;
        if self.stride < row {
            return Err("frame stride is shorter than a row".into());
        }
        let len = self
            .stride
            .checked_mul(self.height)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or("frame size overflows")?;
        if len > MAX_FRAME_BYTES {
            return Err("frame exceeds the size limit".into());
        }
        let row = usize::try_from(row).map_err(|_| "frame row overflows")?;
        Ok((row, len))
    }

    fn row_bytes(&self) -> Result<usize, String> {
        let (row, len) = self.layout()?;
        if self.bytes.len() != len {
            return Err("frame payload has the wrong size".into());
        }
        Ok(row)
    }
}

fn memfd() -> Result<OwnedFd, String> {
    // SAFETY: memfd_create returns a new owned descriptor.
    let fd = unsafe { libc::memfd_create(c"cellward-record".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: the descriptor was just returned and has no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_frame(fd: &OwnedFd) -> Result<Frame, String> {
    let mut header = [0u8; 16];
    File::from(fd.try_clone().map_err(|e| e.to_string())?)
        .read_exact_at(&mut header, 0)
        .map_err(|e| format!("cannot read frame header: {e}"))?;
    let values: Vec<i32> = header
        .chunks_exact(4)
        .map(|word| i32::from_ne_bytes(word.try_into().unwrap()))
        .collect();
    let [width, height, stride, format] = values.try_into().map_err(|_| "bad frame header")?;
    let mut frame = Frame {
        width,
        height,
        stride,
        format,
        bytes: Vec::new(),
    };
    let (_, len) = frame.layout()?;
    frame.bytes = vec![0; len];
    File::from(fd.try_clone().map_err(|e| e.to_string())?)
        .read_exact_at(&mut frame.bytes, 16)
        .map_err(|e| format!("cannot read frame pixels: {e}"))?;
    Ok(frame)
}

fn capture(channel: &mut UnixStream) -> Result<Frame, String> {
    let output = memfd()?;
    crate::sys::send_with_fds(channel.as_raw_fd(), &[CAPTURE], &[output.as_raw_fd()])
        .map_err(|e| format!("cannot request a frame: {e}"))?;
    let mut pfd = libc::pollfd {
        fd: channel.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd points to one initialized pollfd for the duration of poll.
    let ready = unsafe { libc::poll(&mut pfd, 1, REPLY_TIMEOUT_MS) };
    if ready <= 0 {
        return Err(if ready == 0 {
            "proxy capture timed out".into()
        } else {
            std::io::Error::last_os_error().to_string()
        });
    }
    let mut answer = [0u8; 1];
    channel
        .read_exact(&mut answer)
        .map_err(|e| format!("cannot read the capture reply: {e}"))?;
    if answer[0] == CAPTURE_ERR {
        return Err("proxy has no supported root-surface buffer".into());
    }
    if answer[0] != CAPTURE_OK {
        return Err("unknown proxy capture reply".into());
    }
    read_frame(&output)
}

fn encoder_args(width: i32, height: i32, fps: u32, output: &Path) -> Vec<OsString> {
    vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-f".into(),
        "rawvideo".into(),
        "-pixel_format".into(),
        "bgra".into(),
        "-video_size".into(),
        format!("{width}x{height}").into(),
        "-framerate".into(),
        fps.to_string().into(),
        "-i".into(),
        "pipe:0".into(),
        "-an".into(),
        "-c:v".into(),
        "libx264".into(),
        "-preset".into(),
        "veryfast".into(),
        "-crf".into(),
        "23".into(),
        "-pix_fmt".into(),
        "yuv420p".into(),
        "-threads".into(),
        "2".into(),
        "-movflags".into(),
        "+faststart".into(),
        "-n".into(),
        output.as_os_str().to_owned(),
    ]
}

struct Encoder {
    child: Child,
    width: i32,
    height: i32,
    finished: bool,
}

impl Encoder {
    fn start(ffmpeg: &Path, output: &Path, frame: &Frame, fps: u32) -> Result<Self, String> {
        let mut child = Command::new(ffmpeg)
            .args(encoder_args(frame.width, frame.height, fps, output))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start ffmpeg: {e}"))?;
        if child.stdin.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ffmpeg has no raw-frame input".into());
        }
        Ok(Self {
            child,
            width: frame.width,
            height: frame.height,
            finished: false,
        })
    }

    fn write(&mut self, frame: &Frame) -> Result<(), String> {
        if frame.width != self.width || frame.height != self.height {
            return Err("root surface changed size during recording".into());
        }
        let row = frame.row_bytes()?;
        let stride = frame.stride as usize;
        let input = self.child.stdin.as_mut().ok_or("ffmpeg input is closed")?;
        for line in frame.bytes.chunks_exact(stride) {
            input
                .write_all(&line[..row])
                .map_err(|e| format!("cannot send a frame to ffmpeg: {e}"))?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), String> {
        drop(self.child.stdin.take());
        let status = self.child.wait().map_err(|e| e.to_string())?;
        self.finished = true;
        if status.success() {
            Ok(())
        } else {
            Err(format!("ffmpeg exited with {status}"))
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    // SAFETY: the supervisor transfers ownership of this descriptor to the agent.
    let mut channel = unsafe { UnixStream::from_raw_fd(args.fd) };
    let mut encoder: Option<Encoder> = None;
    let interval = Duration::from_secs(1) / args.fps;
    let mut next = Instant::now();
    for _ in 0..args.frames {
        let left = next.saturating_duration_since(Instant::now());
        if !left.is_zero() {
            std::thread::sleep(left);
        }
        let frame = capture(&mut channel)?;
        match &mut encoder {
            Some(encoder) => encoder.write(&frame)?,
            None => {
                let mut started = Encoder::start(&args.ffmpeg, &args.output, &frame, args.fps)?;
                started.write(&frame)?;
                encoder = Some(started);
            }
        }
        next += interval;
    }
    encoder.ok_or("no frames were recorded")?.finish()
}

pub fn agent_main(args: &[OsString]) -> u8 {
    let args = match Args::parse(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("record-agent: {error}");
            return 2;
        }
    };
    match run(&args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("record-agent: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_absolute_and_bounded() {
        let valid = Args::parse(&[
            "--fd".into(),
            "3".into(),
            "--ffmpeg".into(),
            "/nix/store/f/bin/ffmpeg".into(),
            "--output".into(),
            "/tmp/cellward-test.mp4".into(),
            "--frames".into(),
            "30".into(),
            "--fps".into(),
            "15".into(),
        ])
        .unwrap();
        assert_eq!(valid.frames, 30);
        assert_eq!(valid.fps, 15);
        for bad in [
            vec!["--fd".into(), "3".into()],
            vec![
                "--fd".into(),
                "3".into(),
                "--ffmpeg".into(),
                "ffmpeg".into(),
                "--output".into(),
                "/tmp/out.mp4".into(),
                "--frames".into(),
                "30".into(),
                "--fps".into(),
                "15".into(),
            ],
            vec![
                "--fd".into(),
                "3".into(),
                "--ffmpeg".into(),
                "/ffmpeg".into(),
                "--output".into(),
                "out.mp4".into(),
                "--frames".into(),
                "30".into(),
                "--fps".into(),
                "15".into(),
            ],
        ] {
            assert!(Args::parse(&bad).is_err());
        }
    }

    #[test]
    fn encoder_compresses_bgra_without_overwriting_or_audio() {
        let args = encoder_args(640, 480, 30, Path::new("/tmp/out.mp4"));
        for expected in ["rawvideo", "bgra", "640x480", "libx264", "yuv420p", "-n"] {
            assert!(args.iter().any(|arg| arg == expected));
        }
        assert!(!args.iter().any(|arg| arg == "-y"));
    }

    #[test]
    fn a_frame_is_read_within_its_checked_extent() {
        let fd = memfd().unwrap();
        let file = File::from(fd.try_clone().unwrap());
        let mut header = Vec::new();
        for value in [2i32, 2, 12, 1] {
            header.extend_from_slice(&value.to_ne_bytes());
        }
        file.write_all_at(&header, 0).unwrap();
        file.write_all_at(&(0..24).collect::<Vec<u8>>(), 16)
            .unwrap();
        let frame = read_frame(&fd).unwrap();
        assert_eq!(frame.row_bytes().unwrap(), 8);
        assert_eq!(frame.bytes, (0..24).collect::<Vec<u8>>());
        file.write_all_at(&3i32.to_ne_bytes(), 8).unwrap();
        assert!(read_frame(&fd).is_err());
    }

    #[test]
    fn oversized_and_non_shm_frames_are_rejected() {
        let mut frame = Frame {
            width: i32::MAX,
            height: 1,
            stride: 4,
            format: 1,
            bytes: Vec::new(),
        };
        assert!(frame.row_bytes().is_err());
        frame.width = 1;
        frame.format = 99;
        assert!(frame.row_bytes().is_err());
    }
}
