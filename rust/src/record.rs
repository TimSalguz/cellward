//! Bounded raw-frame recording from a dedicated proxy channel to a host sink.
//! No compositor capture, clipboard access or output-path overwrite.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Release);
}

fn install_stop_handler() -> Result<(), String> {
    // SAFETY: the handler only stores an atomic. No allocation, locks or I/O.
    unsafe {
        if libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
            || libc::signal(
                libc::SIGTERM,
                request_stop as *const () as libc::sighandler_t,
            ) == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

const CAPTURE: u8 = b'P';
const CAPTURE_OK: u8 = b'Q';
const CAPTURE_ERR: u8 = b'R';
const MAX_FRAME_BYTES: usize = 64 << 20;
const REPLY_TIMEOUT_MS: i32 = 2_000;

enum Destination {
    Ffmpeg {
        ffmpeg: PathBuf,
        output: PathBuf,
    },
    RawFd(RawFd),
    PipeWire {
        gst_launch: PathBuf,
        plugin_path: Option<OsString>,
    },
}

struct Args {
    fd: RawFd,
    destination: Destination,
    frames: u32,
    fps: u32,
}

impl Args {
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut fd = None;
        let mut ffmpeg = None;
        let mut output = None;
        let mut raw_fd = None;
        let mut pipewire = None;
        let mut gst_plugin_path = None;
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
                Some("--raw-fd") => raw_fd = value.to_str().and_then(|v| v.parse::<RawFd>().ok()),
                Some("--pipewire") => pipewire = Some(PathBuf::from(value)),
                Some("--gst-plugin-path") => gst_plugin_path = Some(value.to_owned()),
                Some("--frames") => frames = value.to_str().and_then(|v| v.parse::<u32>().ok()),
                Some("--fps") => fps = value.to_str().and_then(|v| v.parse::<u32>().ok()),
                _ => return Err(format!("unknown option {word:?}")),
            }
        }
        let fd = fd.filter(|fd| *fd >= 0).ok_or("a valid --fd is required")?;
        if pipewire.is_some() && (raw_fd.is_some() || ffmpeg.is_some() || output.is_some()) {
            return Err("--pipewire cannot be combined with other destinations".into());
        }
        let destination = if let Some(gst_launch) = pipewire {
            if !gst_launch.is_absolute() {
                return Err("absolute --pipewire is required".into());
            }
            Destination::PipeWire {
                gst_launch,
                plugin_path: gst_plugin_path,
            }
        } else {
            match raw_fd {
                Some(raw) if raw >= 0 => {
                    if ffmpeg.is_some() || output.is_some() {
                        return Err("--raw-fd cannot be combined with --ffmpeg or --output".into());
                    }
                    Destination::RawFd(raw)
                }
                _ => {
                    let ffmpeg = ffmpeg
                        .filter(|p| p.is_absolute())
                        .ok_or("absolute --ffmpeg is required")?;
                    let output = output
                        .filter(|p| p.is_absolute())
                        .ok_or("absolute --output is required")?;
                    Destination::Ffmpeg { ffmpeg, output }
                }
            }
        };
        let frames = frames
            .filter(|n| (1..=100_000).contains(n))
            .ok_or("--frames must be 1..100000")?;
        let fps = fps
            .filter(|n| (1..=60).contains(n))
            .ok_or("--fps must be 1..60")?;
        Ok(Self {
            fd,
            destination,
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

fn write_rows(output: &mut dyn Write, frame: &Frame) -> Result<(), String> {
    let row = frame.row_bytes()?;
    let stride = frame.stride as usize;
    for line in frame.bytes.chunks_exact(stride) {
        output
            .write_all(&line[..row])
            .map_err(|e| format!("cannot send raw pixels: {e}"))?;
    }
    Ok(())
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

fn capture(channel: &mut UnixStream) -> Result<Option<Frame>, String> {
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
    if STOP.load(Ordering::Acquire) {
        return Ok(None);
    }
    if ready <= 0 {
        let error = std::io::Error::last_os_error();
        if ready < 0
            && error.kind() == std::io::ErrorKind::Interrupted
            && STOP.load(Ordering::Acquire)
        {
            return Ok(None);
        }
        return Err(if ready == 0 {
            "proxy capture timed out".into()
        } else {
            error.to_string()
        });
    }
    let mut answer = [0u8; 1];
    if let Err(error) = channel.read_exact(&mut answer) {
        if error.kind() == std::io::ErrorKind::Interrupted && STOP.load(Ordering::Acquire) {
            return Ok(None);
        }
        return Err(format!("cannot read the capture reply: {error}"));
    }
    if answer[0] == CAPTURE_ERR {
        return Err("proxy has no supported root-surface buffer".into());
    }
    if answer[0] != CAPTURE_OK {
        return Err("unknown proxy capture reply".into());
    }
    read_frame(&output).map(Some)
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
        let mut command = Command::new(ffmpeg);
        command
            .args(encoder_args(frame.width, frame.height, fps, output))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        // SAFETY: the child only asks for a parent-death signal before exec.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGINT) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
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
        let input = self.child.stdin.as_mut().ok_or("ffmpeg input is closed")?;
        write_rows(input, frame)
    }

    fn finish(mut self) -> Result<(), String> {
        drop(self.child.stdin.take());
        let status = self.child.wait().map_err(|e| e.to_string())?;
        self.finished = true;
        if status.success() || STOP.load(Ordering::Acquire) {
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

struct Raw {
    output: File,
    width: i32,
    height: i32,
    generation: u32,
}

impl Raw {
    fn start(fd: RawFd, frame: &Frame) -> Self {
        // SAFETY: the caller transfers ownership of this descriptor to the agent.
        let output = unsafe { File::from_raw_fd(fd) };
        Self {
            output,
            width: frame.width,
            height: frame.height,
            generation: 0,
        }
    }

    fn write(&mut self, frame: &Frame) -> Result<(), String> {
        if frame.width != self.width || frame.height != self.height {
            return Err("root surface changed size during recording".into());
        }
        let mut header = b"CFR1".to_vec();
        for value in [
            frame.width,
            frame.height,
            frame.stride,
            frame.format,
            self.generation as i32,
        ] {
            header.extend_from_slice(&value.to_le_bytes());
        }
        self.output
            .write_all(&header)
            .map_err(|e| format!("cannot write the broker frame header: {e}"))?;
        write_rows(&mut self.output, frame)?;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }
}

fn pipewire_args(width: i32, height: i32, fps: u32) -> Vec<OsString> {
    vec![
        "-q".into(),
        "fdsrc".into(),
        "fd=0".into(),
        format!("blocksize={}", width * height * 4).into(),
        "is-live=true".into(),
        "!".into(),
        "rawvideoparse".into(),
        "format=bgra".into(),
        format!("width={width}").into(),
        format!("height={height}").into(),
        format!("framerate={fps}/1").into(),
        "!".into(),
        format!("video/x-raw,format=BGRA,width={width},height={height},framerate={fps}/1").into(),
        "!".into(),
        "videoconvert".into(),
        "!".into(),
        "video/x-raw,format=I420".into(),
        "!".into(),
        "pipewiresink".into(),
        "mode=provide".into(),
        "sync=false".into(),
        "enable-last-sample=false".into(),
        "stream-properties=props,media.class=Stream/Output/Video,node.name=cellward_capture,node.description=Cellward-root-surface".into(),
        "client-properties=props,application.name=cellward-capture".into(),
    ]
}

struct GStreamer {
    child: Child,
    width: i32,
    height: i32,
    finished: bool,
}

impl GStreamer {
    fn start(
        program: &Path,
        plugin_path: Option<&OsStr>,
        frame: &Frame,
        fps: u32,
    ) -> Result<Self, String> {
        let mut command = Command::new(program);
        command
            .args(pipewire_args(frame.width, frame.height, fps))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(path) = plugin_path {
            command
                .env("GST_PLUGIN_PATH", path)
                .env("GST_PLUGIN_SYSTEM_PATH", path);
        }
        // SAFETY: the child only asks for a parent-death signal before exec.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGINT) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start the PipeWire broker: {e}"))?;
        if child.stdin.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("the PipeWire broker has no raw-frame input".into());
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
        let input = self
            .child
            .stdin
            .as_mut()
            .ok_or("PipeWire broker input is closed")?;
        write_rows(input, frame)
    }

    fn finish(mut self) -> Result<(), String> {
        drop(self.child.stdin.take());
        let status = self.child.wait().map_err(|e| e.to_string())?;
        self.finished = true;
        if status.success() || STOP.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(format!("PipeWire broker exited with {status}"))
        }
    }
}

impl Drop for GStreamer {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

enum Sink {
    Ffmpeg(Encoder),
    Raw(Raw),
    PipeWire(GStreamer),
}

impl Sink {
    fn write(&mut self, frame: &Frame) -> Result<(), String> {
        match self {
            Self::Ffmpeg(encoder) => encoder.write(frame),
            Self::Raw(raw) => raw.write(frame),
            Self::PipeWire(gstreamer) => gstreamer.write(frame),
        }
    }

    fn finish(self) -> Result<(), String> {
        match self {
            Self::Ffmpeg(encoder) => encoder.finish(),
            Self::Raw(_) => Ok(()),
            Self::PipeWire(gstreamer) => gstreamer.finish(),
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    install_stop_handler()?;
    // SAFETY: the supervisor transfers ownership of this descriptor to the agent.
    let mut channel = unsafe { UnixStream::from_raw_fd(args.fd) };
    let mut encoder: Option<Sink> = None;
    let interval = Duration::from_secs(1) / args.fps;
    let mut next = Instant::now();
    for _ in 0..args.frames {
        if STOP.load(Ordering::Acquire) {
            break;
        }
        let left = next.saturating_duration_since(Instant::now());
        if !left.is_zero() {
            std::thread::sleep(left);
        }
        let Some(frame) = capture(&mut channel)? else {
            break;
        };
        if STOP.load(Ordering::Acquire) {
            break;
        }
        let written = match &mut encoder {
            Some(encoder) => encoder.write(&frame),
            None => {
                let mut started = match &args.destination {
                    Destination::Ffmpeg { ffmpeg, output } => {
                        Sink::Ffmpeg(Encoder::start(ffmpeg, output, &frame, args.fps)?)
                    }
                    Destination::RawFd(fd) => Sink::Raw(Raw::start(*fd, &frame)),
                    Destination::PipeWire {
                        gst_launch,
                        plugin_path,
                    } => Sink::PipeWire(GStreamer::start(
                        gst_launch,
                        plugin_path.as_deref(),
                        &frame,
                        args.fps,
                    )?),
                };
                let written = started.write(&frame);
                encoder = Some(started);
                written
            }
        };
        if STOP.load(Ordering::Acquire) {
            break;
        }
        written?;
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
    fn pipewire_is_a_named_video_source_without_a_file_or_audio() {
        let args = pipewire_args(640, 480, 30);
        assert!(args.iter().any(|arg| arg == "pipewiresink"));
        assert!(args.iter().any(|arg| arg == "blocksize=1228800"));
        assert!(args.iter().any(|arg| arg == "rawvideoparse"));
        assert!(args.iter().any(|arg| arg == "format=bgra"));
        assert!(args
            .iter()
            .any(|arg| arg == "video/x-raw,format=BGRA,width=640,height=480,framerate=30/1"));
        assert!(args.iter().any(|arg| arg == "video/x-raw,format=I420"));
        assert!(args.iter().any(|arg| arg
            .to_string_lossy()
            .contains("media.class=Stream/Output/Video")));
        assert!(!args.iter().any(|arg| arg == "pulseaudiosink"));
    }

    #[test]
    fn raw_frames_carry_a_generation_and_no_stride_padding() {
        use std::os::fd::IntoRawFd;

        let (mut read, write) = UnixStream::pair().unwrap();
        let frame = Frame {
            width: 2,
            height: 1,
            stride: 12,
            format: 1,
            bytes: (0..12).collect(),
        };
        let mut raw = Raw::start(write.into_raw_fd(), &frame);
        raw.write(&frame).unwrap();
        raw.write(&frame).unwrap();
        drop(raw);
        let mut bytes = [0u8; 64];
        read.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], b"CFR1");
        for (at, expected) in [(4, 2), (8, 1), (12, 12), (16, 1), (20, 0), (52, 1)] {
            assert_eq!(
                i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
                expected
            );
        }
        assert_eq!(&bytes[24..32], &(0..8).collect::<Vec<_>>());
        assert_eq!(&bytes[56..64], &(0..8).collect::<Vec<_>>());
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
