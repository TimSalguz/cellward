//! Host-side screenshots to one authenticated private clipboard. No host export.
use super::*;
use crate::clipboard_client::{Client, Reply, Request, Selection};
use crate::clipboard_endpoint as endpoint;
use crate::i18n::{self, Key, Language};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::time::{Duration, Instant};

const LIMIT: usize = 64 << 20;
fn label(key: Key) -> &'static str {
    i18n::text(Language::default(), key)
}

/// Return only the focused supervisor's visible rectangle. Unknown compositor
/// geometry needs explicit region selection; never guess from titles or order.
fn window_geometry(target: paste::Target) -> Option<String> {
    if target.compositor != Compositor::Sway {
        return None;
    }
    let value = run_json("swaymsg", &["-t", "get_tree", "-r"]).ok()?;
    let node = paste::sway_focused(&value)?;
    if node.get("pid")?.as_i64()? != i64::from(target.pid) || node.get("id")?.as_i64()? != target.id
    {
        return None;
    }
    let rect = node.get("rect")?;
    let x = i32::try_from(rect.get("x")?.as_i64()?).ok()?;
    let y = i32::try_from(rect.get("y")?.as_i64()?).ok()?;
    let w = u32::try_from(rect.get("width")?.as_i64()?).ok()?;
    let h = u32::try_from(rect.get("height")?.as_i64()?).ok()?;
    if w == 0 || h == 0 || w > 16384 || h > 16384 {
        return None;
    }
    Some(format!("{x},{y} {w}x{h}"))
}

/// Bounded stdout and lifetime, with simultaneous stdin so neither pipe can
/// deadlock. All bytes stay in memory. The child is always killed/reaped on error.
fn image_command(
    mut command: Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
    owner: BorrowedFd<'_>,
) -> Result<Option<Vec<u8>>, ()> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().map_err(|_| ())?;
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().unwrap();
        std::thread::spawn(move || stdin.write_all(&bytes))
    });
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ())
            .and({
                if bytes.len() <= LIMIT {
                    Ok(bytes)
                } else {
                    Err(())
                }
            });
        let _ = send.send(result);
    });
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        if Instant::now() >= deadline || !endpoint::alive(owner) {
            break Err(());
        }
        match receive.recv_timeout(Duration::from_millis(50)) {
            Ok(result) => break result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break Err(()),
        }
    };
    if outcome.is_err() {
        let _ = child.kill();
    }
    // EOF alone must not allow a child which keeps running to hang the helper.
    let until = Instant::now() + Duration::from_secs(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let _ = reader.join();
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let bytes = outcome?;
    match status.and_then(|s| s.code()) {
        Some(0) if bytes.starts_with(b"\x89PNG\r\n\x1a\n") => Ok(Some(bytes)),
        Some(1) if bytes.is_empty() => Ok(None), // Esc in the region editor.
        _ => Err(()),
    }
}

fn exchange(client: &mut Client, request: Request<'_>) -> Result<Reply, ()> {
    client
        .start(Selection::Clipboard, request, Instant::now())
        .map_err(|_| ())?;
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(result) = client.tick(Instant::now()) {
            return result.map_err(|_| ());
        }
        if Instant::now() >= until {
            return Err(());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub(crate) fn run(tools: &Tools, args: &[OsString]) -> u8 {
    if args.len() != 2 {
        return 2;
    }
    let Some(pid) = args[0]
        .to_str()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|p| *p > 1)
    else {
        return 2;
    };
    let Some(mode @ ("window" | "area" | "hover")) = args[1].to_str() else {
        return 2;
    };
    let attempt = (|| -> Result<bool, ()> {
        let owner = crate::sys::pidfd_open(pid).ok_or(())?;
        let scope = private_clipboard_scope(tools, pid).ok_or(())?;
        let target = paste::Target::focused(pid).ok_or(())?;
        let grim = tools.grim.as_ref().filter(|p| p.is_absolute()).ok_or(())?;
        let geometry = (mode == "window")
            .then(|| window_geometry(target))
            .flatten();
        let mut capture = Command::new(grim);
        if let Some(geometry) = &geometry {
            capture.args(["-g", geometry]);
        }
        capture.args(["-t", "png", "-"]);
        let png = image_command(capture, None, Duration::from_secs(5), owner.as_fd())?.ok_or(())?;
        // Capture finishes before the editor exists. Crop only these pixels.
        let png = {
            let mut editor = Command::new(&tools.window);
            editor.arg("screenshot");
            if mode == "window" && geometry.is_some() {
                editor.arg("--whole");
            }
            match image_command(editor, Some(png), Duration::from_secs(90), owner.as_fd())? {
                Some(png) => png,
                None => return Ok(false),
            }
        };
        if !endpoint::alive(owner.as_fd()) {
            return Err(());
        }
        let runtime = crate::broker::runtime_dir();
        let bound = endpoint::lookup(&runtime, &scope).map_err(|_| ())?;
        let mut client = Client::new(bound.data).map_err(|_| ())?;
        let Reply::Begun(epoch) = exchange(&mut client, Request::BeginCapture { user_copy: true })?
        else {
            return Err(());
        };
        match exchange(
            &mut client,
            Request::FinishCapture {
                epoch,
                parts: &[("image/png", &png)],
            },
        ) {
            Ok(Reply::Set(_)) => {}
            _ => {
                let _ = exchange(&mut client, Request::AbortCapture { epoch });
                return Err(());
            }
        }
        let _ = target.restore();
        crate::dialog::notify(
            &tools.notify_send,
            None,
            "2500",
            label(Key::ScreenshotCopied),
            &scope,
        );
        Ok(true)
    })();
    match attempt {
        Ok(_) => 0,
        Err(()) => {
            eprintln!("window-screenshot: capture, target or private clipboard unavailable");
            crate::dialog::notify(
                &tools.notify_send,
                None,
                "5000",
                label(Key::ScreenshotWindow),
                label(Key::ScreenshotFailed),
            );
            1
        }
    }
}
