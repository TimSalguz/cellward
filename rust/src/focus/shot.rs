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

#[derive(Clone, Copy, Debug, PartialEq)]
struct Rect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

impl Rect {
    fn overlaps(self, other: Self) -> bool {
        self.x < other.x + other.w
            && other.x < self.x + self.w
            && self.y < other.y + other.h
            && other.y < self.y + self.h
    }

    fn grim(self) -> Option<String> {
        if self.w == 0.0
            || self.h == 0.0
            || self.w > 16384.0
            || self.h > 16384.0
            || self.x.fract() != 0.0
            || self.y.fract() != 0.0
        {
            return None;
        }
        Some(format!("{},{} {}x{}", self.x, self.y, self.w, self.h))
    }
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => Some(*n),
        _ => None,
    }
}

fn pair(value: Option<&Value>) -> Option<(f64, f64)> {
    let [x, y] = value?.as_array()? else {
        return None;
    };
    Some((number(x)?, number(y)?))
}

fn niri_rect(window: &Value, workspace: &Value, outputs: &Value) -> Option<Rect> {
    if window.get("workspace_id")?.as_i64()? != workspace.get("id")?.as_i64()?
        || !workspace.get("is_active")?.as_bool()?
    {
        return None;
    }
    let output = outputs
        .get(workspace.get("output")?.as_str()?)?
        .get("logical")?;
    let output_x = output.get("x")?.as_i64()? as f64;
    let output_y = output.get("y")?.as_i64()? as f64;
    let layout = window.get("layout")?;
    let (tile_x, tile_y) = pair(layout.get("tile_pos_in_workspace_view"))?;
    let (offset_x, offset_y) = pair(layout.get("window_offset_in_tile"))?;
    let (w, h) = pair(layout.get("window_size"))?;
    (w > 0.0 && h > 0.0).then_some(Rect {
        x: output_x + tile_x + offset_x,
        y: output_y + tile_y + offset_y,
        w,
        h,
    })
}

fn niri_geometry(
    target: paste::Target,
    focused: &Value,
    windows: &Value,
    workspaces: &Value,
    outputs: &Value,
) -> Option<String> {
    if focused.get("id")?.as_i64()? != target.id
        || focused.get("pid")?.as_i64()? != i64::from(target.pid)
        || !focused.get("is_focused")?.as_bool()?
    {
        return None;
    }
    let workspace_id = focused.get("workspace_id")?.as_i64()?;
    let workspace = workspaces
        .as_array()?
        .iter()
        .find(|w| w.get("id").and_then(Value::as_i64) == Some(workspace_id))?;
    let output = outputs
        .get(workspace.get("output")?.as_str()?)?
        .get("logical")?;
    let output_rect = Rect {
        x: output.get("x")?.as_i64()? as f64,
        y: output.get("y")?.as_i64()? as f64,
        w: output.get("width")?.as_i64()? as f64,
        h: output.get("height")?.as_i64()? as f64,
    };
    let rect = niri_rect(focused, workspace, outputs)?;
    let within = output_rect.x <= rect.x
        && output_rect.y <= rect.y
        && rect.x + rect.w <= output_rect.x + output_rect.w
        && rect.y + rect.h <= output_rect.y + output_rect.h;
    if !within {
        return None;
    }
    let floating = focused.get("is_floating")?.as_bool()?;
    let mut seen_target = false;
    for other in windows.as_array()? {
        let id = other.get("id")?.as_i64()?;
        if id == target.id {
            if seen_target {
                return None;
            }
            seen_target = true;
            continue;
        }
        if other.get("workspace_id").and_then(Value::as_i64) != Some(workspace_id) {
            continue;
        }
        let other_floating = other.get("is_floating")?.as_bool()?;
        match niri_rect(other, workspace, outputs) {
            Some(other) if rect.overlaps(other) => return None,
            Some(_) => {}
            // A floating tile is above the scrolling layout. Any other unknown
            // rectangle, and every unknown rectangle for a tiled target, makes
            // the absence of foreign pixels unprovable.
            None if other_floating || !floating => return None,
            None => {}
        }
    }
    if !seen_target {
        return None;
    }
    rect.grim()
}

fn niri_window_geometry(target: paste::Target) -> Option<String> {
    let focused = run_json("niri", &["msg", "--json", "focused-window"]).ok()?;
    let windows = run_json("niri", &["msg", "--json", "windows"]).ok()?;
    let workspaces = run_json("niri", &["msg", "--json", "workspaces"]).ok()?;
    let outputs = run_json("niri", &["msg", "--json", "outputs"]).ok()?;
    niri_geometry(target, &focused, &windows, &workspaces, &outputs)
}

/// Return only the focused supervisor's visible rectangle. Unknown compositor
/// geometry is an error; never guess from titles or order.
fn window_geometry(target: paste::Target) -> Option<String> {
    match target.compositor {
        Compositor::Niri => return niri_window_geometry(target),
        Compositor::Sway => {}
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

fn window_command(
    grim: &Path,
    target: paste::Target,
    geometry: Option<&str>,
    toplevel: bool,
) -> Result<Command, ()> {
    let mut command = Command::new(grim);
    match (target.compositor, toplevel, geometry) {
        (Compositor::Niri, true, _) => {
            command.arg("-T").arg(target.id.to_string());
        }
        (_, false, Some(geometry)) => {
            command.args(["-g", geometry]);
        }
        _ => return Err(()),
    }
    command.args(["-t", "png", "-"]);
    Ok(command)
}

fn capture_window(
    grim: &Path,
    target: paste::Target,
    geometry: Option<&str>,
    owner: BorrowedFd<'_>,
) -> Result<Vec<u8>, ()> {
    if target.compositor == Compositor::Niri {
        let direct = window_command(grim, target, geometry, true)?;
        if let Ok(Some(png)) = image_command(direct, None, Duration::from_secs(5), owner) {
            return Ok(png);
        }
        if window_geometry(target).as_deref() != geometry {
            return Err(());
        }
    }
    let region = window_command(grim, target, geometry, false)?;
    image_command(region, None, Duration::from_secs(5), owner)?.ok_or(())
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
        let png = if mode == "window" {
            capture_window(grim, target, geometry.as_deref(), owner.as_fd())?
        } else {
            let mut capture = Command::new(grim);
            capture.args(["-t", "png", "-"]);
            image_command(capture, None, Duration::from_secs(5), owner.as_fd())?.ok_or(())?
        };
        // Capture finishes before the editor exists. Crop only these pixels.
        let png = {
            let mut editor = Command::new(&tools.window);
            editor.arg("screenshot");
            if mode == "window" {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn target(compositor: Compositor) -> paste::Target {
        paste::Target {
            compositor,
            id: 42,
            pid: 77,
        }
    }

    fn fixture() -> (Value, Value, Value, Value) {
        let focused = json::parse(
            r#"{"id":42,"pid":77,"title":"chosen","is_focused":true,"is_floating":true,
                "workspace_id":9,"layout":{"tile_pos_in_workspace_view":[20.0,30.0],
                "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}"#,
        )
        .unwrap();
        let windows = json::parse(
            r#"[{"id":7,"pid":78,"title":"chosen","is_floating":true,"workspace_id":9,
                 "layout":{"tile_pos_in_workspace_view":[800.0,30.0],
                 "window_offset_in_tile":[4.0,4.0],"window_size":[100,100]}},
                {"id":42,"pid":77,"title":"chosen","is_floating":true,"workspace_id":9,
                 "layout":{"tile_pos_in_workspace_view":[20.0,30.0],
                 "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}]"#,
        )
        .unwrap();
        let workspaces =
            json::parse(r#"[{"id":9,"output":"test-output","is_active":true,"is_focused":true}]"#)
                .unwrap();
        let outputs = json::parse(
            r#"{"test-output":{"logical":{"x":-1920,"y":100,"width":1920,"height":1080}}}"#,
        )
        .unwrap();
        (focused, windows, workspaces, outputs)
    }

    #[test]
    fn niri_geometry_uses_the_focused_id_and_output_not_title_or_order() {
        let (focused, windows, workspaces, outputs) = fixture();
        assert_eq!(
            niri_geometry(
                target(Compositor::Niri),
                &focused,
                &windows,
                &workspaces,
                &outputs,
            )
            .as_deref(),
            Some("-1896,134 640x480")
        );
        assert_eq!(
            niri_geometry(
                paste::Target {
                    pid: 78,
                    ..target(Compositor::Niri)
                },
                &focused,
                &windows,
                &workspaces,
                &outputs,
            ),
            None
        );
    }

    #[test]
    fn niri_does_not_guess_scrolling_fractional_or_clipped_geometry() {
        let (_, windows, workspaces, outputs) = fixture();
        for (name, focused) in [
            (
                "scrolling position unavailable",
                r#"{"id":42,"pid":77,"is_focused":true,"is_floating":false,
                    "workspace_id":9,"layout":{"tile_pos_in_workspace_view":null,
                    "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}"#,
            ),
            (
                "fractional coordinates",
                r#"{"id":42,"pid":77,"is_focused":true,"is_floating":true,
                    "workspace_id":9,"layout":{"tile_pos_in_workspace_view":[20.5,30.0],
                    "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}"#,
            ),
            (
                "partially offscreen",
                r#"{"id":42,"pid":77,"is_focused":true,"is_floating":true,
                    "workspace_id":9,"layout":{"tile_pos_in_workspace_view":[-3000.0,30.0],
                    "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}"#,
            ),
        ] {
            let focused = json::parse(focused).unwrap();
            assert_eq!(
                niri_geometry(
                    target(Compositor::Niri),
                    &focused,
                    &windows,
                    &workspaces,
                    &outputs,
                ),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn niri_rejects_overlap_and_unprovable_neighbours() {
        let (focused, _, workspaces, outputs) = fixture();
        let overlapping = json::parse(
            r#"[{"id":7,"is_floating":true,"workspace_id":9,
                 "layout":{"tile_pos_in_workspace_view":[600.0,30.0],
                 "window_offset_in_tile":[4.0,4.0],"window_size":[100,100]}},
                {"id":42,"is_floating":true,"workspace_id":9,
                 "layout":{"tile_pos_in_workspace_view":[20.0,30.0],
                 "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}]"#,
        )
        .unwrap();
        assert_eq!(
            niri_geometry(
                target(Compositor::Niri),
                &focused,
                &overlapping,
                &workspaces,
                &outputs,
            ),
            None
        );

        let unknown_tiled = json::parse(
            r#"[{"id":7,"is_floating":false,"workspace_id":9,
                 "layout":{"tile_pos_in_workspace_view":null,
                 "window_offset_in_tile":[4.0,4.0],"window_size":[100,100]}},
                {"id":42,"is_floating":true,"workspace_id":9,
                 "layout":{"tile_pos_in_workspace_view":[20.0,30.0],
                 "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}]"#,
        )
        .unwrap();
        assert!(niri_geometry(
            target(Compositor::Niri),
            &focused,
            &unknown_tiled,
            &workspaces,
            &outputs,
        )
        .is_some());
        let tiled = json::parse(
            r#"{"id":42,"pid":77,"is_focused":true,"is_floating":false,
                "workspace_id":9,"layout":{"tile_pos_in_workspace_view":[20.0,30.0],
                "window_offset_in_tile":[4.0,4.0],"window_size":[640,480]}}"#,
        )
        .unwrap();
        assert_eq!(
            niri_geometry(
                target(Compositor::Niri),
                &tiled,
                &unknown_tiled,
                &workspaces,
                &outputs,
            ),
            None
        );
    }

    #[test]
    fn window_capture_never_degrades_to_an_unbounded_grim() {
        let niri = target(Compositor::Niri);
        let args = |command: &Command| {
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            args(&window_command(Path::new("/grim"), niri, None, true).unwrap()),
            ["-T", "42", "-t", "png", "-"]
        );
        assert_eq!(
            args(&window_command(Path::new("/grim"), niri, Some("1,2 3x4"), false).unwrap()),
            ["-g", "1,2 3x4", "-t", "png", "-"]
        );
        assert!(window_command(Path::new("/grim"), niri, None, false).is_err());
        let sway = target(Compositor::Sway);
        assert!(window_command(Path::new("/grim"), sway, None, true).is_err());
        assert_eq!(
            args(&window_command(Path::new("/grim"), sway, Some("1,2 3x4"), false).unwrap()),
            ["-g", "1,2 3x4", "-t", "png", "-"]
        );
    }
}
