//! Trusted, host-side preview for a single physical paste in a private scope.
use super::*;
use crate::clipboard_endpoint::{self as endpoint, PastePlan};
use crate::i18n::{self, Key, Language};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn label(key: Key) -> &'static str {
    i18n::text(Language::default(), key)
}

#[derive(Clone, Copy)]
pub(super) struct Target {
    pub(super) compositor: Compositor,
    pub(super) id: i64,
    pub(super) pid: i32,
}

pub(super) fn sway_focused(value: &Value) -> Option<&Value> {
    if value.get("focused").and_then(Value::as_bool) == Some(true)
        && value.get("pid").and_then(Value::as_i64).is_some()
    {
        return Some(value);
    }
    ["nodes", "floating_nodes"]
        .iter()
        .filter_map(|k| value.get(k).and_then(Value::as_array))
        .flatten()
        .find_map(sway_focused)
}

impl Target {
    pub(super) fn focused(pid: i32) -> Option<Self> {
        let compositor = compositor()?;
        let value = match compositor {
            Compositor::Niri => run_json("niri", &["msg", "--json", "focused-window"]).ok()?,
            Compositor::Sway => run_json("swaymsg", &["-t", "get_tree", "-r"]).ok()?,
        };
        let node = match compositor {
            Compositor::Niri => &value,
            Compositor::Sway => sway_focused(&value)?,
        };
        if node.get("pid")?.as_i64()? != i64::from(pid) {
            return None;
        }
        Some(Self {
            compositor,
            id: node.get("id")?.as_i64()?,
            pid,
        })
    }
    pub(super) fn restore(self) -> bool {
        // Verify the original id still belongs to the same supervisor. Never
        // fall back to its newest window or to another application.
        let (program, args) = match self.compositor {
            Compositor::Niri => {
                let Ok(windows) = run_json("niri", &["msg", "--json", "windows"]) else {
                    return false;
                };
                if !windows_of_niri(&windows, self.pid).contains(&self.id) {
                    return false;
                }
                (
                    "niri",
                    vec![
                        "msg".into(),
                        "action".into(),
                        "focus-window".into(),
                        "--id".into(),
                        self.id.to_string(),
                    ],
                )
            }
            Compositor::Sway => {
                let Ok(tree) = run_json("swaymsg", &["-t", "get_tree", "-r"]) else {
                    return false;
                };
                if !windows_of_sway(&tree, self.pid).contains(&self.id) {
                    return false;
                }
                ("swaymsg", vec![format!("[con_id={}] focus", self.id)])
            }
        };
        Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

fn result(pid: i32, ticket: u64, revision: Option<u64>) -> bool {
    let path = crate::wl_proxy::ask_path(&crate::broker::runtime_dir(), pid);
    let Ok(mut socket) = std::os::unix::net::UnixStream::connect(path) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
    let mut body = b"\0smart-paste".to_vec();
    body.push(u8::from(revision.is_some()));
    body.extend_from_slice(&ticket.to_le_bytes());
    body.extend_from_slice(&revision.unwrap_or(0).to_le_bytes());
    let mut request = (body.len() as u16).to_le_bytes().to_vec();
    request.extend_from_slice(&body);
    let mut answer = [0];
    socket.write_all(&request).is_ok()
        && socket.read_exact(&mut answer).is_ok()
        && answer[0] == crate::wl_proxy::ASK_YES
}

pub(crate) fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let parsed = (|| {
        if args.len() != 3 {
            return None;
        }
        let pid = args[0].to_str()?.parse::<i32>().ok().filter(|p| *p > 1)?;
        let ticket = args[1].to_str()?.parse::<u64>().ok().filter(|t| *t > 0)?;
        let revision = args[2].to_str()?.parse::<u64>().ok()?;
        Some((pid, ticket, revision))
    })();
    let Some((pid, ticket, expected)) = parsed else {
        return 2;
    };
    let held = crate::sys::pidfd_open(pid);
    // Static reason codes only: never include clipboard data or peer labels.
    let attempt = (|| -> Result<Option<u64>, &'static str> {
        use std::os::fd::AsFd;
        let owner = held.as_ref().ok_or("owner-unavailable")?;
        let scope = private_clipboard_scope(tools, pid).ok_or("scope-unavailable")?;
        let target = Target::focused(pid).ok_or("target-not-focused")?;
        let runtime = crate::broker::runtime_dir();
        let until = Instant::now() + Duration::from_secs(10);
        let plan = loop {
            let plan = endpoint::prepare_paste(&runtime, &scope, expected)
                .map_err(|_| "prepare-failed")?;
            if matches!(plan, PastePlan::Pending(_)) {
                if Instant::now() >= until {
                    return Err("capture-wait-timeout");
                }
                std::thread::sleep(Duration::from_millis(25));
            } else {
                break plan;
            }
        };
        match plan {
            PastePlan::Current(revision) => Ok(Some(revision)),
            PastePlan::Pending(_) => Err("capture-pending"),
            PastePlan::Transfer(preview) => {
                let direction = format!("{} → {}", preview.source_history, preview.target_history);
                let body = format!(
                    "{direction}\n\n{}\n\n{}",
                    preview.preview,
                    preview
                        .types
                        .iter()
                        .map(|(mime, size)| format!("{mime} · {}", crate::cli::human_size(*size)))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                let choices = [
                    ("paste", label(Key::PasteConfirm), false),
                    ("cancel", label(Key::Cancel), false),
                ];
                // Enter is the explicit transfer the person requested. The
                // guarded window consumes the opening shortcut's repeats.
                if !matches!(crate::window::paste_question(&tools.window, label(Key::PastePreview), &body,
                    &choices), crate::window::Asked::Chose(tag) if tag == "paste")
                {
                    return Ok(None);
                }
                if preview.secret {
                    let choices = [
                        ("cancel", label(Key::Cancel), false),
                        ("paste", label(Key::PasteSecretConfirm), true),
                    ];
                    if !matches!(crate::window::question(&tools.window, label(Key::PastePreview),
                        &format!("{direction}\n\n{}", label(Key::PasteSecret)), None, &choices,
                        Some(Duration::from_secs(10))), crate::window::Asked::Chose(tag) if tag == "paste")
                    {
                        return Ok(None);
                    }
                }
                if !endpoint::alive(owner.as_fd()) {
                    return Err("owner-ended");
                }
                let revision = endpoint::commit_paste(&runtime, &scope, &preview, preview.secret)
                    .map_err(|_| "commit-rejected")?;
                if !target.restore() {
                    return Err("target-restore-failed");
                }
                crate::dialog::notify(
                    &tools.notify_send,
                    None,
                    "2500",
                    label(Key::PasteTransferred),
                    &direction,
                );
                Ok(Some(revision))
            }
        }
    })();
    let revision = match attempt {
        Ok(revision) => revision,
        Err(reason) => {
            eprintln!("smart-paste: unavailable ({reason})");
            crate::dialog::notify(
                &tools.notify_send,
                None,
                "5000",
                label(Key::PastePreview),
                label(Key::PasteUnavailable),
            );
            None
        }
    };
    if result(pid, ticket, revision) {
        0
    } else {
        eprintln!("smart-paste: original launch did not accept the result");
        1
    }
}
