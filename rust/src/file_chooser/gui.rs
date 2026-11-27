//! Host-side dialogs: kdialog for paths and Cellward's guarded window for grants.

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::sys::CancelToken;
use crate::tools::Tools;
use crate::window::Asked;

use super::{Chooser, Filter, Operation, Request, Selection};

const MAX_OUTPUT: usize = 1 << 20;

pub struct HostChooser {
    pub tools: Tools,
}

fn run_kdialog(
    program: &Path,
    args: &[OsString],
    cancel: &CancelToken,
) -> Option<(ExitStatus, Vec<u8>)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = std::time::Instant::now();
    let status = loop {
        if cancel.cancelled() || started.elapsed() >= std::time::Duration::from_secs(10 * 60) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(crate::sys::LOOK_AGAIN),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let bytes = reader.join().ok()?.ok()?;
    (bytes.len() <= MAX_OUTPUT).then_some((status, bytes))
}

fn output_paths(bytes: &[u8]) -> Vec<PathBuf> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .map(|line| PathBuf::from(OsString::from_vec(line.to_vec())))
        .collect()
}

fn filter_argument(filter: &Filter) -> String {
    let patterns = filter
        .rules
        .iter()
        .map(|(_, rule)| rule.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{patterns}|{}", filter.label)
}

impl HostChooser {
    fn common_args(request: &Request) -> Vec<OsString> {
        let mut args = vec![
            "--title".into(),
            if request.title.is_empty() {
                "Cellward FileChooser".into()
            } else {
                OsString::from(&request.title)
            },
        ];
        if let Some(label) = &request.accept_label {
            args.push("--ok-label".into());
            args.push(label.into());
        }
        if let Some(id) = request.parent_window.strip_prefix("x11:") {
            if !request.modal {
                return args;
            }
            if id.len() > 2
                && id.starts_with("0x")
                && id[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                args.push("--attach".into());
                args.push(id.into());
            }
        }
        args
    }

    fn choose_filter(&self, request: &Request, cancel: &CancelToken) -> Option<Option<Filter>> {
        if request.filters.len() <= 1 {
            return Some(
                request
                    .current_filter
                    .clone()
                    .or_else(|| request.filters.first().cloned()),
            );
        }
        let selected = request
            .current_filter
            .as_ref()
            .and_then(|current| request.filters.iter().position(|filter| filter == current))
            .unwrap_or(0);
        let mut args = Self::common_args(request);
        args.push("--default".into());
        args.push(selected.to_string().into());
        args.push("--menu".into());
        args.push("Фильтр файлов".into());
        for (index, filter) in request.filters.iter().enumerate() {
            args.push(index.to_string().into());
            args.push(filter.label.clone().into());
        }
        let (_, output) = run_kdialog(&self.tools.kdialog, &args, cancel)?;
        let selected = String::from_utf8_lossy(&output);
        let index = selected.trim().parse::<usize>().ok()?;
        Some(request.filters.get(index).cloned())
    }

    fn choose_options(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Option<Vec<(String, String)>> {
        let mut selected = Vec::with_capacity(request.choices.len());
        for choice in &request.choices {
            if choice.options.is_empty() {
                let mut args = Self::common_args(request);
                args.push("--yesnocancel".into());
                args.push(choice.label.clone().into());
                let (status, _) = run_kdialog(&self.tools.kdialog, &args, cancel)?;
                let selected_value = match status.code() {
                    Some(0) => "true",
                    Some(1) => "false",
                    _ => return None,
                };
                selected.push((choice.id.clone(), selected_value.into()));
                continue;
            }
            let initial = choice.defaults().1;
            let mut args = Self::common_args(request);
            args.push("--default".into());
            args.push(initial.clone().into());
            args.push("--menu".into());
            args.push(choice.label.clone().into());
            for (id, label) in &choice.options {
                args.push(id.clone().into());
                args.push(label.clone().into());
            }
            let (_, output) = run_kdialog(&self.tools.kdialog, &args, cancel)?;
            let answer = String::from_utf8_lossy(&output);
            let answer = answer.trim();
            if !choice.options.iter().any(|(id, _)| id == answer) {
                return None;
            }
            selected.push((choice.id.clone(), answer.to_owned()));
        }
        Some(selected)
    }

    fn start_path(&self, request: &Request) -> PathBuf {
        if let Some(file) = &request.current_file {
            return file.clone();
        }
        let folder = request
            .current_folder
            .clone()
            .unwrap_or_else(|| self.tools.home.clone());
        match &request.operation {
            Operation::Save {
                current_name: Some(name),
            } => folder.join(name),
            _ => folder,
        }
    }
}

impl Chooser for HostChooser {
    fn select(&self, request: &Request, cancel: &CancelToken) -> Option<Selection> {
        let current_filter = self.choose_filter(request, cancel)?;
        let choices = self.choose_options(request, cancel)?;
        let mut args = Self::common_args(request);
        match &request.operation {
            Operation::Open {
                directory: true, ..
            } => {
                args.push("--getexistingdirectory".into());
                args.push(self.start_path(request).into());
            }
            Operation::Open {
                multiple,
                directory: false,
            } => {
                args.push("--getopenfilename".into());
                args.push(self.start_path(request).into());
                if let Some(filter) = &current_filter {
                    args.push(filter_argument(filter).into());
                }
                if *multiple {
                    args.push("--multiple".into());
                    args.push("--separate-output".into());
                }
            }
            Operation::Save { .. } => {
                args.push("--getsavefilename".into());
                args.push(self.start_path(request).into());
                if let Some(filter) = &current_filter {
                    args.push(filter_argument(filter).into());
                }
            }
            Operation::SaveMany { .. } => {
                args.push("--getexistingdirectory".into());
                args.push(self.start_path(request).into());
            }
        }
        let (status, output) = run_kdialog(&self.tools.kdialog, &args, cancel)?;
        if !status.success() {
            return None;
        }
        Some(Selection {
            paths: output_paths(&output),
            choices,
            current_filter,
            confirmed: true,
        })
    }

    fn preview(&self, request: &Request, text: &str, cancel: &CancelToken) -> bool {
        let accept = request
            .accept_label
            .as_deref()
            .unwrap_or(match request.operation {
                Operation::Open { .. } => "Разрешить чтение",
                Operation::Save { .. } | Operation::SaveMany { .. } => "Сохранить",
            });
        let answer = crate::window::question_on_cancellable(
            &self.tools.window,
            None,
            "Cellward FileChooser",
            text,
            None,
            &[("cancel", "Отмена", false), ("allow", accept, true)],
            (Some(std::time::Duration::from_secs(5 * 60)), Some(cancel)),
        );
        match answer {
            Asked::Chose(tag) => tag == "allow",
            Asked::NotShown => {
                let started = std::time::Instant::now();
                let mut args = Self::common_args(request);
                args.push("--warningcontinuecancel".into());
                args.push(text.into());
                args.push("--continue-label".into());
                args.push(accept.into());
                args.push("--cancel-label".into());
                args.push("Отмена".into());
                run_kdialog(&self.tools.kdialog, &args, cancel).is_some_and(|(status, _)| {
                    status.success() && crate::dialog::not_too_soon(started).is_ok()
                })
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn multiple_path_output_keeps_non_utf8_bytes() {
        let paths = output_paths(b"/tmp/one\r\n/tmp/a b\n/tmp/\xff\n");
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], PathBuf::from("/tmp/one"));
        assert_eq!(paths[1], PathBuf::from("/tmp/a b"));
        assert_eq!(paths[2].as_os_str().as_bytes(), b"/tmp/\xff");
    }

    #[test]
    fn png_filter_is_passed_to_the_host_file_dialog() {
        let filter = Filter {
            label: "PNG images".into(),
            rules: vec![(1, "image/png".into())],
        };
        assert_eq!(filter_argument(&filter), "image/png|PNG images");
    }

    #[test]
    fn only_x11_window_handles_become_attach_arguments() {
        let request = Request {
            app_id: "vpnzone.app.test".into(),
            parent_window: "wayland:exported".into(),
            title: "Open".into(),
            accept_label: None,
            modal: false,
            operation: Operation::SaveMany { files: vec![] },
            filters: vec![],
            current_filter: None,
            choices: vec![],
            current_folder: None,
            current_file: None,
        };
        assert!(!HostChooser::common_args(&request).contains(&OsString::from("--attach")));
        assert!(!HostChooser::common_args(&request).contains(&OsString::from("--modal")));
        let request = Request {
            parent_window: "x11:0x123".into(),
            modal: true,
            accept_label: Some("Open now".into()),
            ..request
        };
        let args = HostChooser::common_args(&request);
        assert!(args.contains(&OsString::from("--attach")));
        assert!(args.contains(&OsString::from("0x123")));
        assert!(args.contains(&OsString::from("--ok-label")));
        assert!(args.contains(&OsString::from("Open now")));
    }
}
