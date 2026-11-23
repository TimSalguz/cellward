//! End-to-end checks of `cellward open`: real MIME discovery and `Exec`
//! expansion, with the picker and chooser replaced by recording scripts.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone");
const MIME: &str = "x-scheme-handler/cellward-open-test";

struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("cellward-open-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for dir in ["state", "profiles", "sandboxes", "config", "bin"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        let home = Self { root };
        home.manifest();
        home.script("picker", "printf '%s\\n' \"$@\" > \"$PICKER_LOG\"\n");
        home
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.path("bin").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn manifest(&self) {
        let mut json = String::from("{\n");
        for key in vpn_zone::tools::Tools::keys() {
            let value = match *key {
                "home" => self.root.to_string_lossy().into_owned(),
                "state" | "profiles" | "sandboxes" | "config" => {
                    self.path(key).to_string_lossy().into_owned()
                }
                "picker" | "window" => self
                    .path("bin")
                    .join(if *key == "picker" { "picker" } else { "window" })
                    .to_string_lossy()
                    .into_owned(),
                _ => format!("/nonexistent/{key}"),
            };
            json.push_str(&format!("  \"{key}\": \"{value}\",\n"));
        }
        json.pop();
        json.pop();
        json.push_str("\n}\n");
        fs::write(self.path("tools.json"), json).unwrap();
    }

    fn handler(&self, id: &str, name: &str, exec: &str) {
        let apps = self.path(".local/share/applications");
        fs::create_dir_all(&apps).unwrap();
        fs::write(
            apps.join(format!("{id}.desktop")),
            format!(
                "[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\nMimeType={MIME};\n"
            ),
        )
        .unwrap();
    }

    fn defaults(&self, text: &str) {
        fs::write(self.path("config/mimeapps.list"), text).unwrap();
    }

    fn real_launch_path(&self) {
        let manifest = self.path("tools.json");
        let text = fs::read_to_string(&manifest)
            .unwrap()
            .replace(
                self.path("bin/picker").to_str().unwrap(),
                env!("CARGO_BIN_EXE_vpn-zone-pick"),
            )
            .replace("/nonexistent/runner", BIN);
        fs::write(manifest, text).unwrap();
    }

    fn chooser(&self, answer: &str) {
        self.script(
            "window",
            &format!(
                "cat > /dev/null\nprintf '%s\\n' \"$@\" > \"$WINDOW_LOG\"\nprintf 'action\\t{answer}\\n'\n"
            ),
        );
    }

    fn run(&self, uri: &str) -> Output {
        self.run_args(&["open", uri])
    }

    fn run_args(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .env("VPN_ZONE_TOOLS", self.path("tools.json"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_DATA_DIRS", self.path("data"))
            .env("PICKER_LOG", self.path("picker.log"))
            .env("WINDOW_LOG", self.path("window.log"))
            .env_remove("XDG_CURRENT_DESKTOP")
            .env_remove("VPN_ZONE_CURRENT")
            .env_remove("VPN_ZONE_DELEGATED")
            .env_remove("VPN_ZONE_APPID")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn picker_args(&self) -> Option<Vec<String>> {
        fs::read_to_string(self.path("picker.log"))
            .ok()
            .map(|text| text.lines().map(str::to_owned).collect())
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn one_handler_skips_the_chooser_and_the_uri_reaches_the_picker_byte_for_byte() {
    let home = Home::new("exact");
    home.handler("exact", "Точный обработчик", "/bin/record --uri=%u");
    let uri = "cellward-open-test://Пример/путь с пробелом?запрос=один два&next=%2F%20";

    let out = home.run(uri);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        home.picker_args().unwrap(),
        [
            "--id".to_owned(),
            "exact".to_owned(),
            "--label".to_owned(),
            "Точный обработчик".to_owned(),
            "--".to_owned(),
            "/bin/record".to_owned(),
            format!("--uri={uri}"),
        ]
    );
    assert!(!home.path("window.log").exists());
}

#[test]
fn the_real_picker_and_launch_path_receive_the_expanded_command() {
    let home = Home::new("real-launch");
    home.handler("exact", "Exact", "/bin/record %u");
    let policy = home.path("config/containers/work/container.conf");
    fs::create_dir_all(policy.parent().unwrap()).unwrap();
    fs::write(policy, "home = main\nnetwork = unconfined\napp = exact\n").unwrap();
    fs::create_dir_all(home.path("state/.pinnedprofile")).unwrap();
    fs::write(home.path("state/.pinnedprofile/exact"), "work").unwrap();
    home.real_launch_path();
    let uri = "cellward-open-test:через пикер?x=один два";

    let out = home.run_env(&["open", uri], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = stdout(&out);
    assert!(shown.contains("сеть unconfined"), "{shown}");
    assert!(shown.contains(&format!("/bin/record {uri}")), "{shown}");
}

#[test]
fn a_real_distro_default_skips_the_chooser_without_rewriting_mimeapps() {
    let home = Home::new("default");
    home.handler("first", "First", "/bin/first %u");
    home.handler("second", "Second", "/bin/second %u");
    // The dispatcher itself is not a candidate, even when the host default names it.
    home.handler("vpn-zone-open", "Cellward", "/bin/cellward open %u");
    let mimeapps = "[Default Applications]\nx-scheme-handler/cellward-open-test=second.desktop;\n";
    home.defaults(mimeapps);

    let out = home.run("cellward-open-test:default");
    assert!(out.status.success(), "{}", stderr(&out));
    let args = home.picker_args().unwrap();
    assert_eq!(args[1], "second");
    assert_eq!(args.last().unwrap(), "cellward-open-test:default");
    assert!(!home.path("window.log").exists());
    assert_eq!(
        fs::read_to_string(home.path("config/mimeapps.list")).unwrap(),
        mimeapps
    );

    fs::remove_file(home.path(".local/share/applications/first.desktop")).unwrap();
    home.defaults(
        "[Default Applications]\nx-scheme-handler/cellward-open-test=vpn-zone-open.desktop;\n",
    );
    let out = home.run("cellward-open-test:not-recursive");
    assert!(out.status.success(), "{}", stderr(&out));
    let args = home.picker_args().unwrap();
    assert_ne!(args[1], "vpn-zone-open");
    assert_eq!(args.last().unwrap(), "cellward-open-test:not-recursive");
}

#[test]
fn several_handlers_use_the_cellward_choice_and_keep_the_uri_whole() {
    let home = Home::new("chosen");
    home.handler("first", "First", "/bin/first %u");
    home.handler("second", "Second", "/bin/second %u");
    home.chooser("handler-1");
    let uri = "cellward-open-test:выбор с пробелом?x=1&y=два";

    let out = home.run(uri);
    assert!(out.status.success(), "{}", stderr(&out));
    let args = home.picker_args().unwrap();
    assert_eq!(args[1], "second");
    assert_eq!(args.last().unwrap(), uri);
}

#[test]
fn a_handler_without_a_usable_field_code_is_rejected_not_started_bare() {
    let home = Home::new("no-field-code");
    home.handler("bare", "Bare", "/bin/record --no-uri");

    let out = home.run("cellward-open-test:must-not-start");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("не принимает ссылки"),
        "{}",
        stderr(&out)
    );
    assert_eq!(home.picker_args(), None);
}

#[test]
fn cancellation_an_unknown_tag_and_an_unavailable_chooser_start_nothing() {
    for (tag, answer, code) in [
        ("cancel", "cancel", 0),
        ("unknown", "handler-99", 0),
        ("unavailable", "", 1),
    ] {
        let home = Home::new(tag);
        home.handler("first", "First", "/bin/first %u");
        home.handler("second", "Second", "/bin/second %u");
        if tag != "unavailable" {
            home.chooser(answer);
        }
        let out = home.run("cellward-open-test:no-fallback");
        assert_eq!(out.status.code(), Some(code), "{tag}: {}", stderr(&out));
        assert_eq!(home.picker_args(), None, "{tag}");
    }
}

#[test]
fn open_requires_exactly_one_uri_with_a_scheme() {
    let home = Home::new("arguments");
    for args in [
        vec!["open"],
        vec!["open", "cellward-open-test:one", "cellward-open-test:two"],
        vec!["open", "not a URI"],
    ] {
        let out = home.run_args(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(home.picker_args(), None);
    }
}
