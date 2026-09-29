//! End-to-end checks of the `vpn-zone` command line.
//!
//! Everything here runs against a state directory of its own and a manifest
//! whose tool paths point nowhere: not one of these cases may start a tool, and
//! a test that suddenly does would be a test that touches the developer's real
//! zones. The paths that DO need `systemctl`, `nsenter` or `kdialog` are the
//! ones the smoke test covers on a runner (`tests/integration/smoke.sh`).
//!
//! `VPN_ZONE_CURRENT` is scrubbed for the same reason as the compositor
//! variables in `wl_sandbox_cli.rs`: the developer's shell may well be running
//! inside a zone, and then every launch would take the delegation path and the
//! result would differ from CI.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_vpn-zone");

/// A state directory, a profile directory and a manifest naming them, removed
/// on drop.
struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("vpn-zone-cli-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for sub in ["state", "profiles", "sandboxes", "config"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let home = Self { root };
        home.write_manifest();
        home
    }

    /// The manifest the wrapper would normally hand over. Every tool points at
    /// a path that does not exist: if a test ever starts one, it fails loudly
    /// instead of poking the real system.
    fn write_manifest(&self) {
        let r = self.root.display();
        let mut json = String::from("{\n");
        for (key, value) in [
            ("home", format!("{r}")),
            ("state", format!("{r}/state")),
            ("profiles", format!("{r}/profiles")),
            ("sandboxes", format!("{r}/sandboxes")),
            ("config", format!("{r}/config")),
            ("runner", format!("{r}/bin/vpn-zone")),
            ("picker", format!("{r}/bin/vpn-zone-pick")),
            ("core", "/nonexistent/vpn-zone-core".to_owned()),
            ("systemctl", "/nonexistent/systemctl".to_owned()),
            ("systemd-run", "/nonexistent/systemd-run".to_owned()),
            ("nsenter", "/nonexistent/nsenter".to_owned()),
            ("unshare", "/nonexistent/unshare".to_owned()),
            ("ip", "/nonexistent/ip".to_owned()),
            ("kdialog", "/nonexistent/kdialog".to_owned()),
            ("bwrap", "/nonexistent/bwrap".to_owned()),
            ("dbus-proxy", "/nonexistent/xdg-dbus-proxy".to_owned()),
            ("xwayland", "/nonexistent/xwayland-satellite".to_owned()),
            ("openssl", "/nonexistent/openssl".to_owned()),
            ("certutil", "/nonexistent/certutil".to_owned()),
            ("opener", "/nonexistent/xdg-open".to_owned()),
            ("window", "/nonexistent/vpn-zone-window".to_owned()),
            ("busctl", "/nonexistent/busctl".to_owned()),
            ("secret-tool", "/nonexistent/secret-tool".to_owned()),
            ("notify-send", "/nonexistent/notify-send".to_owned()),
        ] {
            json.push_str(&format!("  \"{key}\": \"{value}\",\n"));
        }
        json.pop();
        json.pop();
        json.push_str("\n}\n");
        fs::write(self.manifest(), json).unwrap();
    }

    fn manifest(&self) -> PathBuf {
        self.root.join("tools.json")
    }

    fn state(&self) -> PathBuf {
        self.root.join("state")
    }

    /// Make a zone look like it is up: `zone.pid` naming a process that really
    /// exists (ourselves), with its start noted as the holder notes its own.
    fn zone_is_up(&self, zone: &str) {
        let dir = self.state().join(zone);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("zone.pid"), format!("{}\n", std::process::id())).unwrap();
        let stamp = vpn_zone::sys::process_stamp(std::process::id() as i32).unwrap();
        fs::write(dir.join("zone.start"), format!("{stamp}\n")).unwrap();
        fs::write(dir.join("ready"), "").unwrap();
    }

    /// Instance `id` up and ready in `network` — its space this very test
    /// process, as `zone_is_up` makes a zone of it — and the zone carrying
    /// it: its bridge's socket, held by the listener returned (stage 5 of
    /// the container design: a launch into a zone runs in its container's
    /// instance, never in the zone's own namespaces). A launch then goes
    /// all the way to exec'ing the manifest's `vpn-zone-core`, which does
    /// not exist.
    fn instance_is_up(&self, id: &str, network: &str) -> std::os::unix::net::UnixListener {
        use vpn_zone::instance;
        let dir = instance::dir(&self.state(), id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(instance::ID), format!("{id}\n")).unwrap();
        fs::write(dir.join(instance::NETWORK), format!("{network}\n")).unwrap();
        let me = std::process::id();
        fs::write(dir.join(instance::PID), format!("{me}\n")).unwrap();
        let stamp = vpn_zone::sys::process_stamp(me as i32).unwrap();
        fs::write(dir.join(instance::START), format!("{stamp}\n")).unwrap();
        fs::write(dir.join(instance::READY), "").unwrap();
        let socket = self.state().join(network).join(vpn_zone::bridge::SOCKET);
        let _ = fs::remove_file(&socket);
        std::os::unix::net::UnixListener::bind(socket).unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("VPN_ZONE_TOOLS", self.manifest())
            .env_remove("VPN_ZONE_CURRENT")
            .env_remove("VPN_ZONE_DELEGATED")
            .env_remove("VPN_ZONE_APPID")
            .env_remove("VPN_ZONE_DRYRUN")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY");
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Declare `text` at `path` as home-manager does: the text into the Nix
/// store, `path` a link to it (`rust/src/declared.rs`: a plain file in
/// `declared/` is nobody's word). These tests need Nix, as they need its
/// libseccomp; the store path is content-addressed and collected later.
fn declare(path: &Path, text: &str) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "cellward-cli-declare-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("cellward-test-declared");
    fs::write(&source, text).unwrap();
    let out = Command::new("nix-store")
        .arg("--add")
        .arg(&source)
        .output()
        .unwrap_or_else(|e| panic!("nix-store: {e} — run the tests where Nix is"));
    assert!(
        out.status.success(),
        "nix-store --add: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
    let stored = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let _ = fs::remove_file(path);
    std::os::unix::fs::symlink(stored, path).unwrap();
}

/// A synthetic config, in the Windows line endings Amnezia hands out.
fn crlf_config() -> String {
    [
        "[Interface]",
        "PrivateKey = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg=",
        "Address = 10.99.0.2/32",
        "",
        "[Peer]",
        "PublicKey = MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFk=",
        "AllowedIPs = 0.0.0.0/0",
        "Endpoint = 192.0.2.1:51820",
        "",
    ]
    .join("\r\n")
}

#[test]
fn the_help_works_without_a_manifest() {
    // Somebody who ran the binary without the wrapper has to be told what this
    // is, not what is missing.
    let out = Command::new(BIN)
        .arg("--help")
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.starts_with("cellward — сетевые зоны"), "{text}");
    for verb in ["cellward run", "cellward check", "cellward gc"] {
        assert!(text.contains(verb), "в справке нет «{verb}»");
    }
    // The short name and the old one are named in the header.
    let header = text.lines().take(2).collect::<Vec<_>>().join("\n");
    assert!(
        header.contains("cw") && header.contains("vpn-zone"),
        "{header}"
    );
}

#[test]
fn a_missing_or_broken_manifest_is_an_error_of_its_own() {
    let out = Command::new(BIN)
        .arg("list")
        .env_remove("VPN_ZONE_TOOLS")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("VPN_ZONE_TOOLS"), "{}", stderr(&out));

    let out = Command::new(BIN)
        .arg("list")
        .env("VPN_ZONE_TOOLS", "/nonexistent/tools.json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // An incomplete manifest names the key that is missing: that is what tells
    // the user the wrapper and the binary come from different generations.
    let home = Home::new("short-manifest");
    fs::write(home.manifest(), "{\"home\":\"/h\"}").unwrap();
    let out = home.run(&["list"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("state"), "{}", stderr(&out));
}

#[test]
fn add_copies_the_config_without_carriage_returns_and_at_mode_600() {
    let home = Home::new("add");
    let source = home.root.join("amnezia.conf");
    fs::write(&source, crlf_config()).unwrap();

    let out = home.run(&["add", "nl", source.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "зона nl создана");

    let copy = home.state().join("nl/config.conf");
    let text = fs::read_to_string(&copy).unwrap();
    assert!(!text.contains('\r'), "CRLF остался в копии конфига");
    assert!(text.contains("PrivateKey ="));
    let mode = fs::metadata(&copy).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "конфиг с приватным ключом не 0600: {mode:o}");

    // The original may go away afterwards — that is what the copy is for.
    fs::remove_file(&source).unwrap();
    assert!(copy.is_file());
}

#[test]
fn add_refuses_a_bad_name_and_a_file_that_is_not_a_config() {
    let home = Home::new("add-bad");
    let conf = home.root.join("ok.conf");
    fs::write(&conf, crlf_config()).unwrap();

    let out = home.run(&["add", "nl 2", conf.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("имя только из букв"),
        "{}",
        stderr(&out)
    );

    let out = home.run(&["add", "nl", "/nonexistent/x.conf"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("нет файла"), "{}", stderr(&out));

    let junk = home.root.join("junk.conf");
    fs::write(&junk, "это не конфиг\n").unwrap();
    let out = home.run(&["add", "nl", junk.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("не похож на конфиг"),
        "{}",
        stderr(&out)
    );
    assert!(!home.state().join("nl").exists(), "зона создана из мусора");

    // The built-in choices of the picker are not names a zone can take: a
    // zone called "unconfined" (or "direct", its old name) would be shadowed
    // by the host's network in every launch, and "offline" is the directory
    // the picker creates by itself.
    for reserved in ["unconfined", "direct", "offline", "host"] {
        let out = home.run(&["add", reserved, conf.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{reserved}");
        assert!(stderr(&out).contains("встроенный"), "{}", stderr(&out));
        assert!(
            !home.state().join(reserved).join("config.conf").exists(),
            "{reserved}"
        );
    }
}

#[test]
fn list_and_check_answer_for_a_zone_that_is_down() {
    let home = Home::new("down");
    fs::create_dir_all(home.state().join("nl")).unwrap();

    let out = home.run(&["list"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "nl — опущена");

    // 2 is "the zone is down", and it is a contract: this is grepped and
    // scripted against.
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out).trim(), "зона nl не поднята");
}

#[test]
fn check_answers_from_the_state_mirror() {
    let home = Home::new("check");
    home.zone_is_up("nl");
    let dir = home.state().join("nl");

    // No mirror at all: a zone brought up by an older version. Saying "dead"
    // here would be a lie, so it gets its own code.
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stdout(&out).contains("состояние неизвестно"),
        "{}",
        stdout(&out)
    );

    fs::write(
        dir.join("status"),
        "interface: awg0\n  public key: k\n\npeer: p\n  endpoint: 192.0.2.1:51820\n  \
         latest handshake: 1 minute, 5 seconds ago\n  transfer: 1 KiB received\n",
    )
    .unwrap();
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout(&out).contains("туннель живой (latest handshake: 1 minute, 5 seconds ago)"),
        "{}",
        stdout(&out)
    );

    fs::write(
        dir.join("status"),
        "interface: awg0\n\npeer: p\n  transfer: 0 B\n",
    )
    .unwrap();
    let out = home.run(&["check", "nl"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("рукопожатия нет"), "{}", stdout(&out));
}

#[test]
fn a_launch_is_wrapped_in_the_compositor_restriction_by_default() {
    // The default is ON, and with no setting file at all. Getting this wrong is
    // invisible from the outside — the program starts and works, only the
    // screen capture and the background clipboard reads are quietly back.
    let home = Home::new("wrap");
    home.zone_is_up("nl");
    // Its sockets by the instance's key: a launch into a zone runs in its
    // container's instance — the main home's here (stage 2 of the container
    // design), and only there since stage 5 (by the zone's name before).
    let key = vpn_zone::instance::key("main:nl");

    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = stdout(&out);
    // Outermost, on the host, and named by the space whose directory the
    // restricted socket goes into (LEAK-MODEL §13).
    assert!(
        line.starts_with(&format!(
            "сеть nl, контейнер настоящий дом: /nonexistent/vpn-zone-core wl-sandbox firefox --zone {key} --frame "
        )),
        "{line}"
    );
    // With the zone's border (docs/WINDOW-FRAME.md §0а): its colour and
    // width, and where the switch that hides it is.
    assert!(line.contains(" --frame-switch "), "{line}");
    assert!(line.trim_end().ends_with(" -- firefox"), "{line}");

    // Turned off by the setting the CLI itself writes — for unconfined
    // launches only: a zone has no unrestricted socket to hand out.
    let out = home.run(&["wayland-sandbox", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(
        stdout(&out).contains(&format!("wl-sandbox firefox --zone {key} --")),
        "{}",
        stdout(&out)
    );
    let out = home.run_with(
        &["run", "unconfined", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert_eq!(
        stdout(&out).trim(),
        "сеть unconfined, контейнер настоящий дом: firefox"
    );
    // The allowlist likewise: obs is let through unconfined only.
    fs::create_dir_all(home.root.join("config")).unwrap();
    let out = home.run(&["wayland-sandbox", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "obs"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(
        stdout(&out).contains(&format!("wl-sandbox obs --zone {key} --")),
        "{}",
        stdout(&out)
    );
    // Unconfined, a name on the list is not enough (2026-09-27): an `obs`
    // that is not the one the system's profiles give — none is, here — is
    // restricted like any other program…
    let out = home.run_with(
        &["run", "unconfined", "--", "obs"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(stdout(&out).contains("wl-sandbox obs"), "{}", stdout(&out));
    // …and a wayland-allow line naming a file by its path lets that file.
    let recorder = home.root.join("bin-rec/rec");
    fs::create_dir_all(recorder.parent().unwrap()).unwrap();
    fs::write(&recorder, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&recorder, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        home.root.join("config/wayland-allow"),
        format!("{}\n", recorder.display()),
    )
    .unwrap();
    let out = home.run_with(
        &["run", "unconfined", "--", recorder.to_str().unwrap()],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(!stdout(&out).contains("wl-sandbox"), "{}", stdout(&out));
}

#[test]
fn an_unconfined_launch_starts_no_zone_and_loses_nothing_on_the_way() {
    // "unconfined" is the host's network: nothing to start and nothing to enter.
    // But the compositor restriction and the container still apply — the
    // picker used to become the command itself and dropped both.
    let home = Home::new("unconfined");
    let out = home.run_with(
        &["run", "unconfined", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    // A zone start would have named the manifest's systemctl in a message and
    // waited ten seconds for a zone that does not exist.
    assert!(!stderr(&out).contains("systemctl"), "{}", stderr(&out));
    let line = stdout(&out);
    assert!(
        line.starts_with("сеть unconfined, контейнер настоящий дом:"),
        "{line}"
    );
    assert!(
        line.contains("wl-sandbox firefox --zone unconfined --"),
        "{line}"
    );

    // The old name is the same network.
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let out = home.run_with(
        &["run", "direct", "--profile", "work", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with("сеть unconfined, контейнер work:"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_zone_left_with_the_name_unconfined_is_refused_not_left_behind() {
    // Before the name was taken it could be a VPN zone: a launch "into" it now
    // would be the host's network, its tunnel silently skipped.
    let home = Home::new("unconfined-zone");
    home.zone_is_up("unconfined");
    fs::write(home.state().join("unconfined/config.conf"), "[Interface]\n").unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    for name in ["unconfined", "direct"] {
        let out = home.run_with(&["run", name, "--", "firefox"], &dry);
        assert_eq!(out.status.code(), Some(1), "{name}");
        assert!(stderr(&out).contains("Переименуй"), "{}", stderr(&out));
        assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    }
    let json = stdout(&home.run(&["status", "--json"]));
    assert_eq!(json.matches("\"name\":\"unconfined\"").count(), 1, "{json}");
}

/// 2e (2026-09-29): `host` is the host's own network — a zone of its own,
/// listed before it is made, made when first wanted, carrying a container's
/// instance like any network. A zone of the person's by that name from
/// before is refused, never written over.
#[test]
fn the_hosts_network_is_made_when_wanted_and_a_zone_by_its_name_refused() {
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let listed_once = |home: &Home| {
        let json = stdout(&home.run(&["status", "--json"]));
        assert_eq!(json.matches("\"name\":\"host\"").count(), 1, "{json}");
        assert!(
            json.contains("\"name\":\"host\",\"kind\":\"host-network\""),
            "{json}"
        );
    };
    let home = Home::new("hostnet");
    listed_once(&home);
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    home.zone_is_up("host");
    let out = home.run_with(&["run", "host", "--profile", "work", "--", "firefox"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("сеть host, контейнер work"),
        "{}",
        stdout(&out)
    );
    assert_eq!(
        fs::read_to_string(home.state().join("host/config.conf")).unwrap(),
        "[HostNetwork]\n"
    );
    listed_once(&home);

    let home = Home::new("hostzone");
    home.zone_is_up("host");
    fs::write(home.state().join("host/config.conf"), "[Interface]\n").unwrap();
    let out = home.run_with(&["run", "host", "--", "firefox"], &dry);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stderr(&out).contains("Переименуй"), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(home.state().join("host/config.conf")).unwrap(),
        "[Interface]\n",
        "never written over"
    );
    listed_once(&home);
    let out = home.run(&["up", "host"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Переименуй"), "{}", stderr(&out));
}

/// 2e (2026-09-29): «без изоляции» is the built-in record `open` — a
/// container of the real home with everything open, the whole home given,
/// in the network asked, a VPN's too. Written anew before every launch into
/// it and not to be changed; a container of the person's by that name is
/// never written over.
#[test]
fn no_isolation_is_a_record_with_everything_open() {
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let home = Home::new("open");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let out = home.run_with(&["run", "nl", "--no-isolation", "--", "claude"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("сеть nl, контейнер open"),
        "{}",
        stdout(&out)
    );
    let policy = home.root.join("config/containers/open");
    let record = fs::read_to_string(policy.join("container.conf")).unwrap();
    for line in [
        "builtin=open",
        "home=main",
        "hermetic=false",
        "host_files_writable=true",
        "camera=true",
        "microphone=yes",
        "device=all",
    ] {
        assert!(record.lines().any(|l| l == line), "{line}: {record}");
    }
    assert_eq!(
        fs::read_to_string(policy.join("paths")).unwrap().trim(),
        home.root.display().to_string()
    );
    // Changed by hand: written back before the next launch.
    fs::write(policy.join("container.conf"), "builtin=open\nhome=main\n").unwrap();
    let out = home.run_with(&["run", "nl", "--container", "open", "--", "claude"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    let record = fs::read_to_string(policy.join("container.conf")).unwrap();
    assert!(record.contains("device=all"), "{record}");
    // Not to be changed, nor made by hand.
    for args in [
        &["container", "set", "open", "camera", "off"][..],
        &["container", "devices", "open", "add", "games"],
        &["container", "grant", "open", "~/x"],
        &["container", "create", "open"],
    ] {
        let out = home.run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stdout(&out));
    }

    let home = Home::new("openmine");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let policy = home.root.join("config/containers/open");
    fs::create_dir_all(&policy).unwrap();
    fs::write(policy.join("container.conf"), "home=private\n").unwrap();
    let out = home.run_with(&["run", "nl", "--no-isolation", "--", "claude"], &dry);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stderr(&out).contains("без изоляции"), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(policy.join("container.conf")).unwrap(),
        "home=private\n",
        "never written over"
    );
}

/// Step 3 (2026-09-29): a program's preset — what its own container takes
/// by itself when it is made (asking for the microphone and the screen),
/// and what is only offered (the cameras).
#[test]
fn a_programs_own_container_takes_what_its_preset_gives_by_itself() {
    let home = Home::new("preset");
    let out = home.run(&["presets", "vesktop"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("микрофон — спрашивать — само"), "{text}");
    assert!(text.contains("камеры — по выбору"), "{text}");
    let json = stdout(&home.run(&["presets", "--json"]));
    assert!(
        json.contains("{\"id\":\"vesktop\",\"source\":\"default\""),
        "{json}"
    );
    assert!(
        stdout(&home.run(&["presets", "no-such-program"])).contains("заготовки нет"),
        "a program with none"
    );
    // Made at its first launch, which goes no further here (no systemctl).
    let _ = home.run(&[
        "run",
        "offline",
        "--sandbox",
        "app-vesktop",
        "--",
        "vesktop",
    ]);
    let record = fs::read_to_string(
        home.root
            .join("config/containers/app-vesktop/container.conf"),
    )
    .unwrap();
    assert!(
        record.contains("microphone = ask") && record.contains("screencast = ask"),
        "{record}"
    );
    assert!(!record.contains("camera"), "only offered: {record}");
}

/// 3d (2026-09-29): «always focused» is a container's word, off without
/// one; the launch tells wl-sandbox, whose frame keeps it.
#[test]
fn always_focused_is_a_containers_word_off_without_one() {
    let home = Home::new("afocus");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/game")).unwrap();
    let said = |home: &Home| {
        let json = stdout(&home.run(&["status", "--json"]));
        let at = json.find("\"name\":\"game\"").expect("the container");
        json[at..]
            .split("\"always_focused\":")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_eq!(said(&home), "{\"value\":false,\"source\":\"default\"");
    let out = home.run(&["container", "set", "game", "always-focused", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(said(&home), "{\"value\":true,\"source\":\"local\"");
    let line = stdout(&home.run_with(
        &["run", "nl", "--container", "game", "--", "steam"],
        &[("VPN_ZONE_DRYRUN", "1")],
    ));
    assert!(line.contains("--always-focused"), "{line}");
    let out = home.run(&["container", "set", "game", "always-focused", "maybe"]);
    assert_eq!(out.status.code(), Some(1));
    let out = home.run(&["container", "set", "game", "always-focused", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(said(&home), "{\"value\":false,\"source\":\"default\"");
}

/// Stage 4 of the firewall (2026-09-29): a container's network by program
/// — a program's line, the record's default for the rest, the template's
/// without one ("ask" built in); «без изоляции» takes none.
#[test]
fn a_containers_network_rules_are_its_programs_lines() {
    let home = Home::new("netrules");
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let ok = |args: &[&str]| {
        let out = home.run(args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        stdout(&out)
    };
    let shown = ok(&["container", "net", "work"]);
    assert!(
        shown.contains("остальным программам: спрашивать"),
        "{shown}"
    );
    ok(&["container", "net", "work", "deny", "curl"]);
    ok(&["container", "net", "work", "allow", "firefox"]);
    ok(&["container", "net", "work", "default", "deny"]);
    let shown = ok(&["container", "net", "work"]);
    assert!(shown.contains("curl: сети нет"), "{shown}");
    assert!(shown.contains("firefox: сеть есть"), "{shown}");
    assert!(shown.contains("остальным программам: сети нет"), "{shown}");
    let record =
        fs::read_to_string(home.root.join("config/containers/work/container.conf")).unwrap();
    assert!(record.contains("net_deny = curl"), "{record}");
    assert!(record.contains("net_default = deny"), "{record}");
    ok(&["container", "net", "work", "forget", "curl"]);
    ok(&["container", "net", "work", "default", "none"]);
    let shown = ok(&["container", "net", "work"]);
    assert!(!shown.contains("curl"), "{shown}");
    assert!(
        shown.contains("остальным программам: спрашивать"),
        "{shown}"
    );
    // The template's word, for every record without one of its own.
    ok(&["defaults", "set", "network", "yes"]);
    let shown = ok(&["container", "net", "work"]);
    assert!(shown.contains("остальным программам: сеть есть"), "{shown}");
    for bad in [
        &["container", "net", "work", "deny", "a b"][..],
        &["container", "net", "work", "maybe", "x"],
        &["container", "net", "nosuch"],
    ] {
        assert_eq!(home.run(bad).status.code(), Some(1), "{bad:?}");
    }
}

#[test]
fn a_sandboxed_launch_carries_the_tool_paths_of_the_manifest() {
    let home = Home::new("fs-flags");
    home.zone_is_up("nl");
    let out = home.run_with(
        &["run", "nl", "--sandbox", "work", "--", "telegram-desktop"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "telegram")],
    );
    let line = stdout(&out);
    for expected in [
        "fs-sandbox",
        "--bwrap /nonexistent/bwrap",
        "--dbus-proxy /nonexistent/xdg-dbus-proxy",
        "--kdialog /nonexistent/kdialog",
        "--xwayland /nonexistent/xwayland-satellite",
        "telegram --name work --",
    ] {
        assert!(line.contains(expected), "нет «{expected}» в: {line}");
    }
}

#[test]
fn a_missing_container_stops_the_launch_with_the_way_out() {
    let home = Home::new("no-profile");
    home.zone_is_up("nl");
    let out = home.run_with(
        &["run", "nl", "--profile", "work", "--", "firefox"],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("контейнера work нет — создай: cellward container create work"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_locked_zone_runs_the_command_where_it_already_is() {
    // No nsenter, no systemd-run: re-entering a namespace is impossible and
    // delegating out of a quarantine zone is forbidden, so the selection
    // arguments are dropped and the command runs on the spot.
    let home = Home::new("locked");
    let dir = home.state().join("nl");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("no-escape"), "").unwrap();

    let out = home.run_with(
        &[
            "run",
            "de",
            "--profile",
            "work",
            "--fs-sandbox",
            "--",
            "echo",
            "hi",
        ],
        &[("VPN_ZONE_CURRENT", "nl")],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "hi");
    assert!(stderr(&out).contains("зона nl заперта"), "{}", stderr(&out));

    // Nothing left after the flags are dropped: a message, not an attempt to
    // execute the flag itself.
    let out = home.run_with(&["run", "de"], &[("VPN_ZONE_CURRENT", "nl")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("нечего запускать"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn containers_and_sandboxes_are_created_listed_and_removed() {
    let home = Home::new("containers");

    assert_eq!(
        stdout(&home.run(&["profile", "list"])).trim(),
        "контейнеров вида «слой над домом» нет. Создать: cellward container create <имя> --home layer"
    );
    assert!(home.run(&["profile", "create", "work"]).status.success());
    assert!(home.root.join("profiles/work").is_dir());
    assert!(stdout(&home.run(&["profile", "list"])).contains("work — слой над домом"));

    // A leading dash is refused: kdialog takes such an argument for an option
    // and closes without a word.
    let out = home.run(&["profile", "create", "-bad"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("не может быть именем"),
        "{}",
        stderr(&out)
    );
    // Cyrillic, on the other hand, is fine — and one name is one container,
    // whatever its home: the data in one directory, the kind in its settings.
    assert!(home.run(&["sandbox", "create", "личное"]).status.success());
    assert!(home.root.join("profiles/личное/home").is_dir());
    let out = home.run(&["container", "create", "work", "--home", "private"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("уже есть"), "{}", stderr(&out));
    assert!(home
        .run(&["container", "create", "files", "--home", "main"])
        .status
        .success());
    let list = stdout(&home.run(&["container", "list"]));
    assert!(list.contains("настоящий дом"), "{list}");
    assert!(list.contains("свой дом"), "{list}");

    assert!(home.run(&["profile", "rm", "work"]).status.success());
    assert!(!home.root.join("profiles/work").exists());
    let out = home.run(&["profile", "rm", "work"]);
    assert_eq!(out.status.code(), Some(1));
    // The words from before are gone with a pointer to what does the job.
    let out = home.run(&["isolate", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("больше нет"), "{}", stderr(&out));
}

#[test]
fn two_entries_for_one_binary_see_each_other() {
    // A Steam game's shortcut (id PEAK) and Steam itself, firefox and its
    // private-window entry: different ids, one single-instance binary. The
    // second launch hands its work to the process that is already up, in ITS
    // network — and the warning used to stay silent.
    //
    // Not a dry run: a dry run says nothing about conflicts on purpose. The
    // launch goes all the way to exec'ing the manifest's `vpn-zone-core`,
    // which does not exist — so it fails AFTER the warning, which is what is
    // looked at. (Into the main home's instance, faked up: nothing is
    // launched into a zone's own namespaces since stage 5 — the manifest's
    // nsenter it went to until then.)
    let home = Home::new("by-binary");
    home.zone_is_up("nl");
    let _instance = home.instance_is_up("main:nl", "nl");
    let index = home.state().join(".running/__main__/.by-binary");
    fs::create_dir_all(&index).unwrap();
    fs::write(index.join("steam"), format!("{} de \n", std::process::id())).unwrap();

    let out = home.run_with(
        &["run", "nl", "--", "steam", "steam://rungameid/1"],
        &[("VPN_ZONE_APPID", "PEAK")],
    );
    // Without a graphical session the warning goes to stderr — and for a link
    // it says what really happens to a link.
    let err = stderr(&out);
    assert!(err.contains("уже запущена в сети «de»"), "{err}");
    assert!(err.contains("ссылку ты открываешь в «nl»"), "{err}");

    // A plain launch of another id of the same binary gets the ordinary text.
    fs::write(
        index.join("firefox"),
        format!("{} de \n", std::process::id()),
    )
    .unwrap();
    let out = home.run_with(
        &["run", "nl", "--", "firefox", "--private-window"],
        &[("VPN_ZONE_APPID", "firefox-private")],
    );
    let err = stderr(&out);
    assert!(err.contains("уже запущена в сети «de»"), "{err}");
    assert!(err.contains("окно ОТКРОЕТСЯ"), "{err}");

    // In a graphical session the person is asked; a question that cannot
    // be put (no kdialog here) stops the launch, and says why — before, it
    // ended with success and nothing to show (2026-09-28).
    let out = home.run_with(
        &["run", "nl", "--", "firefox", "--private-window"],
        &[
            ("VPN_ZONE_APPID", "firefox-private"),
            ("WAYLAND_DISPLAY", "wayland-test"),
        ],
    );
    assert_eq!(out.status.code(), Some(127), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("спросить не вышло"), "{err}");
    assert!(err.contains("не открылось"), "{err}");

    // The same binary in the SAME network is no conflict at all.
    fs::write(
        index.join("firefox"),
        format!("{} nl \n", std::process::id()),
    )
    .unwrap();
    let out = home.run_with(
        &["run", "nl", "--", "firefox"],
        &[("VPN_ZONE_APPID", "firefox-private")],
    );
    assert!(!stderr(&out).contains("уже запущена"), "{}", stderr(&out));
    // …and the launch was filed under both keys on the way.
    let by_id = fs::read_to_string(home.state().join(".running/__main__/firefox-private")).unwrap();
    assert!(by_id.contains(" nl "), "{by_id}");
    let by_binary = fs::read_to_string(index.join("firefox")).unwrap();
    assert_eq!(by_binary.lines().count(), 2, "{by_binary}");
}

#[test]
fn a_launch_asked_for_from_a_zone_is_marked_and_its_id_is_a_file_name() {
    // The broker hands on what a program in a zone asked for — the app id
    // too. It is a file name in the registry, and the launch is marked as
    // not the user's own (the picker does not follow it without asking).
    let home = Home::new("from-zone");
    home.zone_is_up("nl");
    // Into the main home's instance, faked up, as far as the exec (stage 5).
    let _instance = home.instance_is_up("main:nl", "nl");
    let _ = home.run_with(
        &["run", "nl", "--", "true"],
        &[
            ("VPN_ZONE_DELEGATED", "1"),
            ("VPN_ZONE_APPID", "/tmp/../x/firefox"),
        ],
    );
    let main = home.state().join(".running/__main__");
    assert!(main.join("_tmp_.._x_firefox").is_file());
    let started: Vec<String> = fs::read_dir(home.state().join(".running/.started"))
        .unwrap()
        .flatten()
        .map(|e| fs::read_to_string(e.path()).unwrap())
        .collect();
    assert!(
        started.iter().any(|s| s.lines().any(|l| l == "from-zone")),
        "{started:?}"
    );
}

#[test]
fn only_a_throwaway_container_of_ours_can_be_joined() {
    // Its layer is erased behind the last tenant: a directory named by a
    // request would go with it.
    let home = Home::new("join");
    home.zone_is_up("nl");
    let other = home.root.join("documents");
    fs::create_dir_all(&other).unwrap();
    let out = home.run_with(
        &[
            "run",
            "nl",
            "--tmp-profile",
            "--join",
            other.to_str().unwrap(),
            "--",
            "true",
        ],
        &[("VPN_ZONE_DRYRUN", "1")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("не временный контейнер"),
        "{}",
        stderr(&out)
    );
    let ours = home.state().join(".throwaway/vpn-profile-abc12345");
    fs::create_dir_all(&ours).unwrap();
    let join = |zone: &str| {
        home.run_with(
            &[
                "run",
                zone,
                "--tmp-profile",
                "--join",
                ours.to_str().unwrap(),
                "--",
                "true",
            ],
            &[("VPN_ZONE_DRYRUN", "1")],
        )
    };
    // Nothing runs in it: what is left of it is nobody's to join.
    let out = join("nl");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("больше нет"), "{}", stderr(&out));
    // Its programs run in nl: joined there, and nowhere else.
    let reg = home.state().join(".running/vpn-profile-abc12345/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(&reg, format!("{} nl __tmp__\n", std::process::id())).unwrap();
    let out = join("nl");
    assert!(out.status.success(), "{}", stderr(&out));
    let out = join("direct");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("двух сетях"), "{}", stderr(&out));
}

/// Stage 2 of the container design (2026-09-27): a launch into a zone that
/// carries instances — its bridge's socket there — runs in its container's
/// instance (the Wayland sockets by the instance's key). Stage 5
/// (2026-09-28): only there. One into a zone of a previous build — up, no
/// bridge — went into the zone's own namespaces, with a notice, and this test
/// said so; now it is refused, and the refusal says the way out, the zone's
/// restart. A dry run starts and asks nothing, as before: its line is the
/// instance's either way.
#[test]
fn a_launch_into_a_zone_runs_in_its_containers_instance() {
    let home = Home::new("into-instance");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), "[Interface]\n").unwrap();
    let key = vpn_zone::instance::key("main:nl");
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let out = home.run_with(&["run", "nl", "--", "foot"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("wl-sandbox foot --zone {key} ")),
        "{}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("--zone nl "), "{}", stdout(&out));
    // For real: refused, the zone's own namespaces never entered.
    let out = home.run(&["run", "nl", "--", "foot"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("не везёт контейнеры"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("cellward restart nl"),
        "{}",
        stderr(&out)
    );
    // Nothing was put on the record: the launch never came to it.
    assert!(!home.state().join(".running/__main__/foot").exists());
    let socket = home.state().join("nl").join(vpn_zone::bridge::SOCKET);
    let bridge = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let out = home.run_with(&["run", "nl", "--", "foot"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("wl-sandbox foot --zone {key} ")),
        "{}",
        stdout(&out)
    );
    assert!(
        !stderr(&out).contains("не везёт контейнеры"),
        "{}",
        stderr(&out)
    );
    drop(bridge);
}

#[test]
fn a_zone_whose_process_is_in_our_network_is_not_entered() {
    // `zone.pid` of a stopped zone stays behind, and its number comes round to
    // another process. Here it names this test itself — the host's network:
    // entering it would start the program on the host under the zone's name.
    // Until stage 5 of the container design a last check before the `exec`
    // refused that ("указывает на процесс в сети хоста"); since then nothing
    // enters a zone's namespaces at all — the launch runs in an instance,
    // whose way out only a bridge the zone serves gives, and such a "zone"
    // serves none: refused before anything is started.
    let home = Home::new("zone-is-host");
    home.zone_is_up("nl");
    let out = home.run(&["run", "nl", "--", "true"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("не везёт контейнеры"),
        "{}",
        stderr(&out)
    );
    assert!(!home.state().join(".instances").exists());
}

#[test]
fn a_trusted_certificate_needs_a_real_container_and_one_certificate() {
    let home = Home::new("trust-add");
    let pem = home.root.join("ca.pem");
    let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    fs::write(&pem, one).unwrap();

    let out = home.run(&["trust", "add", "nope", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("контейнера nope нет"),
        "{}",
        stderr(&out)
    );

    // The main profile is the host's: a certificate there would be the host's.
    let out = home.run(&["trust", "add", "__main__", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("не контейнер"), "{}", stderr(&out));

    let out = home.run(&["trust", "add", "sb:nope", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("контейнера nope нет"),
        "{}",
        stderr(&out)
    );

    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    // A bundle is refused before anything is run.
    let bundle = home.root.join("bundle.pem");
    fs::write(&bundle, format!("{one}{one}")).unwrap();
    let out = home.run(&["trust", "add", "work", bundle.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("добавляй по одному"),
        "{}",
        stderr(&out)
    );

    // One certificate reaches openssl — here the manifest's, which is not there.
    let out = home.run(&["trust", "add", "work", pem.to_str().unwrap(), "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("/nonexistent/openssl"),
        "{}",
        stderr(&out)
    );
    assert!(!home.root.join("config/containers/work/trust").exists());
}

#[test]
fn trusted_certificates_are_listed_and_removed_by_fingerprint() {
    let home = Home::new("trust-list");
    let out = home.run(&["trust", "list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("нет ни у одного"), "{}", stdout(&out));

    // The container is its data directory; its certificates are with its
    // policy.
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let trust = home.root.join("config/containers/work/trust");
    fs::create_dir_all(&trust).unwrap();
    let a = format!("0f1e{}", "a".repeat(60));
    let b = format!("0f1f{}", "b".repeat(60));
    fs::write(trust.join(format!("{a}.pem")), "x").unwrap();
    fs::write(trust.join(format!("{b}.pem")), "x").unwrap();

    // openssl is not there, and the certificates are listed all the same: by
    // their fingerprints. Hiding one would hide that it is trusted.
    let out = home.run(&["trust", "list", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
    assert!(json.contains(&format!("\"sha256\":\"{a}\"")), "{json}");
    assert!(json.contains("\"container\":\"work\""), "{json}");

    let out = home.run(&["trust", "rm", "work", "0f1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("подходит к 2"), "{}", stderr(&out));

    let out = home.run(&["trust", "rm", "work", "0F1E"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!trust.join(format!("{a}.pem")).exists());
    assert!(trust.join(format!("{b}.pem")).exists());
    // A data container's NSS databases are cleaned from inside the next launch,
    // which the (still existing) trust directory switches on.
    assert!(
        stdout(&out).contains("при следующем запуске"),
        "{}",
        stdout(&out)
    );

    let out = home.run(&["trust", "reset", "work"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(trust.is_dir());
    assert!(fs::read_dir(&trust).unwrap().next().is_none());
}

#[test]
fn a_container_bound_to_a_network_runs_there_only() {
    // docs/CONTAINERS.md I1: one identity, one network at a time, and a change
    // of network is an action of its own — never a side effect of a launch.
    let home = Home::new("bound");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();

    let out = home.run(&["container", "set", "work", "network", "nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("сети nope нет"), "{}", stderr(&out));

    let out = home.run(&["container", "set", "work", "network", "nl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
    assert!(
        json.contains("\"network\":{\"value\":\"nl\",\"source\":\"local\"}"),
        "{json}"
    );

    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let out = home.run_with(
        &["run", "direct", "--profile", "work", "--", "firefox"],
        &dry,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("работает в сети «nl»"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("cellward container set work network unconfined"),
        "{}",
        stderr(&out)
    );
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "firefox"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));

    // Unbinding brings the per-launch question back.
    let out = home.run(&["container", "set", "work", "network", "ask"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(
        &["run", "direct", "--profile", "work", "--", "firefox"],
        &dry,
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn kill_refuses_what_is_not_a_zone_of_its_own() {
    let home = Home::new("kill");
    // The exit codes are a contract: 2 not up, 3 refused.
    for name in ["unconfined", "direct"] {
        let out = home.run(&["kill", name]);
        assert_eq!(out.status.code(), Some(3), "{name}");
        assert!(stderr(&out).contains("без изоляции"), "{}", stderr(&out));
    }
    assert_eq!(home.run(&["kill"]).status.code(), Some(3));
    let out = home.run(&["kill", "nl"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("не поднята"), "{}", stderr(&out));
    // A zone whose pid is a process of the host's network: "everything in its
    // namespace" would be the whole session. Refused before anything is
    // touched — this very test process is in that namespace.
    home.zone_is_up("nl");
    let out = home.run(&["kill", "nl"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("отказываюсь"), "{}", stderr(&out));
    assert!(!home.state().join(".journal").exists());
}

#[test]
fn the_journal_reads_for_a_person_and_for_a_program() {
    let home = Home::new("journal");
    let out = home.run(&["journal"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("журнал пуст"), "{}", stdout(&out));
    fs::create_dir_all(home.state()).unwrap();
    fs::write(
        home.state().join(".journal"),
        "{\"time\":\"2026-09-17T13:05:09Z\",\"event\":\"launch-unconfined\",\"app\":\"firefox\",\"container\":\"sb:web\",\"program\":\"firefox\",\"pid\":\"42\"}\n\
         {\"time\":\"2026-09-17T13:06:00Z\",\"event\":\"broker\",\"origin\":\"nl\",\"target\":\"unconfined\",\"app\":\"tg\",\"decision\":\"refused\",\"why\":\"человек отказал\"}\n\
         {\"time\":\"cut sho\n",
    )
    .unwrap();
    let out = stdout(&home.run(&["journal"]));
    assert!(
        out.contains(
            "2026-09-17 13:05:09 UTC  без изоляции: firefox (firefox, контейнер sb:web), pid 42"
        ),
        "{out}"
    );
    assert!(
        out.contains("брокер: из зоны «nl» в «unconfined» — tg — отказано: человек отказал"),
        "{out}"
    );
    assert!(out.contains("(повреждённая строка)"), "{out}");
    let out = stdout(&home.run(&["journal", "--json", "2"]));
    assert!(
        out.starts_with("{\"schema_version\":1,\"events\":[{\"time\":\"2026-09-17T13:06:00Z\",\"event\":\"broker\""),
        "{out}"
    );
    assert!(out.trim_end().ends_with("}]}"), "{out}");
    assert_eq!(home.run(&["journal", "0"]).status.code(), Some(1));
}

#[test]
fn a_container_is_never_in_two_networks_at_once() {
    // docs/CONTAINERS.md I2: even an unbound container, while its programs run.
    let home = Home::new("two-networks");
    // The zone is there, not up: a record of a container in an up zone whose
    // process is this very test would be a launch in the zone's own
    // namespaces (`launch::zone_launches_refusal`), which the launch into
    // its instance refuses — no longer skipped for a zone of a previous
    // build since stage 5, and not what this test is about.
    fs::create_dir_all(home.state().join("nl")).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let reg = home.state().join(".running/work/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(&reg, format!("{} nl work\n", std::process::id())).unwrap();

    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let out = home.run_with(&["run", "direct", "--profile", "work", "--", "tg"], &dry);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("двух сетях"), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "tg"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    // And the binding cannot be moved under running programs either.
    let out = home.run(&["container", "set", "work", "network", "direct"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("сейчас работают в сети nl"),
        "{}",
        stderr(&out)
    );
}

/// A file in `declared/` that is not a link into the Nix store is nobody's
/// declaration (review 2026-09-27): not shown as Nix's, not in the way of the
/// CLI, and said so on stderr. Anything that writes the home — a host
/// program, a file chooser — could put one there.
#[test]
fn a_plain_file_in_declared_is_not_nixs_word() {
    let home = Home::new("declared-plain");
    let declared = home.root.join("config/declared");
    fs::create_dir_all(declared.join("containers")).unwrap();
    fs::write(declared.join("hermetic-default"), "off").unwrap();
    let elsewhere = home.root.join("elsewhere");
    fs::write(&elsewhere, "leave").unwrap();
    std::os::unix::fs::symlink(&elsewhere, declared.join("user-entries")).unwrap();
    fs::write(
        declared.join("containers/dev.conf"),
        "home = private\nnetwork = unconfined\n",
    )
    .unwrap();

    let out = home.run(&["status", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(
        json.contains("\"hermetic\":{\"value\":true,\"source\":\"default\"},\"ask_again\":"),
        "{json}"
    );
    assert!(
        json.contains("\"user_entries\":{\"value\":\"take-over\",\"source\":\"default\"}"),
        "{json}"
    );
    assert!(!json.contains("\"selector\":\"dev\""), "{json}");
    assert!(stderr(&out).contains("не от Nix"), "{}", stderr(&out));

    // Not in the way: the local setting is written, as with nothing declared.
    let out = home.run(&["hermetic", "--default", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(home.root.join("config/hermetic-default")).unwrap(),
        "on"
    );

    // The same text as Nix's link is Nix's word.
    declare(&declared.join("hermetic-default"), "off");
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":false,\"source\":\"nix\"},\"ask_again\":"),
        "{json}"
    );
}

#[test]
fn what_nix_declares_is_shown_as_such_and_not_changed_here() {
    let home = Home::new("declared");
    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    declare(
        &declared.join("private-dev.conf"),
        "network = offline\napp = firefox\n",
    );
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();

    let out = home.run(&["container", "set", "sb:dev", "network", "direct"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("задана в Nix"), "{}", stderr(&out));
    let out = home.run(&["container", "assign", "firefox", "work"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в Nix"), "{}", stderr(&out));

    let out = home.run(&["status", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(json.starts_with("{\"schema_version\":1,"), "{json}");
    // One name per container: the old `sb:` of a sandbox is not written.
    assert!(json.contains("\"selector\":\"dev\""), "{json}");
    assert!(
        json.contains("\"network\":{\"value\":\"offline\",\"source\":\"nix\"}"),
        "{json}"
    );
    // Declared and not yet on disk: the home itself comes from Nix.
    assert!(
        json.contains("\"home\":{\"value\":\"private\",\"source\":\"nix\"}"),
        "{json}"
    );
    assert!(json.contains("\"id\":\"firefox\""), "{json}");
    assert!(json.contains("\"uplink_owner\":"), "{json}");
    assert!(
        json.contains("\"autostart_unassigned\":{\"value\":\"ask\",\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"wayland_proxy\":{\"value\":true,\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"container\":{\"value\":\"dev\",\"source\":\"nix\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"name\":\"unconfined\",\"kind\":\"unconfined\",\"aliases\":[\"direct\"]"),
        "{json}"
    );
    // A local assignment of another program is local.
    let out = home.run(&["container", "assign", "tg", "work"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"container\":{\"value\":\"work\",\"source\":\"local\"}"),
        "{json}"
    );
}

#[test]
fn a_private_home_is_granted_directories_but_never_the_state() {
    // docs/CONTAINERS.md §3.5: a Wine prefix or a Steam library, not the keys.
    let home = Home::new("grant");
    home.zone_is_up("nl");
    fs::create_dir_all(home.root.join("sandboxes/dev/home")).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let r = home.root.display().to_string();

    let out = home.run(&["container", "grant", "sb:dev", "~/.wine"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("увидят программы вне контейнера"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(
        json.contains(&format!(
            "\"paths\":[{{\"value\":\"{r}/.wine\",\"source\":\"local\",\"expires\":null}}]"
        )),
        "{json}"
    );

    for refused in [
        "~/.local/state/vpn-zones",
        "~/.local/state/vpn-zones/nl",
        "~/state/nl",
        "~/sandboxes/dev/home",
        "~/.local/state",
        "~",
        "~/.wine/../.config/vpn-zones",
        "/run/user/1000",
        "/tmp/.X11-unix",
        "/etc",
        "relative/path",
    ] {
        let out = home.run(&["container", "grant", "sb:dev", refused]);
        assert_eq!(out.status.code(), Some(1), "{refused}: {}", stdout(&out));
        assert!(
            stderr(&out).contains("выдать нельзя"),
            "{refused}: {}",
            stderr(&out)
        );
    }
    // A layer over the home: a grant is a path of the home it writes
    // through, into the real one; outside the home there is no layer.
    let out = home.run(&["container", "grant", "work", "~/.wine"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["container", "grant", "work", "/mnt/games"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("слой над домом"), "{}", stderr(&out));

    // The launch hands the grant to fs-sandbox, which checks it once more.
    let out = home.run_with(
        &["run", "nl", "--sandbox", "dev", "--", "wine"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "wine")],
    );
    assert!(
        stdout(&out).contains(&format!("--name dev --bind-path {r}/.wine --")),
        "{}",
        stdout(&out)
    );

    let out = home.run(&["container", "revoke", "sb:dev", "~/.wine"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(json.contains("\"paths\":[]"), "{json}");

    // With a term: written next to the path, shown, and on the record.
    let out = home.run(&["container", "grant", "sb:dev", "~/.wine", "--for", "2h"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(" до 20"), "{}", stdout(&out));
    let line = fs::read_to_string(home.root.join("config/containers/dev/paths")).unwrap();
    assert!(
        line.starts_with("until=") && line.trim_end().ends_with(&format!(" {r}/.wine")),
        "{line}"
    );
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(
        json.contains("\"source\":\"local\",\"expires\":\"20"),
        "{json}"
    );
    for bad in [&["--for", "2w"][..], &["--for"][..], &["--later", "2h"][..]] {
        let mut argv = vec!["container", "grant", "sb:dev", "~/.wine"];
        argv.extend(bad);
        assert_eq!(home.run(&argv).status.code(), Some(1), "{bad:?}");
    }
    // A term that is over is not granted to anything, before any cleanup.
    fs::write(
        home.root.join("config/containers/dev/paths"),
        format!("until=1 {r}/.wine\n{r}/games\n"),
    )
    .unwrap();
    let json = stdout(&home.run(&["container", "show", "sb:dev", "--json"]));
    assert!(!json.contains(".wine"), "{json}");
    let out = home.run_with(
        &["run", "nl", "--sandbox", "dev", "--", "wine"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "wine")],
    );
    assert!(!stdout(&out).contains(".wine"), "{}", stdout(&out));
    // `expire` takes it out of the file and says so.
    let out = home.run(&["container", "expire"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("истёк"), "{}", stdout(&out));
    assert_eq!(
        fs::read_to_string(home.root.join("config/containers/dev/paths")).unwrap(),
        format!("{r}/games\n")
    );
    let journal = stdout(&home.run(&["journal", "--json"]));
    for event in [
        "\"event\":\"grant\"",
        "\"event\":\"revoke\"",
        "\"event\":\"grant-expired\"",
    ] {
        assert!(journal.contains(event), "{event}: {journal}");
    }
}

#[test]
fn a_merge_keeps_what_the_target_has_and_moves_the_programs() {
    // docs/CONTAINERS.md §3.4.
    let home = Home::new("merge");
    let old = home.root.join("profiles/old");
    let work = home.root.join("profiles/work");
    fs::create_dir_all(old.join("config/upper/app")).unwrap();
    fs::create_dir_all(work.join("config/upper")).unwrap();
    fs::write(old.join("config/upper/app/settings"), "old").unwrap();
    fs::write(old.join("config/upper/shared"), "old").unwrap();
    fs::write(work.join("config/upper/shared"), "work").unwrap();
    // A slot only the source has is created in the target.
    fs::create_dir_all(old.join("local-share/upper")).unwrap();
    fs::write(old.join("local-share/upper/history"), "old").unwrap();
    // A name a program of the target planted: never written through.
    std::os::unix::fs::symlink(
        "/nonexistent-elsewhere",
        work.join("config/upper/.merged-from-old"),
    )
    .unwrap();
    let pins = home.state().join(".pinnedprofile");
    fs::create_dir_all(&pins).unwrap();
    fs::write(pins.join("firefox"), "old").unwrap();
    fs::write(pins.join("tg"), "sb:other").unwrap();
    let sha = "a".repeat(64);
    fs::create_dir_all(old.join("trust")).unwrap();
    fs::write(
        old.join("trust").join(format!("{sha}.pem")),
        "-----BEGIN CERTIFICATE-----\n",
    )
    .unwrap();
    fs::create_dir_all(home.root.join("sandboxes/dev/home")).unwrap();

    let out = home.run(&["container", "merge", "old", "sb:dev"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("разные виды дома"),
        "{}",
        stderr(&out)
    );

    // A certificate the target does not trust yet needs a word of consent.
    let out = home.run(&["container", "merge", "old", "work"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert!(
        !work.join("config/upper/app").exists(),
        "refused means untouched"
    );

    // Not while programs of either run.
    let reg = home.state().join(".running/work/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(&reg, format!("{} direct work\n", std::process::id())).unwrap();
    let out = home.run(&["container", "merge", "old", "work", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("работают"), "{}", stderr(&out));
    fs::remove_file(&reg).unwrap();

    let out = home.run(&["container", "merge", "old", "work", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("теперь доверяет"), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(work.join("config/upper/app/settings")).unwrap(),
        "old"
    );
    assert_eq!(
        fs::read_to_string(work.join("config/upper/shared")).unwrap(),
        "work"
    );
    assert_eq!(
        fs::read_to_string(work.join("config/upper/.merged-from-old-2/shared")).unwrap(),
        "old"
    );
    assert!(
        fs::symlink_metadata(work.join("config/upper/.merged-from-old"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(work.join("local-share/upper/history")).unwrap(),
        "old"
    );
    // With the container's policy, not next to its data (the certificate was
    // put there in the old layout, and moved with the first look).
    assert!(home
        .root
        .join("config/containers/work/trust")
        .join(format!("{sha}.pem"))
        .is_file());
    assert_eq!(fs::read_to_string(pins.join("firefox")).unwrap(), "work");
    assert_eq!(fs::read_to_string(pins.join("tg")).unwrap(), "sb:other");
    // The source stays until it is removed by hand.
    assert!(old.join("config/upper/app/settings").is_file());
    assert!(
        stdout(&out).contains("cellward container rm old"),
        "{}",
        stdout(&out)
    );

    // What Nix declares is merged in the configuration.
    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("overlay-work.conf"), "network = direct\n");
    let out = home.run(&["container", "merge", "old", "work", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("объявлен в Nix"), "{}", stderr(&out));
}

#[test]
fn launch_starts_an_entry_by_id_through_the_picker() {
    // docs/CONTAINERS.md §5.1: a key binding gets what a click gets.
    let home = Home::new("launch");
    let apps = home.root.join(".local/share/applications");
    fs::create_dir_all(&apps).unwrap();
    fs::write(
        apps.join("vpnztest-fox.desktop"),
        "[Desktop Entry]\nType=Application\nName=Test Fox\nExec=fox --new-window %U\n",
    )
    .unwrap();
    let r = home.root.display().to_string();
    let dry = [("VPN_ZONE_DRYRUN", "1")];

    let out = home.run_with(&["launch", "vpnztest-fox", "--", "https://a", "b c"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).trim_end(),
        format!(
            "{r}/bin/vpn-zone-pick --id vpnztest-fox --label Test Fox -- fox --new-window https://a b c"
        )
    );

    // Taken over in place: the original from the backup, never our rewrite.
    fs::write(
        apps.join("vpnztest-fox.desktop"),
        "[Desktop Entry]\nName=Test Fox\nExec=/x/vpn-zone-pick --id vpnztest-fox -- fox\nX-VPNZone=adopted\n",
    )
    .unwrap();
    let backups = home.state().join(".adopted");
    fs::create_dir_all(&backups).unwrap();
    fs::write(
        backups.join("vpnztest-fox.desktop"),
        "[Desktop Entry]\nName=Test Fox\nExec=fox --from-backup\n",
    )
    .unwrap();
    let out = home.run_with(&["launch", "vpnztest-fox"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).ends_with("-- fox --from-backup\n"),
        "{}",
        stdout(&out)
    );

    // Arguments an entry does not take are not passed.
    let out = home.run_with(&["launch", "vpnztest-fox", "--", "x"], &dry);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("не принимает аргументов"),
        "{}",
        stderr(&out)
    );
    assert!(
        stdout(&out).ends_with("-- fox --from-backup\n"),
        "{}",
        stdout(&out)
    );

    for (args, message) in [
        (&["launch", "vpnztest-nope"][..], "нет ни в одном"),
        (&["launch", "vpn-zone-add"][..], "служебный"),
        (&["launch", "vpnztest-fox", "x"][..], "после --"),
        (&["launch"][..], "нужен id"),
    ] {
        let out = home.run_with(args, &dry);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr(&out).contains(message), "{args:?}: {}", stderr(&out));
    }
}

#[test]
fn doctor_reports_as_json_and_fails_on_what_it_cannot_prove() {
    // Every tool in this manifest is missing, and the zone "nl" is up but
    // cannot be entered: both are failures, never silence.
    let home = Home::new("doctor");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.state().join("de")).unwrap();
    fs::write(home.state().join("de/config.conf"), crlf_config()).unwrap();
    let out = home.run(&["doctor", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let json = stdout(&out);
    assert!(
        json.starts_with("{\"schema_version\":1,\"worst\":\"fail\","),
        "{json}"
    );
    assert!(
        json.contains("{\"id\":\"tool-nsenter\",\"level\":\"fail\""),
        "{json}"
    );
    // A zone that is down is skipped, not failed.
    assert!(
        json.contains(
            "{\"name\":\"de\",\"up\":false,\"checks\":[{\"id\":\"up\",\"level\":\"skip\""
        ),
        "{json}"
    );
    assert!(json.contains("\"name\":\"nl\",\"up\":true"), "{json}");
    assert!(
        json.contains("{\"id\":\"probe\",\"level\":\"fail\""),
        "{json}"
    );

    let out = home.run(&["doctor", "nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("такой зоны нет"), "{}", stdout(&out));
}

#[test]
fn a_host_interface_zone_is_added_and_reported_as_such() {
    let home = Home::new("hostif");
    let conf = home.root.join("lan.conf");
    fs::write(
        &conf,
        "[HostInterface]\nInterface = vpnztest0\nDNS = 192.0.2.53\n",
    )
    .unwrap();
    let out = home.run(&["add", "lan", conf.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("не шифрует"), "{}", stdout(&out));
    // The interface is not there right now: said, not refused.
    assert!(stderr(&out).contains("сейчас нет"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("{\"name\":\"lan\",\"kind\":\"host-interface\""),
        "{json}"
    );
    assert!(
        json.contains("\"interface\":\"vpnztest0\",\"x11\":{"),
        "{json}"
    );
    assert!(
        json.contains("\"name\":\"unconfined\",\"kind\":\"unconfined\"")
            && json.contains("\"interface\":null"),
        "{json}"
    );

    for bad in [
        "[HostInterface]\nInterface = lo\n",
        "[HostInterface]\nDNS = 192.0.2.53\n",
        "[HostInterface]\nInterface = eth0\nDNS = resolver.example\n",
    ] {
        fs::write(&conf, bad).unwrap();
        let out = home.run(&["add", "bad", conf.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{bad}");
        assert!(
            stderr(&out).contains("[HostInterface]"),
            "{bad}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn watch_announces_a_dead_tunnel_once_and_its_recovery() {
    let home = Home::new("watch");
    home.zone_is_up("nl");
    let zone = home.state().join("nl");
    fs::write(zone.join("config.conf"), crlf_config()).unwrap();
    let mirror = |rx: &str, tx: &str| {
        fs::write(
            zone.join("status"),
            format!(
                "interface: awg0\n\npeer: x\n  latest handshake: 10 minutes, 2 seconds ago\n  \
                 transfer: {rx} received, {tx} sent\n"
            ),
        )
        .unwrap()
    };
    let look = || {
        let out = home.run(&["watch", "--json"]);
        assert!(out.status.success(), "{}", stderr(&out));
        stdout(&out)
    };
    mirror("1.00 KiB", "1.00 KiB");
    let out = look();
    assert!(out.starts_with("{\"schema_version\":1,"), "{out}");
    assert!(out.contains("\"verdict\":\"unknown\""), "{out}");
    assert!(out.contains("\"handshake_age_s\":602"), "{out}");
    // Sending into silence: suspect at the first look, dead at the second.
    mirror("1.00 KiB", "2.00 KiB");
    assert!(look().contains("\"verdict\":\"suspect\",\"handshake_age_s\":602,\"rx_bytes\":1024,\"tx_bytes\":2048,\"notified\":false"));
    mirror("1.00 KiB", "3.00 KiB");
    let out = look();
    assert!(out.contains("\"verdict\":\"dead\""), "{out}");
    assert!(out.contains("\"notified\":true"), "{out}");
    // Still dead: not announced again.
    mirror("1.00 KiB", "4.00 KiB");
    assert!(look().contains("\"notified\":false"));
    // Answers again: alive, and that is announced.
    mirror("5.00 KiB", "5.00 KiB");
    let out = look();
    assert!(out.contains("\"verdict\":\"alive\""), "{out}");
    assert!(out.contains("\"notified\":true"), "{out}");

    // The status bar line marks nothing dead now.
    let bar = stdout(&home.run(&["status", "--bar"]));
    assert_eq!(
        bar.trim(),
        "{\"text\":\"nl\",\"tooltip\":\"cellward: поднятые зоны\",\"class\":\"up\",\"unconfined\":0}"
    );

    // A program running unconfined is marked, dead records are not.
    let reg = home.state().join(".running/__main__/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    fs::write(
        &reg,
        format!(
            "{} direct __main__\n999999999 unconfined __main__\n",
            std::process::id()
        ),
    )
    .unwrap();
    let bar = stdout(&home.run(&["status", "--bar"]));
    assert_eq!(
        bar.trim(),
        "{\"text\":\"nl ⚠1\",\"tooltip\":\"cellward: поднятые зоны\\nБез изоляции (⚠) сейчас: firefox\",\"class\":\"up\",\"unconfined\":1}"
    );
    fs::remove_file(&reg).unwrap();

    // status --json carries the counters too.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"handshake_age_s\":602,\"rx_bytes\":5120,\"tx_bytes\":5120"),
        "{json}"
    );
}

#[test]
fn a_containers_focus_policy_goes_to_the_proxy_with_its_source() {
    // rust/src/wl_focus.rs: `input` by default and not said to wl-sandbox
    // (its own default); another word goes to it with the launch; Nix over
    // the local word, and the CLI does not change what Nix set.
    let home = Home::new("focus");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];

    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"focus\":{\"value\":\"input\",\"source\":\"default\"}"),
        "{json}"
    );
    let line = stdout(&home.run_with(&["run", "nl", "--profile", "work", "--", "tg"], &dry));
    // By its instance's key: the container's own (stage 5: nothing by the
    // zone's name).
    let key = vpn_zone::instance::key("work");
    assert!(
        line.contains(&format!("wl-sandbox tg --zone {key} ")),
        "{line}"
    );
    assert!(!line.contains("--focus"), "{line}");

    let out = home.run(&["container", "set", "work", "focus", "notify"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("после этого"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"focus\":{\"value\":\"notify\",\"source\":\"local\"}"),
        "{json}"
    );
    let line = stdout(&home.run_with(&["run", "nl", "--profile", "work", "--", "tg"], &dry));
    assert!(line.contains(" --focus notify -- "), "{line}");
    // The main home has no container: `input`.
    let line = stdout(&home.run_with(&["run", "nl", "--", "tg"], &dry));
    assert!(!line.contains("--focus"), "{line}");

    let out = home.run(&["container", "set", "work", "focus", "sometimes"]);
    assert_eq!(out.status.code(), Some(1));
    let out = home.run(&["container", "set", "work", "focus", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"focus\":{\"value\":\"input\",\"source\":\"default\"}"),
        "{json}"
    );

    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("chat.conf"), "home = main\nfocus = allow\n");
    let out = home.run(&["container", "set", "chat", "focus", "ask"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "chat", "--json"]));
    assert!(
        json.contains("\"focus\":{\"value\":\"allow\",\"source\":\"nix\"}"),
        "{json}"
    );
    let line = stdout(&home.run_with(&["run", "nl", "--container", "chat", "--", "tg"], &dry));
    assert!(line.contains(" --focus allow -- "), "{line}");
}

/// Stage 5 of the container design (2026-09-28): a container's own
/// zone-level permissions — hermetic, the Nix daemon, the host's files, the
/// audio manager — set locally, shown with where they are from (`null`: its
/// network's), taken back with `default`; a word that is none refused, and
/// what Nix set changed there.
#[test]
fn a_container_has_its_own_zone_level_permissions() {
    let home = Home::new("permissions");
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let show = |name: &str| stdout(&home.run(&["container", "show", name, "--json"]));
    let json = show("work");
    for key in [
        "hermetic",
        "nix_daemon",
        "host_files_writable",
        "audio_manager",
    ] {
        assert!(
            json.contains(&format!(
                "\"{key}\":{{\"value\":null,\"source\":\"default\"}}"
            )),
            "{key}: {json}"
        );
    }
    let out = home.run(&["container", "set", "work", "hermetic", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("следующего подъёма"),
        "{}",
        stdout(&out)
    );
    let out = home.run(&["container", "set", "work", "host-files", "writable"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = show("work");
    assert!(
        json.contains("\"hermetic\":{\"value\":false,\"source\":\"local\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"host_files_writable\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );
    for bad in [&["host-files", "on"][..], &["nix-daemon", "maybe"]] {
        let mut argv = vec!["container", "set", "work"];
        argv.extend(bad);
        assert_eq!(home.run(&argv).status.code(), Some(1), "{bad:?}");
    }
    let out = home.run(&["container", "set", "work", "hermetic", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        show("work").contains("\"hermetic\":{\"value\":null,\"source\":\"default\"}"),
        "{}",
        show("work")
    );
    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    declare(
        &declared.join("chat.conf"),
        "home = main\naudio_manager = true\n",
    );
    let out = home.run(&["container", "set", "chat", "audio-manager", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    assert!(
        show("chat").contains("\"audio_manager\":{\"value\":true,\"source\":\"nix\"}"),
        "{}",
        show("chat")
    );
}

/// Step 1 of the permission model (2026-09-28): a way around a network is
/// open where the container asks and the network tolerates it, and
/// `explain` says whose word decided each setting; `offline` tolerates
/// none, and is refused them; `status` says what a network tolerates.
#[test]
fn explain_says_who_asked_and_what_the_network_tolerates() {
    let home = Home::new("explain");
    fs::create_dir_all(home.state().join("nl")).unwrap();
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.state().join("offline")).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let ok = |argv: &[&str]| {
        let out = home.run(argv);
        assert!(out.status.success(), "{argv:?}: {}", stderr(&out));
        stdout(&out)
    };
    let setting = |argv: &[&str], key: &str| {
        let json = ok(argv);
        let at = json
            .find(&format!("{{\"key\":\"{key}\""))
            .unwrap_or_else(|| panic!("{key}: {json}"));
        // Up to the end of its `tolerated`.
        let rest = &json[at..];
        let end = rest.find("\"moot\"").unwrap();
        rest[..end].to_owned()
    };
    // Bound to no network and running nowhere: the network is to be named.
    let out = home.run(&["explain", "work"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("назови её"), "{}", stderr(&out));
    ok(&["container", "set", "work", "network", "nl"]);
    // Asked, not tolerated: closed, and said so when it is asked for.
    let said = ok(&["container", "set", "work", "nix-daemon", "on"]);
    assert!(
        said.contains("ВНИМАНИЕ: сеть nl этого не допускает"),
        "{said}"
    );
    assert!(said.contains("cellward nix-daemon nl on"), "{said}");
    assert_eq!(
        setting(&["explain", "work", "--json"], "nix_daemon"),
        "{\"key\":\"nix_daemon\",\"value\":false,\"source\":\"default\",\
         \"asked\":{\"value\":true,\"source\":\"local\",\"by\":\"container\"},\
         \"tolerated\":{\"value\":false,\"source\":\"default\",\"refused_by\":\"network\"},"
    );
    let text = ok(&["explain", "work"]);
    assert!(text.contains("Контейнер «work»"), "{text}");
    assert!(text.contains("в сети nl"), "{text}");
    assert!(
        text.contains("контейнер просит (местно), но сеть не допускает (по умолчанию)"),
        "{text}"
    );
    // Tolerated: open.
    ok(&["nix-daemon", "nl", "on"]);
    assert_eq!(
        setting(&["explain", "work", "--json"], "nix_daemon"),
        "{\"key\":\"nix_daemon\",\"value\":true,\"source\":\"local\",\
         \"asked\":{\"value\":true,\"source\":\"local\",\"by\":\"container\"},\
         \"tolerated\":{\"value\":true,\"source\":\"local\",\"refused_by\":null},"
    );
    let said = ok(&["container", "set", "work", "nix-daemon", "on"]);
    assert!(!said.contains("ВНИМАНИЕ"), "{said}");
    // The main home asks for what the template asks for (2c of §11.15):
    // nothing by default — the network's word is only what it tolerates.
    assert_eq!(
        setting(&["explain", "main", "nl", "--json"], "nix_daemon"),
        "{\"key\":\"nix_daemon\",\"value\":false,\"source\":\"default\",\
         \"asked\":{\"value\":false,\"source\":\"default\",\"by\":\"template\"},\
         \"tolerated\":{\"value\":true,\"source\":\"local\",\"refused_by\":null},"
    );
    ok(&["defaults", "set", "nix-daemon", "on"]);
    assert_eq!(
        setting(&["explain", "main", "nl", "--json"], "nix_daemon"),
        "{\"key\":\"nix_daemon\",\"value\":true,\"source\":\"local\",\
         \"asked\":{\"value\":true,\"source\":\"local\",\"by\":\"template\"},\
         \"tolerated\":{\"value\":true,\"source\":\"local\",\"refused_by\":null},"
    );
    ok(&["defaults", "set", "nix-daemon", "default"]);
    assert!(ok(&["explain", "main", "nl"]).contains("Настоящий дом"));
    // Offline tolerates none, and is refused them.
    let json = setting(&["explain", "work", "offline", "--json"], "nix_daemon");
    assert!(json.contains("\"value\":false"), "{json}");
    assert!(json.contains("\"refused_by\":\"offline\""), "{json}");
    for argv in [
        &["nix-daemon", "offline", "on"][..],
        &["host-files", "offline", "writable"],
        &["hermetic", "offline", "off"],
    ] {
        let out = home.run(argv);
        assert_eq!(out.status.code(), Some(1), "{argv:?}");
        assert!(
            stderr(&out).contains("offline не допускает обходов сети"),
            "{argv:?}: {}",
            stderr(&out)
        );
    }
    // Closing words are taken there as anywhere.
    ok(&["nix-daemon", "offline", "off"]);
    ok(&["hermetic", "offline", "on"]);
    // What each network tolerates.
    let status = ok(&["status", "--json"]);
    assert!(
        status.contains(
            "\"tolerates\":{\"hermetic\":{\"value\":false,\"source\":\"default\"},\
             \"nix_daemon\":{\"value\":true,\"source\":\"local\"},\
             \"host_files_writable\":{\"value\":false,\"source\":\"default\"}}"
        ),
        "{status}"
    );
    // A program by its container; one of none, as a throwaway's.
    ok(&["container", "assign", "org.example.Editor", "work"]);
    assert!(ok(&["explain", "org.example.Editor"]).contains("Контейнер «work»"));
    let text = ok(&["explain", "org.example.Unknown"]);
    assert!(text.contains("ни в одном контейнере"), "{text}");
    assert!(text.contains("offline"), "{text}");
    // Unconfined: nothing of the container's there.
    assert!(ok(&["explain", "work", "unconfined"]).contains("unconfined"));
    assert_eq!(
        home.run(&["explain", "work", "nowhere"]).status.code(),
        Some(1)
    );
}

/// Stage 1 of the network monitor (2026-09-28): what a running instance
/// sent and received, as its relay counted it, in `traffic` and in
/// `status`; an instance without counters is said to have none.
#[test]
fn traffic_says_what_an_instance_sent_and_received() {
    use std::os::fd::AsFd;
    use vpn_zone::{instance, traffic};
    // A short tag: the zone's bridge socket is made below it (SUN_LEN).
    let home = Home::new("trf");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let out = home.run(&["traffic"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("ни один экземпляр"),
        "{}",
        stdout(&out)
    );
    let _bridge = home.instance_is_up("work", "nl");
    let json = stdout(&home.run(&["traffic", "--json"]));
    assert!(
        json.contains("\"id\":\"work\"") && json.contains("\"traffic\":null"),
        "{json}"
    );
    let file = traffic::create(&instance::dir(&home.state(), "work")).unwrap();
    let tally = traffic::Tally::map(file.as_fd(), true).unwrap();
    tally.outbound(1500);
    tally.inbound(3000);
    let json = stdout(&home.run(&["traffic", "--json"]));
    assert!(
        json.contains(
            "\"traffic\":{\"out_bytes\":1500,\"out_frames\":1,\"in_bytes\":3000,\"in_frames\":1,"
        ),
        "{json}"
    );
    let text = stdout(&home.run(&["traffic"]));
    assert!(text.contains("work · nl: ↑ 1.5 КБ · ↓ 2.9 КБ"), "{text}");
    let status = stdout(&home.run(&["status", "--json"]));
    assert!(
        status.contains("\"traffic\":{\"out_bytes\":1500,"),
        "{status}"
    );
    assert_eq!(home.run(&["traffic", "--bogus"]).status.code(), Some(1));
    // Recorded into today's summary, twice: the second adds only what came
    // since; `--days` says it.
    assert!(home.run(&["traffic", "--record"]).status.success());
    tally.outbound(500);
    assert!(home.run(&["traffic", "--record"]).status.success());
    let json = stdout(&home.run(&["traffic", "--days", "1", "--json"]));
    assert!(
        json.contains(
            "{\"container\":\"work\",\"network\":\"nl\",\"out_bytes\":2000,\"in_bytes\":3000}"
        ),
        "{json}"
    );
    let text = stdout(&home.run(&["traffic", "--days", "7"]));
    assert!(text.contains("work · nl: ↑ 2.0 КБ · ↓ 2.9 КБ"), "{text}");
    assert_eq!(home.run(&["traffic", "--days", "0"]).status.code(), Some(1));
    tally.close();
}

/// The main home's own record (`docs/PERMISSIONS.md` §11.15, 2a): its
/// permissions set and shown as a container's, in status as `main`; no
/// network, no kind of home, not removed, not merged.
#[test]
fn the_main_home_has_a_record_of_its_own() {
    let home = Home::new("mainrec");
    let status = stdout(&home.run(&["status", "--json"]));
    assert!(status.contains("\"main\":{\"name\":\"main\""), "{status}");
    let out = home.run(&["container", "set", "main", "microphone", "no"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let conf = fs::read_to_string(home.root.join("config/containers/main/container.conf")).unwrap();
    assert!(conf.contains("microphone = no"), "{conf}");
    let out = home.run(&["container", "devices", "main", "add", "serial"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = stdout(&home.run(&["container", "show", "main", "--json"]));
    assert!(shown.contains("serial"), "{shown}");
    for bad in [
        &["container", "set", "main", "network", "offline"][..],
        &["container", "set", "main", "home", "private"][..],
        &["container", "rm", "main"][..],
        &["container", "merge", "main", "work"][..],
    ] {
        assert_eq!(home.run(bad).status.code(), Some(1), "{bad:?}");
    }
    // Not a container of the list.
    let list = stdout(&home.run(&["container", "list", "--json"]));
    assert!(!list.contains("\"name\":\"main\""), "{list}");
}

/// What no container of the real home writes (`cellward protect`,
/// 2026-09-29): added, shown, in status; refused outside the home; Nix's not
/// taken off here; given to write to a container of the real home — what is
/// listed only, and for good.
#[test]
fn protect_lists_what_no_container_writes() {
    let home = Home::new("prot");
    let root = home.root.display().to_string();
    assert!(home.run(&["protect", "add", "~/repo"]).status.success());
    let shown = stdout(&home.run(&["protect"]));
    assert!(shown.contains(&format!("{root}/repo\n")), "{shown}");
    let status = stdout(&home.run(&["status", "--json"]));
    assert!(
        status.contains(&format!(
            "\"protected\":[{{\"value\":\"{root}/repo\",\"source\":\"local\"}}]"
        )),
        "{status}"
    );
    for bad in ["/etc/nixos", "~", "~/../x"] {
        assert_eq!(
            home.run(&["protect", "add", bad]).status.code(),
            Some(1),
            "{bad}"
        );
    }
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("protect"), "~/nixrepo\n");
    let shown = stdout(&home.run(&["protect"]));
    assert!(shown.contains(&format!("{root}/nixrepo (Nix)")), "{shown}");
    assert_eq!(
        home.run(&["protect", "rm", "~/nixrepo"]).status.code(),
        Some(1)
    );
    // Given to a container of the real home: what is listed, for good.
    let out = home.run(&["container", "create", "real", "--home", "main"]);
    assert!(out.status.success(), "{}", stderr(&out));
    fs::create_dir_all(home.root.join("repo")).unwrap();
    let out = home.run(&["container", "grant", "real", "~/repo"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("с его следующего подъёма"),
        "{}",
        stdout(&out)
    );
    for bad in [&["~/Documents"][..], &["~/repo", "--for", "2h"][..]] {
        let mut args = vec!["container", "grant", "real"];
        args.extend_from_slice(bad);
        assert_eq!(home.run(&args).status.code(), Some(1), "{bad:?}");
    }
    let out = home.run(&["container", "revoke", "real", "~/repo"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.run(&["protect", "rm", "~/repo"]).status.success());
    assert!(!stdout(&home.run(&["protect"])).contains(&format!("{root}/repo\n")));
}

/// The connections' journal's keep and cap (`cellward netlog`): set, shown,
/// refused outside their bounds, back to the default; `traffic --programs`
/// with nothing recorded.
#[test]
fn netlog_keeps_what_the_person_chose() {
    let home = Home::new("nlog");
    let shown = stdout(&home.run(&["netlog"]));
    assert!(
        shown.contains("30 дн. (умолчание)") && shown.contains("1.0 ГБ (умолчание)"),
        "{shown}"
    );
    assert!(home.run(&["netlog", "keep", "90"]).status.success());
    assert!(home.run(&["netlog", "cap", "512M"]).status.success());
    let shown = stdout(&home.run(&["netlog"]));
    assert!(
        shown.contains("хранится 90 дн.\n") && shown.contains("не больше 512.0 МБ —"),
        "{shown}"
    );
    for bad in [
        &["keep", "0"][..],
        &["keep", "x"],
        &["cap", "10K"],
        &["cap", "1X"],
    ] {
        let mut args = vec!["netlog"];
        args.extend_from_slice(bad);
        assert_eq!(home.run(&args).status.code(), Some(1), "{bad:?}");
    }
    assert!(home.run(&["netlog", "keep", "default"]).status.success());
    assert!(stdout(&home.run(&["netlog"])).contains("30 дн. (умолчание)"));
    let json = stdout(&home.run(&["traffic", "--programs", "--json"]));
    assert!(
        json.contains("\"days\":1,") && json.contains("\"programs\":[]"),
        "{json}"
    );
    let text = stdout(&home.run(&["traffic", "--programs", "--days", "7"]));
    assert!(text.contains("ничего не записано"), "{text}");
    assert_eq!(
        home.run(&["traffic", "--programs", "--watch"])
            .status
            .code(),
        Some(1)
    );
}

/// Stage 2 of the network monitor: `traffic --connections` says whom an
/// instance reached, as its relay noted it (`vpn_zone::flows`), with the
/// name a DNS answer gave for the address.
#[test]
fn traffic_connections_says_whom_an_instance_reached() {
    use std::os::fd::AsFd;
    use vpn_zone::{flows, instance};
    let home = Home::new("tcon");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let json = stdout(&home.run(&["traffic", "--connections", "--json"]));
    assert!(json.contains("\"instances\":[]"), "{json}");
    let _bridge = home.instance_is_up("work", "nl");
    let json = stdout(&home.run(&["traffic", "--connections", "--json"]));
    assert!(json.contains("\"connections\":null"), "{json}");
    let file = flows::create(&instance::dir(&home.state(), "work")).unwrap();
    let mut table = flows::Table::map(file.as_fd(), true).unwrap();
    let key = flows::Key {
        proto: flows::TCP,
        lport: 40000,
        remote: "192.0.2.10".parse().unwrap(),
        rport: 443,
    };
    for (outbound, len) in [(true, 1500), (false, 3000)] {
        let seen = flows::Seen {
            key,
            outbound,
            len,
            dns: None,
        };
        table.note(&seen, flows::now());
    }
    // An answer of the forwarder's: 192.0.2.10 is example.org.
    let mut answer = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    answer.extend_from_slice(b"\x07example\x03org\x00\x00\x01\x00\x01");
    answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10]);
    let dns = flows::Seen {
        key: flows::Key {
            proto: flows::UDP,
            lport: 5353,
            remote: "10.254.255.253".parse().unwrap(),
            rport: 53,
        },
        outbound: false,
        len: 90,
        dns: Some(&answer),
    };
    table.note(&dns, flows::now());
    let json = stdout(&home.run(&["traffic", "--connections", "--json"]));
    assert!(
        json.contains(
            "{\"proto\":\"tcp\",\"local_port\":40000,\"remote\":\"192.0.2.10\",\
             \"remote_port\":443,\"name\":\"example.org\","
        ),
        "{json}"
    );
    assert!(
        json.contains("\"out_bytes\":1500,\"in_bytes\":3000,\"out_packets\":1,\"in_packets\":1"),
        "{json}"
    );
    let text = stdout(&home.run(&["traffic", "--connections"]));
    assert!(text.contains("work · nl:"), "{text}");
    assert!(
        text.contains("tcp 192.0.2.10:443 (example.org) · ↑ 1.5 КБ · ↓ 2.9 КБ"),
        "{text}"
    );
    assert!(
        text.contains("udp 10.254.255.253:53 (DNS контейнера)"),
        "{text}"
    );
    // Not with the others' flags.
    for other in [&["--watch"][..], &["--days", "1"][..]] {
        let mut args = vec!["traffic", "--connections"];
        args.extend_from_slice(other);
        assert_eq!(home.run(&args).status.code(), Some(1), "{other:?}");
    }
    table.close();
}

/// Review 2026-09-28: a network's `restart_needed` is its running
/// instances' — what changed since they came up —, not its own space's,
/// where nothing runs since stage 5.
#[test]
fn a_networks_restart_needed_is_its_instances() {
    use vpn_zone::instance;
    // A short tag: the zone's bridge socket is made below it (SUN_LEN; red
    // once in CI, 2026-09-28).
    let home = Home::new("rneed");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let networks_say = |what: &str| {
        let json = stdout(&home.run(&["status", "--json"]));
        assert!(
            json.contains(&format!("\"restart_needed\":{what},\"attached\"")),
            "{what}: {json}"
        );
    };
    // Nothing runs in it: nothing to restart, whatever its own space says.
    networks_say("[]");
    let _bridge = home.instance_is_up("work", "nl");
    fs::write(
        instance::dir(&home.state(), "work").join(instance::SETTINGS),
        "hermetic=true\nnix_daemon=false\nhost_files_writable=false\naudio_manager=false\n",
    )
    .unwrap();
    networks_say("[]");
    // Its own asking for the Nix daemon, in a network that does not
    // tolerate it (step 1 of the permission model, 2026-09-28): nothing
    // would come up otherwise — said at once.
    let out = home.run(&["container", "set", "work", "nix-daemon", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("сеть nl этого не допускает"),
        "{}",
        stdout(&out)
    );
    networks_say("[]");
    // Tolerated: it would.
    let out = home.run(&["nix-daemon", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[\"nix_daemon\"]");
    // Its own "off" holds whatever the network tolerates.
    let out = home.run(&["container", "set", "work", "nix-daemon", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[]");
    // A container without a word of its own asks what the template says
    // (2c, 2026-09-29): the network's lists only tolerate.
    let out = home.run(&["container", "set", "work", "nix-daemon", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[]");
    let out = home.run(&["defaults", "set", "nix-daemon", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[\"nix_daemon\"]");
    let out = home.run(&["nix-daemon", "nl", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[]");
    let out = home.run(&["defaults", "set", "host-files", "writable"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[]");
    let out = home.run(&["host-files", "nl", "writable"]);
    assert!(out.status.success(), "{}", stderr(&out));
    networks_say("[\"host_files_writable\"]");
}

/// Review 2026-09-28: a locked zone takes a hermetic container only. A
/// launch of one that is not is refused — in a dry run too —, `lock` names
/// it, and `status` says it (`networks[].lock_not_held_by`); an instance
/// that came up not hermetic is judged by what it came up with, whatever
/// its container says now.
#[test]
fn a_locked_zone_refuses_a_container_that_is_not_hermetic() {
    use vpn_zone::instance;
    // A short tag: the zone's bridge socket is made below it (SUN_LEN; red
    // once in CI, 2026-09-28).
    let home = Home::new("lockh");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let launch = || home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    let set = |args: &[&str]| {
        let mut argv = vec!["container", "set", "work"];
        argv.extend(args);
        let out = home.run(&argv);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    };
    set(&["network", "nl"]);
    set(&["hermetic", "off"]);
    // The zone tolerates containers without hermeticity (step 1 of the
    // permission model, 2026-09-28).
    let out = home.run(&["hermetic", "nl", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let explained = |key: &str| {
        let json = stdout(&home.run(&["explain", "work", "--json"]));
        let at = json
            .find(&format!("{{\"key\":\"{key}\""))
            .unwrap_or_else(|| panic!("{key}: {json}"));
        json[at..].split('}').next().unwrap().to_owned()
    };
    assert!(
        explained("hermetic").starts_with("{\"key\":\"hermetic\",\"value\":false"),
        "{}",
        explained("hermetic")
    );
    // Unlocked: it goes.
    let out = launch();
    assert!(out.status.success(), "{}", stderr(&out));
    // Locked: the zone tolerates no host session any more — it would come
    // up hermetic there, which the lock says, and holds.
    let out = home.run(&["lock", "nl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("work"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("поднимутся в ней герметичными"),
        "{}",
        stderr(&out)
    );
    assert!(
        explained("hermetic").starts_with("{\"key\":\"hermetic\",\"value\":true"),
        "{}",
        explained("hermetic")
    );
    let json = stdout(&home.run(&["explain", "work", "--json"]));
    assert!(json.contains("\"refused_by\":\"lock\""), "{json}");
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"locked\":true,\"lock_not_held_by\":[]"),
        "{json}"
    );
    let out = launch();
    assert!(out.status.success(), "{}", stderr(&out));
    // Hermetic: it goes, locked.
    set(&["hermetic", "default"]);
    let out = launch();
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"locked\":true,\"lock_not_held_by\":[]"),
        "{json}"
    );
    // Its instance up in the zone, come up not hermetic: named as running,
    // and a launch refused though the container is hermetic now.
    let _bridge = home.instance_is_up("work", "nl");
    fs::write(
        instance::dir(&home.state(), "work").join(instance::SETTINGS),
        "hermetic=false\nnix_daemon=false\nhost_files_writable=false\naudio_manager=false\n",
    )
    .unwrap();
    let out = home.run(&["lock", "nl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("работают"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"locked\":true,\"lock_not_held_by\":[\"work\"]"),
        "{json}"
    );
    let out = launch();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("cellward container stop work"),
        "{}",
        stderr(&out)
    );
    // Unlocked: nothing is said, nothing refused.
    assert!(home.run(&["unlock", "nl"]).status.success());
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(!json.contains("\"locked\":true"), "{json}");
}

#[test]
fn a_container_with_x11_gets_its_own_x_server_in_zones_only() {
    // docs/HERMETICITY.md §7, A.
    let home = Home::new("x11");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    fs::create_dir_all(home.root.join("profiles/work")).unwrap();
    fs::create_dir_all(home.root.join("sandboxes/dev/home")).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];

    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));

    let out = home.run(&["container", "set", "work", "x11", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );

    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(
        stdout(&out).contains("x11-run --xwayland /nonexistent/xwayland-satellite -- steam"),
        "{}",
        stdout(&out)
    );
    // `direct` is the host's own session: nothing to add.
    let out = home.run_with(&["run", "direct", "--profile", "work", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));

    // A sandbox is told, and starts its own satellite.
    let out = home.run(&["container", "set", "sb:dev", "x11", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(
        &["run", "nl", "--sandbox", "dev", "--", "steam"],
        &[("VPN_ZONE_DRYRUN", "1"), ("VPN_ZONE_APPID", "steam")],
    );
    assert!(stdout(&out).contains("--x11 on --"), "{}", stdout(&out));

    let out = home.run(&["container", "set", "work", "x11", "maybe"]);
    assert_eq!(out.status.code(), Some(1));

    // Or the zone itself, without any container.
    let out = home.run_with(&["run", "nl", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));
    let out = home.run(&["x11", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run_with(&["run", "nl", "--", "steam"], &dry);
    assert!(
        stdout(&out).contains("x11-run --xwayland"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":true,\"source\":\"local\"},\"hermetic\":"),
        "{json}"
    );
    // 2026-09-28: a container's own `off` refuses the zone's X server —
    // it used to be the container's OR the zone's —; `default` takes its
    // word back, and the zone's is its again.
    let out = home.run(&["container", "set", "work", "x11", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":false,\"source\":\"local\"}"),
        "{json}"
    );
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));
    let out = home.run(&["container", "set", "work", "x11", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":null,\"source\":\"default\"}"),
        "{json}"
    );
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(stdout(&out).contains("x11-run"), "{}", stdout(&out));
    // Declared in Nix: `false` refuses the zone's too, and is changed there.
    let declared = home.root.join("config/declared/containers");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("work.conf"), "home = layer\nx11 = false\n");
    let out = home.run_with(&["run", "nl", "--profile", "work", "--", "steam"], &dry);
    assert!(!stdout(&out).contains("x11-run"), "{}", stdout(&out));
    let json = stdout(&home.run(&["container", "show", "work", "--json"]));
    assert!(
        json.contains("\"x11\":{\"value\":false,\"source\":\"nix\"}"),
        "{json}"
    );
    assert_eq!(
        home.run(&["container", "set", "work", "x11", "on"])
            .status
            .code(),
        Some(1)
    );
    fs::remove_file(declared.join("work.conf")).unwrap();
    // Hermetic (the prototype): a marker and its JSON.
    let out = home.run(&["hermetic", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    // Changed on purpose (review 2026-09-28): a restart of the zone changes
    // nothing for its containers — their instances take it as they come up.
    assert!(
        stdout(&out).contains("следующего подъёма экземпляров контейнеров"),
        "{}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("перезапуска"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":true,\"source\":\"local\"},\"nix_daemon\":"),
        "{json}"
    );
    // What the zone is let besides: a marker each, and its JSON.
    let out = home.run(&["nix-daemon", "nl", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("cellward container stop"),
        "{}",
        stdout(&out)
    );
    let out = home.run(&["host-files", "nl", "writable"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"nix_daemon\":{\"value\":true,\"source\":\"local\"},\"host_files_writable\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );
    assert!(!home.run(&["nix-daemon", "nl", "yes"]).status.success());
    assert!(home.run(&["nix-daemon", "nl", "default"]).status.success());
    assert!(home.run(&["host-files", "nl", "default"]).status.success());
    // The microphone and the screen cast (2b of docs/PERMISSIONS.md
    // §11.15): the network has no word for its programs any more — status
    // shows the template for it, and the old verb says what to use.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"microphone\":{\"value\":\"ask\",\"source\":\"default\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"camera\":null,\"microphone\":null,"),
        "{json}"
    );
    for key in ["microphone", "screencast"] {
        let out = home.run(&[key, "nl", "no"]);
        assert_eq!(out.status.code(), Some(1), "{key}");
        let said = stderr(&out);
        assert!(
            said.contains(&format!("cellward container set main {key} no")),
            "{said}"
        );
        assert!(
            said.contains(&format!("cellward defaults set {key} no")),
            "{said}"
        );
        assert!(!home.state().join("nl").join(key).exists());
    }
    let out = home.run(&["defaults", "set", "microphone", "no"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("microphone: no\n"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"microphone\":{\"value\":\"no\",\"source\":\"local\"}"),
        "{json}"
    );
    assert!(!home
        .run(&["defaults", "set", "microphone", "maybe"])
        .status
        .success());
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    declare(
        &home.root.join("config/declared/defaults.conf"),
        "screencast = ask\n",
    );
    let out = home.run(&["defaults", "set", "screencast", "no"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("задан в Nix"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"screencast\":{\"value\":\"ask\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/defaults.conf")).unwrap();
    assert!(home
        .run(&["defaults", "set", "microphone", "default"])
        .status
        .success());
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains(
            "\"microphone\":{\"value\":\"ask\",\"source\":\"default\"},\
             \"screencast\":{\"value\":\"ask\",\"source\":\"default\"}"
        ),
        "{json}"
    );
    // The cameras and the audio manager (2b of §11.15): no network's word
    // either — the template's for those with none of their own, a
    // container's (or the main home's) own over it; the raw socket said
    // loudly where it is given.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"audio_manager\":{\"value\":false,\"source\":\"default\"}"),
        "{json}"
    );
    for key in ["camera", "audio-manager"] {
        let out = home.run(&[key, "nl", "on"]);
        assert_eq!(out.status.code(), Some(1), "{key}");
        let said = stderr(&out);
        assert!(
            said.contains(&format!("cellward defaults set {key} on")),
            "{said}"
        );
        assert!(!home.state().join("nl").join(key).exists());
    }
    let out = home.run(&["defaults", "set", "audio-manager", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("audio-manager: on\n"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"audio_manager\":{\"value\":true,\"source\":\"local\"}"),
        "{json}"
    );
    // The camera: a mode of its own words (2026-09-29), `camera` still
    // the real ones given; nonsense refused.
    let out = home.run(&["defaults", "set", "camera", "black"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("camera: black\n"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"camera\":{\"value\":false,\"source\":\"local\"}",
        "\"camera_mode\":{\"value\":\"black\",\"source\":\"local\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    assert!(!home
        .run(&["defaults", "set", "camera", "grey"])
        .status
        .success());
    assert!(home
        .run(&["defaults", "set", "camera", "default"])
        .status
        .success());
    assert!(home
        .run(&["defaults", "set", "audio-manager", "default"])
        .status
        .success());
    let out = home.run(&["container", "set", "main", "audio-manager", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("ВНИМАНИЕ"), "{}", stdout(&out));
    assert!(home
        .run(&["container", "set", "main", "audio-manager", "default"])
        .status
        .success());
    // The pause after a refusal — kept, not used since 2026-09-29 (a
    // refusal is the program's rule): a term within 30s…1d, Nix over it.
    let out = home.run(&["ask-again", "10m"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("срок 10m"), "{}", stdout(&out));
    assert!(stdout(&out).contains("не действует"), "{}", stdout(&out));
    let out = home.run(&["ask-again", "600s"]);
    assert!(stdout(&out).contains("срок 10m"), "{}", stdout(&out));
    for bad in ["5s", "2d", "0m", "soon"] {
        assert!(!home.run(&["ask-again", bad]).status.success(), "{bad}");
    }
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"ask_again\":{\"value\":\"10m\",\"source\":\"local\"}"),
        "{json}"
    );
    declare(&home.root.join("config/declared/ask-again"), "1h");
    let out = home.run(&["ask-again", "default"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"ask_again\":{\"value\":\"1h\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/ask-again")).unwrap();
    assert!(home.run(&["ask-again", "default"]).status.success());
    assert!(!home.root.join("config/ask-again").exists());
    // The waits that end by a clock on purpose: the person's, never where
    // that is a value, Nix's before the local one.
    let out = home.run(&["question-timeout", "never"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("без срока"), "{}", stdout(&out));
    assert!(!home.run(&["question-timeout", "5s"]).status.success());
    assert!(!home.run(&["handshake-check", "never"]).status.success());
    assert!(home.run(&["handshake-check", "20s"]).status.success());
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains(
            "\"question_timeout\":{\"value\":\"never\",\"source\":\"local\"},\
             \"handshake_check\":{\"value\":\"20s\",\"source\":\"local\"}"
        ),
        "{json}"
    );
    declare(&home.root.join("config/declared/question-timeout"), "10m");
    assert!(!home.run(&["question-timeout", "default"]).status.success());
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"question_timeout\":{\"value\":\"10m\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/question-timeout")).unwrap();
    assert!(home.run(&["question-timeout", "default"]).status.success());
    assert!(home.run(&["handshake-check", "default"]).status.success());
    let out = home.run(&["hermetic", "nl", "off"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":false,\"source\":\"local\"},\"nix_daemon\":"),
        "{json}"
    );
    assert!(
        json.contains(
            "\"hermetic\":{\"value\":true,\"source\":\"default\"},\
             \"ask_again\":{\"value\":\"3m\",\"source\":\"default\"},\
             \"question_timeout\":{\"value\":\"2m\",\"source\":\"default\"},\
             \"handshake_check\":{\"value\":\"6s\",\"source\":\"default\"},\
             \"protected\":[],\"host_runs\":[\""
        ),
        "{json}"
    );
    // The places the host runs, where the defaults go on.
    assert!(
        json.contains(&format!("\"{}/.bashrc\"", home.root.display())),
        "{json}"
    );
    assert!(
        json.contains(
            "],\"permissions\":{\"microphone\":{\"value\":\"ask\",\"source\":\"default\"},\
             \"screencast\":{\"value\":\"ask\",\"source\":\"default\"},\
             \"camera\":{\"value\":false,\"source\":\"default\"},\
             \"camera_mode\":{\"value\":\"ask\",\"source\":\"default\"},\
             \"audio_manager\":{\"value\":false,\"source\":\"default\"},\
             \"hermetic\":{\"value\":true,\"source\":\"default\"},\
             \"nix_daemon\":{\"value\":false,\"source\":\"default\"},\
             \"host_files_writable\":{\"value\":false,\"source\":\"default\"},\
             \"network\":{\"value\":\"ask\",\"source\":\"default\"}}}"
        ),
        "{json}"
    );
    // A local default, and a zone that follows it again.
    let out = home.run(&["hermetic", "--default", "on"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["hermetic", "nl", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"user_entries\":{\"value\":\"take-over\",\"source\":\"default\"},\"hermetic\":{\"value\":true,\"source\":\"local\"},\"ask_again\":"),
        "{json}"
    );
    // Declared in Nix: the default refuses the CLI, and an exception inverts it.
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    declare(&home.root.join("config/declared/hermetic-default"), "on");
    declare(
        &home.root.join("config/declared/hermetic-exceptions"),
        "nl\n",
    );
    let out = home.run(&["hermetic", "--default", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в Nix"), "{}", stderr(&out));
    let out = home.run(&["hermetic", "nl", "on"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("hermetic.exceptions"),
        "{}",
        stderr(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"hermetic\":{\"value\":false,\"source\":\"nix\"},\"nix_daemon\":"),
        "{json}"
    );
    fs::remove_file(home.root.join("config/declared/hermetic-default")).unwrap();
    fs::remove_file(home.root.join("config/declared/hermetic-exceptions")).unwrap();
    // Declared in Nix: switched off there, not here.
    fs::create_dir_all(home.root.join("config/declared")).unwrap();
    declare(&home.root.join("config/declared/zone-x11"), "nl\n");
    let out = home.run(&["x11", "nl", "off"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("в Nix"), "{}", stderr(&out));
}

#[test]
fn the_registry_keeps_its_three_field_shape() {
    let home = Home::new("registry");
    home.zone_is_up("nl");
    let reg = home.state().join(".running/__main__/firefox");
    fs::create_dir_all(reg.parent().unwrap()).unwrap();
    // One live record (ourselves) in another network and one dead one.
    fs::write(
        &reg,
        format!("{} de sb:work\n999999 de \n", std::process::id()),
    )
    .unwrap();

    // A dry run rewrites the registry but starts nothing, and without a
    // graphical session the conflict is a warning on stderr rather than a
    // dialog nobody could answer.
    let out = home.run_with(&["run", "nl", "--", "firefox"], &[("VPN_ZONE_DRYRUN", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let kept = fs::read_to_string(&reg).unwrap();
    assert_eq!(kept, format!("{} de sb:work\n", std::process::id()));
    assert!(Path::new(&home.state().join(".running/__main__/.lock")).is_file());
}

#[test]
fn a_zone_gets_its_border_colour_width_and_switch() {
    // docs/WINDOW-FRAME.md §0а, §11: the colour per zone and its width go to
    // the proxy with the launch, from Nix over the local setting over the
    // default; the switch is read by the supervisor, so only its directory.
    let home = Home::new("frame");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let default = vpn_zone::frame::default_color("nl").hex();

    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    // The title strip: always by default, the zone and the container as the
    // launch knows it.
    assert!(
        line.contains(&format!(
            "wl-sandbox foot --zone {} --frame {}:4:always --frame-title nl · настоящий дом \
             --frame-switch {} --frame-state {} --frame-zone nl ",
            // The sockets by the instance's key (stage 5: nothing by the
            // zone's name); the title still names the zone.
            vpn_zone::instance::key("main:nl"),
            &default[1..],
            home.root.join("config").display(),
            home.state().display()
        )),
        "{line}"
    );
    // Where the frame comes from, for the supervisor to read it again on
    // the fly; the program after it.
    assert!(line.contains(" -- foot"), "{line}");
    let line = stdout(&home.run_with(&["run", "nl", "--fs-sandbox", "--", "foot"], &dry));
    assert!(line.contains("--frame-title nl · разовый "), "{line}");
    // No border for the host's own session: it is no zone.
    let line = stdout(&home.run_with(&["run", "unconfined", "--", "foot"], &dry));
    assert!(!line.contains("--frame"), "{line}");

    let out = home.run(&["frame", "color", "nl", "#3366FF"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("#3366ff"), "{}", stdout(&out));
    let out = home.run(&["frame", "width", "6"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = home.run(&["frame", "title", "hover"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(line.contains("--frame 3366ff:6:hover "), "{line}");
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frame_title\":{\"value\":\"hover\",\"source\":\"local\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"frame_color\":{\"value\":\"#3366ff\",\"source\":\"local\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"frame_width\":{\"value\":6,\"source\":\"local\"}"),
        "{json}"
    );

    // Nix wins, and the command does not pretend to change what Nix set.
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("frame-colors"), "nl #ff0000\n");
    declare(&declared.join("frame-width"), "3");
    declare(&declared.join("frame-title"), "off");
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(line.contains("--frame ff0000:3:off "), "{line}");
    for change in [&["frame", "width", "8"][..], &["frame", "title", "default"]] {
        let out = home.run(change);
        assert!(!out.status.success(), "{change:?}");
        assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    }
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frame_color\":{\"value\":\"#ff0000\",\"source\":\"nix\"}"),
        "{json}"
    );
    assert!(
        json.contains("\"frame_title\":{\"value\":\"off\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(declared.join("frame-title")).unwrap();
    let out = home.run(&["frame", "title", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frame_title\":{\"value\":\"always\",\"source\":\"default\"}"),
        "{json}"
    );

    // Back to the name's colour.
    fs::remove_file(declared.join("frame-colors")).unwrap();
    let out = home.run(&["frame", "color", "nl", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(&default), "{}", stdout(&out));

    // The switch: a setting of its own, read when a program connects.
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frames\":{\"value\":true,\"source\":\"default\"}"),
        "{json}"
    );
    let out = home.run(&["frame", "hide"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(home.root.join("config/frames")).unwrap(),
        "hidden"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"frames\":{\"value\":false,\"source\":\"local\"}"),
        "{json}"
    );
    assert!(home.run(&["frame", "show"]).status.success());
    assert!(!vpn_zone::frame::hidden(&home.root.join("config")));

    // Nonsense is refused, and a zone that is not there too.
    for bad in [
        &["frame", "color", "nl", "blue"][..],
        &["frame", "color", "nope", "#000000"],
        &["frame", "width", "-1"],
        &["frame", "width", "33"],
        &["frame", "title", "sometimes"],
        &["frame", "title"],
        &["frame", "sideways"],
    ] {
        assert!(!home.run(bad).status.success(), "{bad:?}");
    }
}

#[test]
fn a_black_camera_is_the_supervisors_to_serve() {
    // 2026-09-29 (`crate::camera`): a camera `black` or `ask` is served by
    // the launch's supervisor — `wl-sandbox --camera <mode>` —; `no` is
    // none, `yes` the real ones, which are no supervisor's. `ask` — the
    // default — only where the host has a camera to ask about.
    let camera_here = vpn_zone::camera::host_has_camera();
    let home = Home::new("black-camera");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert_eq!(line.contains("--camera ask --"), camera_here, "{line}");
    for (word, served) in [
        ("black", true),
        ("ask", camera_here),
        ("yes", false),
        ("no", false),
    ] {
        let out = home.run(&["container", "set", "main", "camera", word]);
        assert!(out.status.success(), "{word}: {}", stderr(&out));
        let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
        assert_eq!(
            line.contains(&format!("--camera {word} --")),
            served,
            "{word}: {line}"
        );
    }
    let out = home.run(&["container", "set", "main", "camera", "grey"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("black"), "{}", stderr(&out));
}

#[test]
fn the_frames_look_goes_to_the_launch_and_the_status() {
    // docs/WINDOW-FRAME.md §8 «Вид рамки» (2026-09-28): the style, the
    // buttons' look and the corners' radius, as the width and the title —
    // Nix over the local setting over the default, in `status --json` with
    // their source, and to the proxy in the launch's `--frame`, said only
    // when one is not the default.
    let home = Home::new("frame-look");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let colour = vpn_zone::frame::default_color("nl").hex()[1..].to_owned();

    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"frame_buttons\":{\"value\":\"cellward\",\"source\":\"default\"}",
        "\"frame_style\":{\"value\":\"soft\",\"source\":\"default\"}",
        "\"frame_radius\":{\"value\":0,\"source\":\"default\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!("--frame {colour}:4:always --frame-title")),
        "{line}"
    );

    for (setting, value) in [("style", "tag"), ("buttons", "macos"), ("radius", "12")] {
        let out = home.run(&["frame", setting, value]);
        assert!(out.status.success(), "{setting}: {}", stderr(&out));
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!("--frame {colour}:4:always:macos:tag:12 ")),
        "{line}"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"frame_buttons\":{\"value\":\"macos\",\"source\":\"local\"}",
        "\"frame_style\":{\"value\":\"tag\",\"source\":\"local\"}",
        "\"frame_radius\":{\"value\":12,\"source\":\"local\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    // The summary names them.
    let summary = stdout(&home.run(&["frame"]));
    assert!(
        summary.contains("(tag)") && summary.contains("(macos)"),
        "{summary}"
    );

    // Nix wins, and the command does not pretend to change what Nix set.
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("frame-style"), "full");
    declare(&declared.join("frame-buttons"), "windows");
    declare(&declared.join("frame-radius"), "8");
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!("--frame {colour}:4:always:windows:full:8 ")),
        "{line}"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"frame_buttons\":{\"value\":\"windows\",\"source\":\"nix\"}",
        "\"frame_style\":{\"value\":\"full\",\"source\":\"nix\"}",
        "\"frame_radius\":{\"value\":8,\"source\":\"nix\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    for change in [
        &["frame", "style", "soft"][..],
        &["frame", "buttons", "default"],
        &["frame", "radius", "4"],
    ] {
        let out = home.run(change);
        assert!(!out.status.success(), "{change:?}");
        assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    }
    for name in ["frame-style", "frame-buttons", "frame-radius"] {
        fs::remove_file(declared.join(name)).unwrap();
    }
    // Back to the defaults: the launch's line as it was.
    for setting in ["style", "buttons", "radius"] {
        let out = home.run(&["frame", setting, "default"]);
        assert!(out.status.success(), "{setting}: {}", stderr(&out));
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!("--frame {colour}:4:always --frame-title")),
        "{line}"
    );

    // niri's radius (2026-09-29), inside and outside: the setting says
    // `niri`, the launch niri's number as its config has it now.
    let niri = home.root.join("niri.kdl");
    fs::write(
        &niri,
        "window-rule {\n    geometry-corner-radius 20\n    clip-to-geometry true\n}\n",
    )
    .unwrap();
    let with_niri = [
        ("VPN_ZONE_DRYRUN", "1"),
        ("NIRI_CONFIG", niri.to_str().unwrap()),
    ];
    for setting in ["radius", "outer-radius"] {
        let out = home.run_with(&["frame", setting, "niri"], &with_niri);
        assert!(out.status.success(), "{setting}: {}", stderr(&out));
        assert!(stdout(&out).contains("как у niri (20)"), "{}", stdout(&out));
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &with_niri));
    assert!(
        line.contains(&format!(
            "--frame {colour}:4:always:cellward:soft:niri20:niri20 "
        )),
        "{line}"
    );
    let json = stdout(&home.run_with(&["status", "--json"], &with_niri));
    for field in [
        "\"frame_radius\":{\"value\":\"niri\",\"source\":\"local\"}",
        "\"frame_outer_radius\":{\"value\":\"niri\",\"source\":\"local\"}",
        "\"frame_niri_radius\":20,",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    // The outer radius alone away from its default says the look before it.
    for (setting, value) in [("radius", "default"), ("outer-radius", "24")] {
        let out = home.run(&["frame", setting, value]);
        assert!(out.status.success(), "{setting}: {}", stderr(&out));
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!("--frame {colour}:4:always:cellward:soft:0:24 ")),
        "{line}"
    );
    assert!(home
        .run(&["frame", "outer-radius", "default"])
        .status
        .success());

    // Nonsense is refused.
    for bad in [
        &["frame", "style", "glass"][..],
        &["frame", "style"],
        &["frame", "buttons", "beos"],
        &["frame", "radius", "17"],
        &["frame", "radius", "-1"],
        &["frame", "radius", "round"],
        &["frame", "radius", "niri20"],
        &["frame", "outer-radius", "33"],
        &["frame", "outer-radius"],
    ] {
        assert!(!home.run(bad).status.success(), "{bad:?}");
    }
}

#[test]
fn the_frame_in_fullscreen_goes_to_the_launch_and_the_status() {
    // 2026-09-29: the frame of a fullscreen window, the fullscreen buttons
    // and the double click, as the look — Nix over the local setting over
    // the default, in `status --json` with their source, and to the proxy
    // in the launch's `--frame`, said only when one is not the default.
    let home = Home::new("frame-fullscreen");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let dry = [("VPN_ZONE_DRYRUN", "1")];
    let colour = vpn_zone::frame::default_color("nl").hex()[1..].to_owned();

    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"frame_fullscreen_width\":{\"value\":\"same\",\"source\":\"default\"}",
        "\"frame_fullscreen_title\":{\"value\":\"off\",\"source\":\"default\"}",
        "\"frame_fullscreen_notice\":{\"value\":3,\"source\":\"default\"}",
        "\"frame_fullscreen_button\":{\"value\":\"one\",\"source\":\"default\"}",
        "\"frame_double_click\":{\"value\":\"maximize\",\"source\":\"default\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    for args in [
        &["frame", "fullscreen", "width", "0"][..],
        &["frame", "fullscreen", "title", "hover"],
        &["frame", "fullscreen", "notice", "off"],
        &["frame", "fullscreen-button", "two"],
        &["frame", "double-click", "none"],
    ] {
        let out = home.run(args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!(
            "--frame {colour}:4:always:cellward:soft:0:0:0:hover:0:two:none "
        )),
        "{line}"
    );
    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"frame_fullscreen_width\":{\"value\":0,\"source\":\"local\"}",
        "\"frame_fullscreen_title\":{\"value\":\"hover\",\"source\":\"local\"}",
        "\"frame_fullscreen_notice\":{\"value\":0,\"source\":\"local\"}",
        "\"frame_fullscreen_button\":{\"value\":\"two\",\"source\":\"local\"}",
        "\"frame_double_click\":{\"value\":\"none\",\"source\":\"local\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    let summary = stdout(&home.run(&["frame"]));
    assert!(
        summary.contains("(two)") && summary.contains("ничего (none)"),
        "{summary}"
    );
    // `on` is the default's seconds, a number seconds of its own.
    let out = home.run(&["frame", "fullscreen", "notice", "on"]);
    assert!(stdout(&out).contains("3 с"), "{}", stdout(&out));
    let out = home.run(&["frame", "fullscreen", "notice", "10"]);
    assert!(stdout(&out).contains("10 с"), "{}", stdout(&out));

    // Nix wins, and the command does not pretend to change what Nix set.
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("frame-fullscreen-width"), "same");
    declare(&declared.join("frame-double-click"), "maximize");
    let json = stdout(&home.run(&["status", "--json"]));
    for field in [
        "\"frame_fullscreen_width\":{\"value\":\"same\",\"source\":\"nix\"}",
        "\"frame_double_click\":{\"value\":\"maximize\",\"source\":\"nix\"}",
    ] {
        assert!(json.contains(field), "{field}: {json}");
    }
    for change in [
        &["frame", "fullscreen", "width", "2"][..],
        &["frame", "double-click", "default"],
    ] {
        let out = home.run(change);
        assert!(!out.status.success(), "{change:?}");
        assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    }
    for name in ["frame-fullscreen-width", "frame-double-click"] {
        fs::remove_file(declared.join(name)).unwrap();
    }
    // Back to the defaults: the launch's line as it was.
    for args in [
        &["frame", "fullscreen", "width", "default"][..],
        &["frame", "fullscreen", "title", "default"],
        &["frame", "fullscreen", "notice", "default"],
        &["frame", "fullscreen-button", "default"],
        &["frame", "double-click", "default"],
    ] {
        let out = home.run(args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    }
    let line = stdout(&home.run_with(&["run", "nl", "--", "foot"], &dry));
    assert!(
        line.contains(&format!("--frame {colour}:4:always --frame-title")),
        "{line}"
    );

    // Nonsense is refused.
    for bad in [
        &["frame", "fullscreen", "width", "33"][..],
        &["frame", "fullscreen", "width", "wide"],
        &["frame", "fullscreen", "width"],
        &["frame", "fullscreen", "title", "never"],
        &["frame", "fullscreen", "notice", "31"],
        &["frame", "fullscreen", "notice", "-1"],
        &["frame", "fullscreen", "sideways", "1"],
        &["frame", "fullscreen-button", "three"],
        &["frame", "double-click", "triple"],
    ] {
        assert!(!home.run(bad).status.success(), "{bad:?}");
    }
}

#[test]
fn a_networks_connection_is_a_setting_nix_wins() {
    // docs/PERMISSIONS.md §11.16: a network's «Подключение» — auto (the
    // default), ask or manual —, Nix over the network's own setting over the
    // default, in `status --json` with its source.
    let home = Home::new("connection");
    home.zone_is_up("nl");
    fs::write(home.state().join("nl/config.conf"), crlf_config()).unwrap();
    let out = home.run(&["connection", "nl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("nl: подключение сразу (auto) (умолчание)"),
        "{}",
        stdout(&out)
    );
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"connection\":{\"value\":\"auto\",\"source\":\"default\"}"),
        "{json}"
    );
    // No network, no connecting.
    assert!(
        json.contains("\"name\":\"unconfined\"") && json.contains("\"connection\":null"),
        "{json}"
    );
    let out = home.run(&["connection", "nl", "ask"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("спросить (ask)"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"connection\":{\"value\":\"ask\",\"source\":\"local\"}"),
        "{json}"
    );
    let all = stdout(&home.run(&["connection"]));
    assert!(all.contains("nl: подключение спросить (ask)"), "{all}");

    // Nix wins, and the command does not pretend to change what Nix set.
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("network-connect"), "nl manual\n");
    let out = home.run(&["connection", "nl", "auto"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"connection\":{\"value\":\"manual\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(declared.join("network-connect")).unwrap();
    let out = home.run(&["connection", "nl", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"connection\":{\"value\":\"auto\",\"source\":\"default\"}"),
        "{json}"
    );

    // Nonsense is refused.
    for bad in [
        &["connection", "nl", "always"][..],
        &["connection", "nope", "ask"],
        &["connection", "../nl", "ask"],
    ] {
        assert!(!home.run(bad).status.success(), "{bad:?}");
    }
}

#[test]
fn the_tray_badge_is_a_setting_nix_wins() {
    let home = Home::new("tray-badge");
    let out = home.run(&["tray"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("(dot)"), "{}", stdout(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"tray_badge\":{\"value\":\"dot\",\"source\":\"default\"}"),
        "{json}"
    );
    let out = home.run(&["tray", "badge", "bar"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"tray_badge\":{\"value\":\"bar\",\"source\":\"local\"}"),
        "{json}"
    );
    for bad in [&["tray", "badge", "number"][..], &["tray", "colour"]] {
        assert!(!home.run(bad).status.success(), "{bad:?}");
    }
    // Nix wins, and the command does not pretend to change what Nix set.
    let declared = home.root.join("config/declared");
    fs::create_dir_all(&declared).unwrap();
    declare(&declared.join("tray-badge"), "off");
    let out = home.run(&["tray", "badge", "dot"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Nix"), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"tray_badge\":{\"value\":\"off\",\"source\":\"nix\"}"),
        "{json}"
    );
    fs::remove_file(declared.join("tray-badge")).unwrap();
    let out = home.run(&["tray", "badge", "default"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let json = stdout(&home.run(&["status", "--json"]));
    assert!(
        json.contains("\"tray_badge\":{\"value\":\"dot\",\"source\":\"default\"}"),
        "{json}"
    );
}

#[test]
fn restart_needs_a_zone_by_its_name() {
    let home = Home::new("restart-name");
    let out = home.run(&["restart"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("нужно имя"), "{}", stderr(&out));
    let out = home.run(&["restart", "-bad"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("не имя зоны"), "{}", stderr(&out));
}

#[test]
fn version_names_the_build() {
    let home = Home::new("version");
    for word in ["version", "--version"] {
        let out = home.run(&[word]);
        assert!(out.status.success(), "{word}: {}", stderr(&out));
        let text = stdout(&out);
        assert!(text.starts_with("cellward "), "{word}: {text}");
        assert!(
            text.contains('(') && text.trim_end().ends_with(')'),
            "{word}: {text}"
        );
    }
}
