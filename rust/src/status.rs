//! Machine-readable state (`docs/CONTAINERS.md` §9).
//!
//! `vpn-zone status --json`, `vpn-zone container list --json` and
//! `vpn-zone container show <name> --json` print parts of one schema, for
//! configuration tools that set this project up through its module options and
//! must never parse its files.
//!
//! Two promises, both part of the contract:
//!
//! * **`schema_version`** is in every document. Within a version changes are
//!   additive only; removing a field or changing its meaning is a new version
//!   and a CHANGELOG entry;
//! * **every settable value says where it comes from**: `{"value": …, "source":
//!   "nix" | "local" | "default"}`. A tool that offers to change a value
//!   declared in Nix would be fighting the module; this tells it not to.
//!   Runtime facts (`up`, `running`, `tunnel_alive`) are plain values.
//!
//! Written by hand, like the manifest is read by hand: the schema is ours and
//! small, and `serde` would be a code generator in the build for it.

use std::fs;

use crate::cli::{liveness_line, read_setting, strip_cr, visible_entries, zone_pid};
use crate::config::WgConfig;
use crate::container::{self, Container, Home, Source};
use crate::fs_sandbox::Perms;
use crate::launch::NO_ESCAPE;
use crate::tools::Tools;

pub const SCHEMA_VERSION: u32 = 1;

/// A JSON string literal.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // DEL and C1 too: valid JSON either way, but `--json` is read in
            // terminals as well, and U+009B is an escape sequence's start
            // in some of them (a name from a zone may carry one).
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn array(items: Vec<String>) -> String {
    format!("[{}]", items.join(","))
}

fn sourced(value: String, source: Source) -> String {
    format!(
        "{{\"value\":{value},\"source\":{}}}",
        string(source.as_str())
    )
}

fn sourced_str(value: &str, source: Source) -> String {
    sourced(string(value), source)
}

/// A one-line setting file of `~/.config/vpn-zones`, or its default.
fn setting(tools: &Tools, name: &str, default: &str) -> (String, Source) {
    match crate::cli::setting(tools, name) {
        Some((value, source)) if !value.is_empty() => (value, source),
        _ => (default.to_owned(), Source::Default),
    }
}

pub fn defaults(tools: &Tools) -> String {
    let (network, network_source) = setting(tools, "default", "offline");
    let network = crate::launch::network_name(&network).to_owned();
    let (container, container_source) = setting(tools, "default-profile", "ask");
    // A container by the name `containers[].selector` has — `sb:work` from
    // before one name per container is `work` (or `work-sb`) there.
    let container = match container.as_str() {
        "ask" | "main" | "own" => container,
        other => crate::container::canonical(tools, other).unwrap_or(container),
    };
    let (mode, mode_source) = setting(tools, "mode", "picker");
    let (wayland, wayland_source) = setting(tools, "wayland-sandbox", "on");
    // As `launch::proxy_wanted` decides it: only `off` switches it off.
    let (proxy, proxy_source) = setting(tools, "wayland-proxy", "on");
    let (autostart, autostart_source) = setting(tools, "autostart", "ask");
    let (user_entries, user_entries_source) = setting(tools, "user-entries", "take-over");
    let (hermetic, hermetic_source) = crate::hermetic::default_setting(&tools.config);
    // The zones' borders: whether the switch shows them (local only — it is
    // flipped for a call and back, `crate::frame`), and their width.
    let (_, frames_source) = setting(tools, crate::frame::SWITCH_SETTING, "shown");
    let frames = !crate::frame::hidden(&tools.config);
    let (frame_width, frame_width_source) = crate::frame::width(&tools.config);
    // And their title strip: always, hover or off (`crate::frame::title_mode`).
    let (frame_title, frame_title_source) = crate::frame::title_mode(&tools.config);
    // And their look (2026-09-28): the buttons', the style, the corners'
    // radius — for the configurator as the others, `{value, source}`.
    let (frame_buttons, frame_buttons_source) = crate::frame::buttons(&tools.config);
    let (frame_style, frame_style_source) = crate::frame::style(&tools.config);
    let (frame_radius, frame_radius_source) = crate::frame::radius(&tools.config);
    // The zone's mark on its programs' tray icons (`crate::tray`).
    let (tray_badge, tray_badge_source) = crate::tray::badge(&tools.config);
    // How long a refused permission is not asked about again.
    let (ask_again, ask_again_source) = crate::grants::ask_again(&tools.config);
    // The waits that end by a clock on purpose (`crate::timings`).
    let (question, question_source) = crate::timings::QUESTION.read(&tools.config);
    let (handshake, handshake_source) = crate::timings::HANDSHAKE_CHECK.read(&tools.config);
    format!(
        "{{\"network\":{},\"container\":{},\"launcher_mode\":{},\"compositor_restriction\":{},\
         \"wayland_proxy\":{},\"frames\":{},\"frame_width\":{},\"frame_title\":{},\
         \"frame_buttons\":{},\"frame_style\":{},\"frame_radius\":{},\"tray_badge\":{},\
         \"autostart_unassigned\":{},\"user_entries\":{},\"hermetic\":{},\"ask_again\":{},\
         \"question_timeout\":{},\"handshake_check\":{}}}",
        sourced_str(&network, network_source),
        sourced_str(&container, container_source),
        sourced_str(&mode, mode_source),
        sourced((wayland == "on").to_string(), wayland_source),
        sourced((proxy.trim() != "off").to_string(), proxy_source),
        sourced(frames.to_string(), frames_source),
        sourced(frame_width.to_string(), frame_width_source),
        sourced_str(frame_title.as_str(), frame_title_source),
        sourced_str(frame_buttons.as_str(), frame_buttons_source),
        sourced_str(frame_style.as_str(), frame_style_source),
        sourced(frame_radius.to_string(), frame_radius_source),
        sourced_str(tray_badge.as_str(), tray_badge_source),
        sourced_str(&autostart, autostart_source),
        sourced_str(&user_entries, user_entries_source),
        sourced(hermetic.to_string(), hermetic_source),
        sourced_str(&crate::grants::term_text(ask_again), ask_again_source),
        sourced_str(&question.text(), question_source),
        sourced_str(&handshake.text(), handshake_source)
    )
}

/// The host interface a `host-interface` zone goes out through.
fn host_interface(dir: &std::path::Path) -> Option<String> {
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let ini = WgConfig::parse(&strip_cr(&raw)).ok()?;
    crate::hostif::HostIfConfig::from_ini(&ini)
        .ok()
        .map(|h| h.interface)
}

/// The system zone a `system-zone` zone goes out through (`docs/SYSTEM.md` §7b).
fn system_zone_of(dir: &std::path::Path) -> Option<String> {
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let ini = WgConfig::parse(&strip_cr(&raw)).ok()?;
    crate::sysuplink::SysUplinkConfig::from_ini(&ini)
        .ok()
        .map(|s| s.zone)
}

/// The kind of a zone directory, or `None` when it is not a zone.
fn zone_kind(dir: &std::path::Path) -> Option<&'static str> {
    if dir.join("offline").exists() {
        return Some("offline");
    }
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let ini = WgConfig::parse(&strip_cr(&raw)).ok();
    Some(match ini {
        Some(ini) if crate::openconnect::is_openconnect(&ini) => "openconnect",
        // Not encrypted by the zone: a configuration tool has to be able to
        // say so without reading the file.
        Some(ini) if crate::hostif::is_host_interface(&ini) => "host-interface",
        // No tunnel of its own: the named system zone's.
        Some(ini) if crate::sysuplink::is_system_zone(&ini) => "system-zone",
        _ => "wireguard",
    })
}

pub fn networks(tools: &Tools) -> String {
    let mut items = vec![
        // `aliases`: the names it is also read by — `direct`, its name until
        // 2026-09, may still be in a configuration or in Nix.
        "{\"name\":\"unconfined\",\"kind\":\"unconfined\",\"aliases\":[\"direct\"],\"source\":\"default\",\"up\":true,\
         \"locked\":false,\"tunnel_alive\":null,\"handshake_age_s\":null,\"rx_bytes\":null,\
             \"tx_bytes\":null,\"interface\":null,\"x11\":null,\"hermetic\":null,\"nix_daemon\":null,\"host_files_writable\":null,\"camera\":null,\"microphone\":null,\"screencast\":null,\"audio_manager\":null,\"system_zone\":null,\"frame_color\":null,\"build\":null,\"restart_needed\":null,\"attached\":null,\"bridge\":null}"
            .to_owned(),
    ];
    let mut offline_listed = false;
    let installed = crate::build::installed(tools);
    let instances = crate::instance::running(&tools.state);
    for dir in visible_entries(&tools.state) {
        if !dir.is_dir() {
            continue;
        }
        let Some(kind) = zone_kind(&dir) else {
            continue;
        };
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        // A zone left with a name that now means the host's network: it would
        // be a second `unconfined` here, and a launch refuses it anyway.
        // (`vpn-zone doctor` names it.)
        if crate::launch::is_unconfined_name(&name) {
            continue;
        }
        offline_listed |= name == "offline";
        let up = zone_pid(&tools.state, dir.file_name().unwrap_or_default()).is_some();
        // A running zone's build: an update leaves it running, on the build it
        // was started from (`crate::build`).
        let build = if up {
            crate::build::string(crate::build::age(&dir, &installed))
        } else {
            "null".to_owned()
        };
        // What it came up with and is set otherwise now — in force from its
        // next start (`hermetic::APPLIED`); `null` down, or not known.
        let restart_needed = if up {
            crate::hermetic::restart_needed(&dir, &tools.config, &name).map_or(
                "null".to_owned(),
                |names| {
                    let names: Vec<String> = names.into_iter().map(string).collect();
                    format!("[{}]", names.join(","))
                },
            )
        } else {
            "null".to_owned()
        };
        let mirror = if up && kind != "offline" {
            fs::read_to_string(dir.join("status")).ok()
        } else {
            None
        };
        let alive = mirror.as_deref().map_or("null".to_owned(), |m| {
            crate::cli::alive_line(&dir, m).is_some().to_string()
        });
        // Counters for status bars, from the same mirror; `null` when there is
        // nothing to read (down, offline, or a zone from an older version).
        let reading = mirror.as_deref().map(crate::watch::parse_mirror);
        let counters = match &reading {
            Some(r) => format!(
                "\"handshake_age_s\":{},\"rx_bytes\":{},\"tx_bytes\":{}",
                r.handshake_age_s
                    .map_or("null".to_owned(), |a| a.to_string()),
                r.rx_bytes,
                r.tx_bytes
            ),
            None => "\"handshake_age_s\":null,\"rx_bytes\":null,\"tx_bytes\":null".to_owned(),
        };
        // Named for the one kind that has one: "через enp4s0 — без шифрования"
        // has to be sayable without reading the config.
        let interface = if kind == "host-interface" {
            host_interface(&dir).map_or("null".to_owned(), |i| string(&i))
        } else {
            "null".to_owned()
        };
        let system_zone = if kind == "system-zone" {
            system_zone_of(&dir).map_or("null".to_owned(), |z| string(&z))
        } else {
            "null".to_owned()
        };
        let x11 = {
            let (on, source) = crate::x11::zone_setting(&tools.state, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        let hermetic = {
            let (on, source) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        // What the zone is let besides (`vpn-zone nix-daemon`, `host-files`):
        // in force when it next comes up, and from where.
        let nix_daemon = {
            let (on, source) = crate::hermetic::nix_daemon(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        let host_files_writable = {
            let (on, source) = crate::hermetic::host_files_writable(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        let camera = {
            let (on, source) = crate::hermetic::camera(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        // Whether its programs record the microphone: in force at once (the
        // sound filter reads it for every record stream).
        let microphone = {
            let (setting, source) = crate::microphone::setting(&dir, &tools.config, &name);
            sourced_str(setting.as_str(), source)
        };
        // Whether its programs cast the screen, and may have the choice
        // remembered: in force at once (the zone's bus filter reads it for
        // every call of the screen cast portal).
        let screencast = {
            let (setting, source) = crate::screencast::setting(&dir, &tools.config, &name);
            sourced_str(setting.as_str(), source)
        };
        // Whether a hermetic zone gets the host's raw PipeWire socket instead
        // of the restricted one (`crate::pw_context`); from its next start.
        let audio_manager = {
            let (on, source) = crate::hermetic::audio_manager(&dir, &tools.config, &name);
            sourced(on.to_string(), source)
        };
        // The colour of the border around its programs' windows.
        let frame_color = {
            let (color, source) = crate::frame::zone_color(&tools.state, &tools.config, &name);
            sourced_str(&color.hex(), source)
        };
        let source = if kind == "offline" {
            "default"
        } else {
            "local"
        };
        // The containers' instances: those that run with no network (stage 1
        // of the container design), what `offline` is now; those a zone
        // carries now, their exit through it (stage 2) — none while it is
        // down. And whether it can carry them at all: its bridge is there
        // (`false`: a zone of a previous build, into which a launch is
        // refused until it is restarted — stage 5), `null` down.
        let (attached, bridge) = if name == crate::launch::OFFLINE {
            (attached_to(&instances, &name), "null".to_owned())
        } else if up {
            (
                carried_by(&instances, &name),
                crate::bridge::carries(&dir).to_string(),
            )
        } else {
            ("[]".to_owned(), "null".to_owned())
        };
        items.push(format!(
            "{{\"name\":{},\"kind\":\"{kind}\",\"aliases\":[],\"source\":\"{source}\",\"up\":{up},\"locked\":{},\"tunnel_alive\":{alive},{counters},\"interface\":{interface},\"x11\":{x11},\"hermetic\":{hermetic},\"nix_daemon\":{nix_daemon},\"host_files_writable\":{host_files_writable},\"camera\":{camera},\"microphone\":{microphone},\"screencast\":{screencast},\"audio_manager\":{audio_manager},\"system_zone\":{system_zone},\"frame_color\":{frame_color},\"build\":{build},\"restart_needed\":{restart_needed},\"attached\":{attached},\"bridge\":{bridge}}}",
            string(&name),
            dir.join(NO_ESCAPE).exists()
        ));
    }
    if !offline_listed {
        let (color, source) = crate::frame::zone_color(&tools.state, &tools.config, "offline");
        // Its directory is made when it first comes up; the setting may be
        // declared before that.
        let (mic, mic_source) =
            crate::microphone::setting(&tools.state.join("offline"), &tools.config, "offline");
        let (cast, cast_source) =
            crate::screencast::setting(&tools.state.join("offline"), &tools.config, "offline");
        items.push(format!(
            "{{\"name\":\"offline\",\"kind\":\"offline\",\"aliases\":[],\"source\":\"default\",\"up\":false,\
             \"locked\":false,\"tunnel_alive\":null,\"handshake_age_s\":null,\"rx_bytes\":null,\
             \"tx_bytes\":null,\"interface\":null,\"x11\":null,\"hermetic\":null,\"nix_daemon\":null,\"host_files_writable\":null,\"camera\":null,\
             \"microphone\":{},\"screencast\":{},\"audio_manager\":null,\"system_zone\":null,\"frame_color\":{},\"build\":null,\"restart_needed\":null,\"attached\":{},\"bridge\":null}}",
            sourced_str(mic.as_str(), mic_source),
            sourced_str(cast.as_str(), cast_source),
            sourced_str(&color.hex(), source),
            attached_to(&instances, crate::launch::OFFLINE)
        ));
    }
    array(items)
}

/// One system zone (`docs/SYSTEM.md` §8): the same counters as a network,
/// `null` where the reader may not look — the run directory is the group
/// `vpn-zones`'s.
pub fn system_network(
    name: &str,
    kind: &str,
    source: &str,
    state: &crate::system::RunState,
    uplink: Option<&str>,
) -> String {
    use crate::system::RunState;
    let (readable, up, mirror) = match state {
        RunState::Closed => (false, "null", None),
        RunState::Down => (true, "false", None),
        RunState::Up(mirror) => (true, "true", mirror.as_deref()),
    };
    let alive = mirror.map_or("null".to_owned(), |m| {
        liveness_line(m).is_some().to_string()
    });
    let counters = match mirror.map(crate::watch::parse_mirror) {
        Some(r) => format!(
            "\"handshake_age_s\":{},\"rx_bytes\":{},\"tx_bytes\":{}",
            r.handshake_age_s
                .map_or("null".to_owned(), |a| a.to_string()),
            r.rx_bytes,
            r.tx_bytes
        ),
        None => "\"handshake_age_s\":null,\"rx_bytes\":null,\"tx_bytes\":null".to_owned(),
    };
    format!(
        "{{\"name\":{},\"netns\":{},\"kind\":{},\"source\":{},\"up\":{up},\"tunnel_alive\":{alive},{counters},\"readable\":{readable},\"uplink\":{}}}",
        string(name),
        string(&crate::system::netns_path(name).to_string_lossy()),
        string(kind),
        string(source),
        uplink.map_or("null".to_owned(), string)
    )
}

/// The declared system zones — a separate array and not entries of
/// `networks`: a tool that did not know the difference would offer a system
/// zone to a program container, which cannot use one.
pub fn system_networks() -> String {
    array(
        crate::system::all_zones()
            .iter()
            .map(|name| {
                let settings = crate::system::settings(name);
                let declared = settings.as_ref().is_some_and(|s| s.declared);
                system_network(
                    name,
                    crate::system::declared_kind(name),
                    if declared { "nix" } else { "local" },
                    &crate::system::run_state(name),
                    settings.as_ref().and_then(|s| s.uplink.as_deref()),
                )
            })
            .collect(),
    )
}

/// The live launches of a container: `{app, pid, network, instance}` — the
/// instance a launch runs in (`crate::instance`: offline since stage 1 of
/// the container design, in a zone since stage 2), `null` for one that is
/// not in one: unconfined, or in a zone's own namespaces (launched there by
/// a previous build; nothing is since stage 5).
fn running(tools: &Tools, c: &Container) -> String {
    let records = container::live_records(tools, c);
    let asks = c.network.value == container::Network::Ask;
    let instances = crate::instance::running(&tools.state);
    array(
        records
            .iter()
            .map(|(app, r)| {
                let instance = crate::instance::id_of(
                    crate::instance::Of::Container {
                        name: &c.name,
                        home: c.home,
                        asks,
                    },
                    &r.zone,
                )
                .and_then(|id| instances.iter().find(|i| i.id == id && i.network == r.zone));
                // The network it is in now (stage 4): its instance's — a live
                // switch moves its records as well (`registry::retarget`).
                let network_now = instance.map_or(r.zone.as_str(), |i| i.network.as_str());
                let instance = instance.map_or_else(|| "null".to_owned(), |i| string(&i.id));
                format!(
                    "{{\"app\":{},\"pid\":{},\"network\":{},\"network_now\":{},\
                     \"instance\":{instance}}}",
                    string(app),
                    r.pid,
                    string(&r.zone),
                    string(network_now)
                )
            })
            .collect(),
    )
}

/// The ids of the running instances in `network`, as a JSON array.
fn attached_to(instances: &[crate::instance::Running], network: &str) -> String {
    array(
        instances
            .iter()
            .filter(|i| i.network == network)
            .map(|i| string(&i.id))
            .collect(),
    )
}

/// The ids of the running instances zone `zone` carries now — their way out
/// through it by their keepers' notes (`instance::Exit::Through`), not those
/// cut from it —, as a JSON array.
fn carried_by(instances: &[crate::instance::Running], zone: &str) -> String {
    array(
        instances
            .iter()
            .filter(|i| {
                i.network == zone
                    && crate::instance::exit_of(&i.dir)
                        == Some(crate::instance::Exit::Through(zone.to_owned()))
            })
            .map(|i| string(&i.id))
            .collect(),
    )
}

/// What an instance's way out is, as `status --json` says it: `exit`
/// (`"through"` or `"none"`) and `why` there is none (`null` while there is
/// one) — its keeper's note (`instance::Exit`). No note: `offline` for an
/// instance with no network, `null` for one that has not said yet.
pub fn exit_fields(exit: Option<crate::instance::Exit>, network: &str) -> (String, String) {
    match exit {
        Some(crate::instance::Exit::Through(_)) => (string("through"), "null".to_owned()),
        Some(crate::instance::Exit::Cut(why)) => (string("none"), string(&why)),
        None if network == crate::launch::OFFLINE => (string("none"), string("offline")),
        None => (string("none"), "null".to_owned()),
    }
}

/// One running container instance (`crate::instance`, the container design
/// of 2026-09-27): its runtime facts. Its way out since stage 2 (a zone, or
/// none); its own pid namespace since stage 3 (`pid_namespace`: false for
/// an instance an earlier build started — `pid_namespace` is then among
/// what it needs a restart for); no switch yet.
pub fn instance(tools: &Tools, running: &crate::instance::Running) -> String {
    let (exit, why) = exit_fields(crate::instance::exit_of(&running.dir), &running.network);
    let container = match crate::instance::who_of(&running.id) {
        crate::origin::Who::Container(name) => string(&name),
        crate::origin::Who::Main => string(crate::instance::MAIN),
        crate::origin::Who::Unknown => "null".to_owned(),
    };
    let since = fs::metadata(running.dir.join(crate::instance::READY))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or_else(
            || "null".to_owned(),
            |d| string(&crate::journal::utc(d.as_secs())),
        );
    let build = crate::build::string(crate::build::age(
        &running.dir,
        &crate::build::installed(tools),
    ));
    let pid_namespace = crate::instance::own_pid_namespace(running.pid);
    // What it came up with against what is set now — for its container's
    // programs (stage 5: a container's own over its network's).
    let restart_needed = crate::hermetic::restart_needed_of(
        &running.dir,
        &tools.state.join(&running.network),
        &tools.config,
        &running.network,
        &crate::instance::who_of(&running.id),
    )
    .map(|mut names| {
        if !pid_namespace {
            names.push(PID_NAMESPACE);
        }
        names
    })
    .map_or("null".to_owned(), |names| {
        array(names.into_iter().map(string).collect())
    });
    // Its live launches, by the registry.
    let launches = crate::instance::container_of(&running.id).map_or(0, |name| {
        let dir = tools.state.join(".running").join(name);
        crate::registry::live_records(&dir, &|pid| {
            crate::registry::alive(&tools.state.join(".running"), pid)
        })
        .iter()
        .filter(|(_, r)| r.zone == running.network)
        .count()
    });
    // Its epoch and whether it can be switched live (stage 4,
    // `crate::epoch`), as its keeper noted them.
    let epoch = crate::epoch::read(&running.dir).map_or(1, |e| e.n);
    let live_switch = live_switch(crate::epoch::read_live(&running.dir));
    let switch = switch_state(crate::instance::switch_of(&running.dir));
    format!(
        "{{\"id\":{},\"container\":{container},\"network\":{},\"exit\":{exit},\
         \"why\":{why},\"up\":true,\"pid\":{},\"since\":{since},\"epoch\":{epoch},\
         \"pid_namespace\":{pid_namespace},\"build\":{build},\"restart_needed\":{restart_needed},\
         \"programs\":{launches},\"live_switch\":{live_switch},\"switch\":{switch}}}",
        string(&running.id),
        string(&running.network),
        running.pid
    )
}

/// `{state, from, to}` of a live switch under way or failed (stage 4,
/// `instance::SWITCH`): `cutting`, `attaching` or `failed`; `idle` with
/// `from` and `to` null when there is none.
pub fn switch_state(noted: Option<(String, String, String)>) -> String {
    match noted {
        Some((state, from, to)) => format!(
            "{{\"state\":{},\"from\":{},\"to\":{}}}",
            string(&state),
            string(&from),
            string(&to)
        ),
        None => "{\"state\":\"idle\",\"from\":null,\"to\":null}".to_owned(),
    }
}

/// `{available, reason}` of an instance's live switch (stage 4): its
/// keeper's note ([`crate::epoch::LiveSwitch`]); none — an instance of a
/// previous build — is `previous-build`.
pub fn live_switch(live: Option<crate::epoch::LiveSwitch>) -> String {
    let (available, reason) = match &live {
        Some(live) => (live.reason().is_none(), live.reason()),
        None => (false, Some("previous-build")),
    };
    format!(
        "{{\"available\":{available},\"reason\":{}}}",
        reason.map_or_else(|| "null".to_owned(), string)
    )
}

/// What an instance of an earlier build needs a restart for besides its
/// settings (`restart_needed`): a pid namespace of its own (stage 3).
pub const PID_NAMESPACE: &str = "pid_namespace";

/// Every running container instance ([`instance`]).
pub fn instances(tools: &Tools) -> String {
    array(
        crate::instance::running(&tools.state)
            .iter()
            .map(|i| instance(tools, i))
            .collect(),
    )
}

/// One trusted certificate, with what openssl can tell about it.
fn trust(tools: &Tools, c: &Container) -> String {
    let declared = c
        .declared_trust
        .iter()
        .flat_map(|dir| crate::trust::stored(dir.as_path()))
        .map(|cert| (cert, Source::Nix));
    let local = crate::trust::stored(&c.trust_dir())
        .into_iter()
        .map(|cert| (cert, Source::Local));
    array(
        declared
            .chain(local)
            .map(|(cert, source)| {
                let info = crate::cli::certificate_info(tools, &cert.path, "PEM").ok();
                let field = |f: fn(&crate::trust::CertInfo) -> &str| {
                    info.as_ref().map_or("null".to_owned(), |i| string(f(i)))
                };
                format!(
                    "{{\"sha256\":{},\"subject\":{},\"not_after\":{},\"source\":{}}}",
                    string(&cert.sha256),
                    field(|i| i.subject.as_str()),
                    field(|i| i.not_after.as_str()),
                    string(source.as_str())
                )
            })
            .collect(),
    )
}

pub fn container(tools: &Tools, c: &Container) -> String {
    let home_source = c.home_source;
    let apps = array(
        c.apps
            .iter()
            .map(|app| sourced_str(&app.value, app.source))
            .collect(),
    );
    // A private home has permissions of its own; an overlay is the real home
    // with its data split, and has none to speak of; the main home is the
    // real one.
    let permissions = match c.home {
        Home::Layer | Home::Main => "null".to_owned(),
        Home::Private => {
            let file = c.policy.join("perms");
            let (perms, source) = match fs::read_to_string(&file) {
                Ok(text) => (Perms::parse(&text), Source::Local),
                Err(_) => (Perms::default(), Source::Default),
            };
            let filesystem: Vec<String> = [
                (perms.downloads, "downloads"),
                (perms.documents, "documents"),
                (perms.pictures, "pictures"),
                (perms.home, "home"),
            ]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, name)| string(name))
            .collect();
            // `expires`: the end of a grant's term, `null` for a grant without one.
            let paths = array(
                c.paths
                    .iter()
                    .map(|p| {
                        let expires = c
                            .expires
                            .iter()
                            .find(|(path, _)| *path == p.value)
                            .map_or("null".to_owned(), |(_, until)| {
                                string(&crate::journal::utc(*until))
                            });
                        format!(
                            "{{\"value\":{},\"source\":{},\"expires\":{expires}}}",
                            string(&p.value.to_string_lossy()),
                            string(p.source.as_str())
                        )
                    })
                    .collect(),
            );
            format!(
                "{{\"filesystem\":{},\"x11\":{},\"paths\":{paths}}}",
                sourced(array(filesystem), source),
                sourced(perms.x11.to_string(), source)
            )
        }
    };
    let (wayland, wayland_source) = setting(tools, "wayland-sandbox", "on");
    let compositor = if wayland == "on" {
        "restricted"
    } else {
        "full"
    };
    // Its own colour, or none: the zone's is the network's (`networks[]`).
    let frame_color = match &c.frame_color {
        Some(color) => sourced_str(&color.value, color.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    // Its own microphone and screen cast settings, or none: the zone's
    // (`networks[]`).
    let microphone = match &c.microphone {
        Some(m) => sourced_str(m.value.as_str(), m.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    let screencast = match &c.screencast {
        Some(m) => sourced_str(m.value.as_str(), m.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    let camera = match &c.camera {
        Some(m) => sourced(m.value.to_string(), m.source),
        None => sourced("null".to_owned(), Source::Default),
    };
    // The devices it is given (`crate::devices`), each with where from.
    let devices = array(
        c.devices
            .iter()
            .map(|d| sourced_str(&d.value, d.source))
            .collect(),
    );
    // Its rules for links (`crate::links`): the program its links of a
    // scheme open in without the choice of one, each with where from.
    let links = array(
        c.links
            .iter()
            .map(|l| {
                format!(
                    "{{\"scheme\":{},\"program\":{},\"source\":{}}}",
                    string(&l.value.0),
                    string(&l.value.1),
                    string(l.source.as_str())
                )
            })
            .collect(),
    );
    // Its running instances' ids (`crate::instance`): one, or one per
    // network for a container of the main home.
    let instances = array(
        crate::instance::running(&tools.state)
            .iter()
            .filter(|i| crate::instance::container_of(&i.id) == Some(c.name.as_str()))
            .map(|i| string(&i.id))
            .collect(),
    );
    // What becomes of its programs' asking for the focus (`crate::wl_focus`).
    let focus = sourced_str(c.focus.value.as_str(), c.focus.source);
    // Its own zone-level permissions (stage 5 of the container design,
    // `hermetic::CONTAINER_KEYS`): each `null` where it has none of its own
    // — its network's then (`networks[]`), as for the camera. In force from
    // its instance's next start (`instances[].restart_needed`).
    let own = crate::hermetic::CONTAINER_KEYS
        .iter()
        .map(|(key, _)| {
            let value = match crate::hermetic::container_own(&tools.config, &c.name, key) {
                Some((on, source)) => sourced(on.to_string(), source),
                None => sourced("null".to_owned(), Source::Default),
            };
            format!("{}:{value}", string(key))
        })
        .collect::<Vec<String>>()
        .join(",");
    format!(
        "{{\"name\":{},\"selector\":{},\"home\":{},\"network\":{},\"apps\":{apps},\
         \"permissions\":{permissions},\"compositor\":{},\"trust\":{},\"running\":{},\
         \"x11\":{},\"frame_color\":{frame_color},\"microphone\":{microphone},\"screencast\":{screencast},\"camera\":{camera},\"devices\":{devices},\"links\":{links},\"focus\":{focus},{own},\"instances\":{instances}}}",
        string(&c.name),
        string(&c.selector()),
        sourced_str(c.home.as_str(), home_source),
        sourced_str(c.network.value.as_str(), c.network.source),
        sourced_str(compositor, wayland_source),
        trust(tools, c),
        running(tools, c),
        sourced(c.x11.value.to_string(), c.x11.source)
    )
}

pub fn containers(tools: &Tools) -> String {
    array(
        container::load_all(tools)
            .iter()
            .map(|c| container(tools, c))
            .collect(),
    )
}

/// Every program the picker knows about: labelled, or assigned to a
/// container — by the picker or in Nix. Its `network` is its container's.
pub fn apps(tools: &Tools) -> String {
    let names = |sub: &str| -> Vec<String> {
        visible_entries(&tools.state.join(sub))
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect()
    };
    let all = container::load_all(tools);
    let mut ids: Vec<String> = names(".labels");
    ids.extend(names(".pinnedprofile"));
    for c in &all {
        ids.extend(c.apps.iter().map(|a| a.value.clone()));
    }
    ids.sort();
    ids.dedup();

    array(
        ids.iter()
            .map(|id| {
                let label = read_setting(&tools.state.join(".labels").join(id))
                    .map_or("null".to_owned(), |l| string(&l));
                let assigned = all.iter().find_map(|c| {
                    c.apps
                        .iter()
                        .find(|a| &a.value == id)
                        .map(|a| sourced_str(&c.selector(), a.source))
                });
                let assigned = assigned.unwrap_or_else(|| sourced("null".to_owned(), Source::Default));
                // The network is the container's (`docs/PERMISSIONS.md`
                // §11.8): the one the program's container is bound to.
                let network = all
                    .iter()
                    .find(|c| c.apps.iter().any(|a| &a.value == id))
                    .and_then(|c| match &c.network.value {
                        container::Network::Named(n) => Some(sourced_str(n, c.network.source)),
                        container::Network::Ask => None,
                    })
                    .unwrap_or_else(|| sourced("null".to_owned(), Source::Default));
                format!(
                    "{{\"id\":{},\"label\":{label},\"container\":{assigned},\"network\":{network}}}",
                    string(id)
                )
            })
            .collect(),
    )
}

/// `vpn-zone status --bar`: one JSON line in the shape status bars take
/// (`text`, `tooltip`, `class`, as waybar's `return-type: json` reads it).
///
/// The text names the zones that are up, a dead tunnel marked; the class is
/// the worst of them — `dead` when a tunnel `vpn-zone watch` found dead, `up`
/// when zones are up and none is, `none` when no zone is up. Nothing here reads
/// the network itself: the watcher's memory and the status mirrors only, so a
/// bar polling every second costs nothing.
pub fn bar(tools: &Tools) -> String {
    let mut up = Vec::new();
    let mut dead = false;
    for dir in visible_entries(&tools.state) {
        let Some(name) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if zone_kind(&dir).is_none() || zone_pid(&tools.state, name.as_ref()).is_none() {
            continue;
        }
        let verdict = fs::read_to_string(tools.state.join(crate::watch::WATCH_DIR).join(&name))
            .ok()
            .and_then(|t| crate::watch::parse_memory(&t))
            .map(|(_, v)| v);
        let is_dead = verdict == Some(crate::watch::Verdict::Dead);
        dead |= is_dead;
        up.push(if is_dead { format!("{name} ✗") } else { name });
    }
    let class = if dead {
        "dead"
    } else if up.is_empty() {
        "none"
    } else {
        "up"
    };
    let mut tooltip = if up.is_empty() {
        "cellward: ни одна зона не поднята".to_owned()
    } else if dead {
        "cellward: туннель не отвечает (✗)".to_owned()
    } else {
        "cellward: поднятые зоны".to_owned()
    };
    // What runs with nothing of a zone around it is to be seen, not looked
    // for: a mark in the text and the programs in the tooltip.
    let unconfined = unconfined_launches(&tools.state);
    let mut text = up.join(" ");
    if !unconfined.is_empty() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&format!("⚠{}", unconfined.len()));
        tooltip.push_str(&format!(
            "\nБез ограничений (⚠) сейчас: {}",
            unconfined.join(", ")
        ));
    }
    format!(
        "{{\"text\":{},\"tooltip\":{},\"class\":{},\"unconfined\":{}}}",
        string(&text),
        string(&tooltip),
        string(class),
        unconfined.len()
    )
}

/// The programs running in `unconfined` right now, by the registry: one name
/// per live pid (a launch is recorded under its id and its binary both).
pub fn unconfined_launches(state: &std::path::Path) -> Vec<String> {
    let mut seen = std::collections::BTreeMap::new();
    let running = state.join(".running");
    for dir in crate::registry::dirs(&running) {
        for file in visible_entries(&dir) {
            if !file.is_file() {
                continue;
            }
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            let name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            for record in text.lines().filter_map(crate::registry::parse_record) {
                if record.zone == crate::launch::UNCONFINED
                    && crate::registry::alive(&running, record.pid)
                {
                    seen.entry(record.pid).or_insert_with(|| name.clone());
                }
            }
        }
    }
    seen.into_values().collect()
}

/// The whole document of `vpn-zone status --json`.
pub fn document(tools: &Tools) -> String {
    // The host ids of the zones' sockets on the host, for a host egress policy
    // (`meta skuid`/`meta skgid`); `null` without subordinate ranges.
    let uplink_owner = crate::zone::uplink_owner().map_or("null".to_owned(), |(uid, gid)| {
        format!("{{\"uid\":{uid},\"gid\":{gid}}}")
    });
    format!(
        "{{\"schema_version\":{SCHEMA_VERSION},\"defaults\":{},\"networks\":{},\"containers\":{},\"apps\":{},\"system_networks\":{},\"uplink_owner\":{uplink_owner},\"instances\":{}}}",
        defaults(tools),
        networks(tools),
        containers(tools),
        apps(tools),
        system_networks(),
        instances(tools)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An instance's way out as its keeper noted it (stage 2): through its
    /// zone, or none and why.
    #[test]
    fn an_instances_exit_is_its_keepers_note() {
        use crate::instance::Exit;
        assert_eq!(
            exit_fields(Some(Exit::Through("nl".to_owned())), "nl"),
            ("\"through\"".to_owned(), "null".to_owned())
        );
        assert_eq!(
            exit_fields(Some(Exit::Cut("zone-down".to_owned())), "nl"),
            ("\"none\"".to_owned(), "\"zone-down\"".to_owned())
        );
        assert_eq!(
            exit_fields(None, "offline"),
            ("\"none\"".to_owned(), "\"offline\"".to_owned())
        );
        assert_eq!(
            exit_fields(None, "nl"),
            ("\"none\"".to_owned(), "null".to_owned())
        );
    }

    /// Stage 4: whether an instance can be switched live, as its keeper
    /// noted it.
    #[test]
    fn an_instances_live_switch_is_its_keepers_note() {
        use crate::epoch::LiveSwitch;
        assert_eq!(
            live_switch(Some(LiveSwitch::Yes)),
            "{\"available\":true,\"reason\":null}"
        );
        assert_eq!(
            live_switch(Some(LiveSwitch::No("outside".to_owned()))),
            "{\"available\":false,\"reason\":\"outside\"}"
        );
        assert_eq!(
            live_switch(None),
            "{\"available\":false,\"reason\":\"previous-build\"}"
        );
        assert_eq!(
            switch_state(None),
            "{\"state\":\"idle\",\"from\":null,\"to\":null}"
        );
        assert_eq!(
            switch_state(Some((
                "failed".to_owned(),
                "nl".to_owned(),
                "de".to_owned()
            ))),
            "{\"state\":\"failed\",\"from\":\"nl\",\"to\":\"de\"}"
        );
    }

    #[test]
    fn strings_are_escaped_the_json_way() {
        assert_eq!(string("plain"), "\"plain\"");
        assert_eq!(string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(string("line\nnext\ttab"), "\"line\\nnext\\ttab\"");
        assert_eq!(string("\u{1}"), "\"\\u0001\"");
        assert_eq!(string("\u{7f}\u{9b}"), "\"\\u007f\\u009b\"");
        assert_eq!(string("Огненный лис"), "\"Огненный лис\"");
    }

    #[test]
    fn a_sourced_value_carries_its_origin() {
        assert_eq!(
            sourced_str("nl", Source::Nix),
            "{\"value\":\"nl\",\"source\":\"nix\"}"
        );
        assert_eq!(
            sourced("true".to_owned(), Source::Default),
            "{\"value\":true,\"source\":\"default\"}"
        );
        assert_eq!(array(vec![]), "[]");
        assert_eq!(array(vec!["1".into(), "2".into()]), "[1,2]");
    }

    #[test]
    fn a_system_zone_says_only_what_its_reader_may_know() {
        use crate::system::RunState;

        let closed = system_network("nl", "wireguard", "nix", &RunState::Closed, None);
        for part in [
            "\"name\":\"nl\"",
            "\"netns\":\"/run/netns/vz-nl\"",
            "\"source\":\"nix\"",
            "\"up\":null",
            "\"tunnel_alive\":null",
            "\"rx_bytes\":null",
            "\"readable\":false",
        ] {
            assert!(closed.contains(part), "{part} in {closed}");
        }

        let down = system_network("nl", "wireguard", "nix", &RunState::Down, None);
        assert!(down.contains("\"up\":false"), "{down}");
        assert!(down.contains("\"readable\":true"), "{down}");
        assert!(down.contains("\"tunnel_alive\":null"), "{down}");

        let mirror = "interface: awg0\n\npeer: abc=\n  endpoint: 192.0.2.1:51820\n  \
                      latest handshake: 12 seconds ago\n  \
                      transfer: 1.00 KiB received, 2.00 KiB sent\n";
        let up = system_network(
            "nl",
            "wireguard",
            "nix",
            &RunState::Up(Some(mirror.to_owned())),
            None,
        );
        assert!(up.contains("\"up\":true"), "{up}");
        assert!(up.contains("\"uplink\":null"), "{up}");
        assert!(up.contains("\"tunnel_alive\":true"), "{up}");
        assert!(up.contains("\"handshake_age_s\":12"), "{up}");
        assert!(up.contains("\"rx_bytes\":1024"), "{up}");

        let plain = system_network(
            "pl",
            "plain",
            "local",
            &RunState::Up(Some(
                "interface: awg0\n  backend: plain\n  connected: yes\n".to_owned(),
            )),
            Some("enp4s0"),
        );
        assert!(plain.contains("\"kind\":\"plain\""), "{plain}");
        assert!(plain.contains("\"uplink\":\"enp4s0\""), "{plain}");
        assert!(plain.contains("\"source\":\"local\""), "{plain}");
        assert!(plain.contains("\"tunnel_alive\":true"), "{plain}");

        // Up, before the holder has written its first mirror.
        let early = system_network("nl", "wireguard", "nix", &RunState::Up(None), None);
        assert!(early.contains("\"up\":true"), "{early}");
        assert!(early.contains("\"tunnel_alive\":null"), "{early}");
    }
}
