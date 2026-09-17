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
use crate::profile::proc_is_alive;
use crate::registry;
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
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
    let (container, container_source) = setting(tools, "default-profile", "ask");
    let (mode, mode_source) = setting(tools, "mode", "picker");
    let (wayland, wayland_source) = setting(tools, "wayland-sandbox", "on");
    let (autostart, autostart_source) = setting(tools, "autostart", "offline");
    let (user_entries, user_entries_source) = setting(tools, "user-entries", "take-over");
    format!(
        "{{\"network\":{},\"container\":{},\"launcher_mode\":{},\"compositor_restriction\":{},\
         \"autostart_unassigned\":{},\"user_entries\":{}}}",
        sourced_str(&network, network_source),
        sourced_str(&container, container_source),
        sourced_str(&mode, mode_source),
        sourced((wayland == "on").to_string(), wayland_source),
        sourced_str(&autostart, autostart_source),
        sourced_str(&user_entries, user_entries_source)
    )
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
        _ => "wireguard",
    })
}

pub fn networks(tools: &Tools) -> String {
    let mut items = vec![
        "{\"name\":\"direct\",\"kind\":\"direct\",\"source\":\"default\",\"up\":true,\
         \"locked\":false,\"tunnel_alive\":null}"
            .to_owned(),
    ];
    let mut offline_listed = false;
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
        offline_listed |= name == "offline";
        let up = zone_pid(&tools.state, dir.file_name().unwrap_or_default()).is_some();
        let alive = if up && kind != "offline" {
            match fs::read_to_string(dir.join("status")) {
                Ok(mirror) => liveness_line(&mirror).is_some().to_string(),
                Err(_) => "null".to_owned(),
            }
        } else {
            "null".to_owned()
        };
        let source = if kind == "offline" {
            "default"
        } else {
            "local"
        };
        items.push(format!(
            "{{\"name\":{},\"kind\":\"{kind}\",\"source\":\"{source}\",\"up\":{up},\"locked\":{},\"tunnel_alive\":{alive}}}",
            string(&name),
            dir.join(NO_ESCAPE).exists()
        ));
    }
    if !offline_listed {
        items.push(
            "{\"name\":\"offline\",\"kind\":\"offline\",\"source\":\"default\",\"up\":false,\
             \"locked\":false,\"tunnel_alive\":null}"
                .to_owned(),
        );
    }
    array(items)
}

/// The live launches of a container: `{app, pid, network}`.
fn running(tools: &Tools, c: &Container) -> String {
    let base = tools.state.join(".running");
    let records = match c.home {
        Home::Overlay => registry::live_records(&base.join(&c.name), &proc_is_alive),
        Home::Private => {
            let selector = c.selector();
            registry::live_records(&base.join(registry::MAIN), &proc_is_alive)
                .into_iter()
                .filter(|(_, r)| r.selector == selector)
                .collect()
        }
    };
    array(
        records
            .iter()
            .map(|(app, r)| {
                format!(
                    "{{\"app\":{},\"pid\":{},\"network\":{}}}",
                    string(app),
                    r.pid,
                    string(&r.zone)
                )
            })
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
    let home_source = if c.dir.is_dir() {
        Source::Local
    } else {
        Source::Nix
    };
    let apps = array(
        c.apps
            .iter()
            .map(|app| sourced_str(&app.value, app.source))
            .collect(),
    );
    // A private home has permissions of its own; an overlay is the real home
    // with its data split, and has none to speak of.
    let permissions = match c.home {
        Home::Overlay => "null".to_owned(),
        Home::Private => {
            let file = c.dir.join("perms");
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
            let paths = array(
                c.paths
                    .iter()
                    .map(|p| sourced_str(&p.value.to_string_lossy(), p.source))
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
    format!(
        "{{\"name\":{},\"selector\":{},\"home\":{},\"network\":{},\"apps\":{apps},\
         \"permissions\":{permissions},\"compositor\":{},\"trust\":{},\"running\":{}}}",
        string(&c.name),
        string(&c.selector()),
        sourced_str(c.home.as_str(), home_source),
        sourced_str(c.network.value.as_str(), c.network.source),
        sourced_str(compositor, wayland_source),
        trust(tools, c),
        running(tools, c)
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

/// Every program the picker knows about: labelled, pinned to a network, or
/// assigned to a container — by the picker or in Nix.
pub fn apps(tools: &Tools) -> String {
    let names = |sub: &str| -> Vec<String> {
        visible_entries(&tools.state.join(sub))
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect()
    };
    let all = container::load_all(tools);
    let mut ids: Vec<String> = names(".labels");
    ids.extend(names(".pinned"));
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
                let network = match read_setting(&tools.state.join(".pinned").join(id)) {
                    Some(net) if !net.is_empty() => sourced_str(&net, Source::Local),
                    _ => sourced("null".to_owned(), Source::Default),
                };
                format!(
                    "{{\"id\":{},\"label\":{label},\"container\":{assigned},\"network\":{network}}}",
                    string(id)
                )
            })
            .collect(),
    )
}

/// The whole document of `vpn-zone status --json`.
pub fn document(tools: &Tools) -> String {
    format!(
        "{{\"schema_version\":{SCHEMA_VERSION},\"defaults\":{},\"networks\":{},\"containers\":{},\"apps\":{}}}",
        defaults(tools),
        networks(tools),
        containers(tools),
        apps(tools)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped_the_json_way() {
        assert_eq!(string("plain"), "\"plain\"");
        assert_eq!(string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(string("line\nnext\ttab"), "\"line\\nnext\\ttab\"");
        assert_eq!(string("\u{1}"), "\"\\u0001\"");
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
}
