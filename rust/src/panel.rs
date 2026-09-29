//! What the cellward window's panel shows (`vpn-zone-window panel`, the
//! containers and the network monitor, 2026-09-28): `cellward _panel`
//! prints it, the window reads it again every second and acts through the
//! ordinary verbs of `cellward` (`container set`, `container stop`, …). The
//! window keeps no state of the project's and decides nothing; this is its
//! whole view of it.
//!
//! One line per item, fields separated by a tab, nothing in a field with a
//! tab or a line break in it (`window::clean`):
//!
//! ```text
//! container⇥<name>⇥<home: private|layer|main>⇥<network|ask>⇥<#rrggbb>
//! path⇥<container>⇥<path>⇥<until: unix seconds, 0 for ever>
//! network⇥<name>⇥<kind: zone|offline|unconfined>⇥<up: 0|1>⇥<#rrggbb>⇥<locked: 0|1>⇥<tunnel>
//! instance⇥<id>⇥<container|->⇥<network>⇥<out bytes>⇥<in bytes>⇥<since>
//! flow⇥<instance id>⇥<proto>⇥<remote>⇥<remote port>⇥<name>⇥<who>⇥<out>⇥<in>⇥<last>
//! today⇥<container>⇥<network>⇥<out bytes>⇥<in bytes>
//! month⇥<container>⇥<network>⇥<out bytes>⇥<in bytes>
//! program⇥<container>⇥<program, for a person>⇥<out bytes>⇥<in bytes>
//! setting⇥<default|default-profile|mode|wayland-sandbox>⇥<value>⇥<nix|local|default>
//! pin⇥<program's key>⇥<its name>⇥<the container it goes to, or empty>
//! ```
//!
//! `<tunnel>`: what the tunnel watch last found (`crate::watch`): `alive`,
//! `idle`, `dead`, `suspect`, `unknown`, or `-` — not looked at (a zone that
//! is down, `offline`, `unconfined`).
//!
//! The counts are `crate::traffic`'s: an instance's since it came up, and
//! the summaries of today and of the last 30 days. A `flow` is one of an
//! instance's [`FLOWS_SHOWN`] latest connections (`crate::flows`): `name`
//! what a DNS answer said of the address, `who` the program that holds it
//! (`crate::owners`), each empty where none; `last` Unix seconds. A
//! `program` is what a program of a container used today, from the
//! connections' journal (`crate::connlog`).

use std::ffi::OsStr;
use std::path::Path;

use crate::container::{Home, Network};

/// How many of each instance's latest connections the panel shows.
pub const FLOWS_SHOWN: usize = 30;
use crate::tools::Tools;
use crate::window::clean;

/// A container's home, as a word.
pub fn home_word(home: Home) -> &'static str {
    match home {
        Home::Private => "private",
        Home::Layer => "layer",
        Home::Main => "main",
    }
}

/// The zones: directories of the state directory with a config.
fn zones(state: &Path) -> Vec<String> {
    let mut out: Vec<String> = crate::cli::visible_entries(state)
        .into_iter()
        .filter(|d| d.join("config.conf").is_file())
        .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
        // The host's own network has a line of its own, there or not yet.
        .filter(|n| n != crate::launch::HOST)
        .collect();
    out.sort();
    out
}

/// The panel's lines (see the module's words).
pub fn data(tools: &Tools) -> String {
    let mut out = String::new();
    let mut line = |fields: &[&str]| {
        let cleaned: Vec<String> = fields.iter().map(|f| clean(f)).collect();
        out.push_str(&cleaned.join("\t"));
        out.push('\n');
    };
    let color = |zone: &str| {
        crate::frame::zone_color(&tools.state, &tools.config, zone)
            .0
            .hex()
    };
    let mut containers = crate::container::load_all(tools);
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    for c in &containers {
        let network = match &c.network.value {
            Network::Ask => "ask".to_owned(),
            Network::Named(n) => crate::launch::network_name(n).to_owned(),
        };
        let own = c.frame_color.as_ref().map(|s| s.value.clone());
        let shown = own.unwrap_or_else(|| {
            if network == "ask" {
                color(crate::launch::OFFLINE)
            } else {
                color(&network)
            }
        });
        line(&["container", &c.name, home_word(c.home), &network, &shown]);
        for p in &c.paths {
            let path = p.value.to_string_lossy();
            let until = c
                .expires
                .iter()
                .find(|(q, _)| *q == p.value)
                .map_or(0, |(_, t)| *t);
            line(&["path", &c.name, &path, &until.to_string()]);
        }
    }
    let locked = |zone: &str| {
        if tools
            .state
            .join(zone)
            .join(crate::launch::NO_ESCAPE)
            .exists()
        {
            "1"
        } else {
            "0"
        }
    };
    let tunnel = |zone: &str, up: bool| {
        if !up {
            return "-";
        }
        std::fs::read_to_string(tools.state.join(crate::watch::WATCH_DIR).join(zone))
            .ok()
            .and_then(|t| crate::watch::parse_memory(&t))
            .map_or("unknown", |(_, v)| v.as_str())
    };
    for zone in zones(&tools.state) {
        let up = crate::cli::zone_pid(&tools.state, OsStr::new(&zone)).is_some();
        line(&[
            "network",
            &zone,
            "zone",
            if up { "1" } else { "0" },
            &color(&zone),
            locked(&zone),
            tunnel(&zone, up),
        ]);
    }
    line(&[
        "network",
        crate::launch::OFFLINE,
        "offline",
        "1",
        &color(crate::launch::OFFLINE),
        locked(crate::launch::OFFLINE),
        "-",
    ]);
    {
        let up = crate::cli::zone_pid(&tools.state, OsStr::new(crate::launch::HOST)).is_some();
        line(&[
            "network",
            crate::launch::HOST,
            "host",
            if up { "1" } else { "0" },
            &color(crate::launch::HOST),
            locked(crate::launch::HOST),
            "-",
        ]);
    }
    line(&[
        "network",
        crate::launch::UNCONFINED,
        "unconfined",
        "1",
        &color(crate::launch::UNCONFINED),
        "0",
        "-",
    ]);
    let procs = crate::owners::Procs::scan();
    for i in crate::instance::running(&tools.state) {
        let container = crate::instance::container_of(&i.id)
            .unwrap_or("-")
            .to_owned();
        if let Some(c) = crate::traffic::read(&i.dir) {
            line(&[
                "instance",
                &i.id,
                &container,
                &i.network,
                &c.out_bytes.to_string(),
                &c.in_bytes.to_string(),
                &c.since.to_string(),
            ]);
        }
        for fields in crate::flows::panel_lines(tools, i, &procs, FLOWS_SHOWN) {
            let mut all = vec!["flow"];
            all.extend(fields.iter().map(String::as_str));
            line(&all);
        }
    }
    for (kind, days) in [("today", 1), ("month", 30)] {
        for ((who, net), (o, i)) in crate::traffic::used_over(&tools.state, days) {
            line(&[kind, &who, &net, &o.to_string(), &i.to_string()]);
        }
    }
    for ((who, program), (o, i)) in crate::connlog::used_today(&tools.state) {
        let name = crate::connlog::program_text(&tools.state, &program);
        line(&["program", &who, &name, &o.to_string(), &i.to_string()]);
    }
    for (name, fallback) in [
        ("default", "offline"),
        ("default-profile", "ask"),
        ("mode", "picker"),
        ("wayland-sandbox", "on"),
    ] {
        let (value, source) = crate::cli::setting(tools, name)
            .unwrap_or_else(|| (fallback.to_owned(), crate::container::Source::Default));
        line(&["setting", name, &value, source.as_str()]);
    }
    let profile_pins = tools.state.join(".pinnedprofile");
    for key in crate::gui::pinned_keys(&tools.state.join(".pinned"), &profile_pins) {
        let label = crate::cli::read_setting(&tools.state.join(".labels").join(&key))
            .unwrap_or_else(|| key.clone());
        let to = crate::cli::read_setting(&profile_pins.join(&key)).unwrap_or_default();
        line(&["pin", &key, &label, &to]);
    }
    out
}

/// `cellward _panel`: the panel's lines on stdout.
pub fn run(tools: &Tools) -> u8 {
    print!("{}", data(tools));
    0
}
