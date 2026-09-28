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
//! network⇥<name>⇥<kind: zone|offline|unconfined>⇥<up: 0|1>⇥<#rrggbb>
//! instance⇥<id>⇥<container|->⇥<network>⇥<out bytes>⇥<in bytes>⇥<since>
//! today⇥<container>⇥<network>⇥<out bytes>⇥<in bytes>
//! month⇥<container>⇥<network>⇥<out bytes>⇥<in bytes>
//! ```
//!
//! The counts are `crate::traffic`'s: an instance's since it came up, and
//! the summaries of today and of the last 30 days.

use std::ffi::OsStr;
use std::path::Path;

use crate::container::{Home, Network};
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
    for zone in zones(&tools.state) {
        let up = crate::cli::zone_pid(&tools.state, OsStr::new(&zone)).is_some();
        line(&[
            "network",
            &zone,
            "zone",
            if up { "1" } else { "0" },
            &color(&zone),
        ]);
    }
    line(&[
        "network",
        crate::launch::OFFLINE,
        "offline",
        "1",
        &color(crate::launch::OFFLINE),
    ]);
    line(&[
        "network",
        crate::launch::UNCONFINED,
        "unconfined",
        "1",
        &color(crate::launch::UNCONFINED),
    ]);
    for i in crate::instance::running(&tools.state) {
        let container = crate::instance::container_of(&i.id)
            .unwrap_or("-")
            .to_owned();
        let Some(c) = crate::traffic::read(&i.dir) else {
            continue;
        };
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
    for (kind, days) in [("today", 1), ("month", 30)] {
        for ((who, net), (o, i)) in crate::traffic::used_over(&tools.state, days) {
            line(&[kind, &who, &net, &o.to_string(), &i.to_string()]);
        }
    }
    out
}

/// `cellward _panel`: the panel's lines on stdout.
pub fn run(tools: &Tools) -> u8 {
    print!("{}", data(tools));
    0
}
