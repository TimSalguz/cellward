//! **Схема** of the cellward window, as a metro: `cellward scheme --lines`
//! (`rust/src/scheme.rs`) — every flow and every kind of packet, each a
//! line from its source to its end through the stations it crosses.
//!
//! The layout: columns, the layers a packet crosses outside in; each row a
//! lane straight across its zone's band, every column on the same lanes. A
//! nested VPN advances through another encryptor/uplink pair, then reaches
//! the servers from the outermost one inward.
//! The host's one cable (the interface, the gateway, the unknown beyond)
//! packs the zones' lanes together and lets them go again — the only bends
//! there are, gentle, in the room left before it and after it. Frames: the
//! machine, each network of the host its own, the unknown beyond.
//!
//! A line's colour says who can read it: grey only the machine, blue
//! nobody (the tunnel), dark the server, red a stranger (dashed). Dotted:
//! drawn by design, not seen yet. A tube: the lines of a zone that go
//! together between two stations (the tunnel's blue).

use std::collections::HashMap;

use iced::alignment::{Horizontal, Vertical};
use iced::widget::canvas::{self, Frame, Geometry, LineDash, Path, Stroke, Text};
use iced::widget::text::Shaping;
use iced::{font, mouse, Color, Font, Point, Rectangle, Renderer, Size, Theme};

/// A station: a program, a network, a gate, a translator, a server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Place {
    pub id: String,
    pub name: String,
    pub tech: String,
    pub gate: bool,
    pub unknown: bool,
    pub translates: bool,
}

/// One stretch of a row: where to, what goes, in what, who can read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hop {
    pub to: String,
    pub what: String,
    pub wrap: String,
    /// `machine`, `nobody`, `server`, `stranger`.
    pub sees: String,
    pub seen_by: String,
}

/// One flow, or one kind of packet, from its source to its end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub group: String,
    pub name: String,
    pub kind: String,
    pub from: String,
    /// `arrives`, `denied`, `answered`, `cut`, `leak`.
    pub end: String,
    pub end_text: String,
    pub count: u64,
    pub out_bytes: u64,
    pub in_bytes: u64,
    /// Seen so; else drawn as it would go.
    pub observed: bool,
    pub hops: Vec<Hop>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scheme {
    pub places: Vec<Place>,
    /// `(id, title)`.
    pub groups: Vec<(String, String)>,
    pub rows: Vec<Row>,
}

/// `cellward scheme --lines`; a line of another shape is skipped.
pub fn parse(text: &str) -> Scheme {
    let mut s = Scheme::default();
    let own = |v: &str| v.to_owned();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["place", id, _layer, name, tech, gate, unknown, translates] => s.places.push(Place {
                id: own(id),
                name: own(name),
                tech: own(tech),
                gate: *gate == "1",
                unknown: *unknown == "1",
                translates: *translates == "1",
            }),
            ["group", id, title] => s.groups.push((own(id), own(title))),
            ["row", id, group, name, kind, from, end, end_text, count, out, inb, observed] => {
                let num = |v: &str| v.parse().unwrap_or(0);
                s.rows.push(Row {
                    id: own(id),
                    group: own(group),
                    name: own(name),
                    kind: own(kind),
                    from: own(from),
                    end: own(end),
                    end_text: own(end_text),
                    count: num(count),
                    out_bytes: num(out),
                    in_bytes: num(inb),
                    observed: *observed == "1",
                    hops: Vec::new(),
                })
            }
            ["hop", row, to, what, wrap, sees, seen_by] => {
                if let Some(r) = s.rows.iter_mut().rev().find(|r| r.id == *row) {
                    r.hops.push(Hop {
                        to: own(to),
                        what: own(what),
                        wrap: own(wrap),
                        sees: own(sees),
                        seen_by: own(seen_by),
                    });
                }
            }
            _ => {}
        }
    }
    s
}

#[cfg(test)]
pub fn many_flows(mut scheme: Scheme, total: usize) -> Scheme {
    let flow = scheme
        .rows
        .iter()
        .find(|row| row.id == "main:nl:socat:data")
        .cloned()
        .expect("the sample's data flow");
    while scheme.rows.len() < total {
        let n = scheme.rows.len();
        let mut row = flow.clone();
        row.id = format!("synthetic:flow:{n}");
        row.name = format!("synthetic-{n}");
        scheme.rows.push(row);
    }
    scheme
}

const COLW: f32 = 172.0;
const BOXW: f32 = 136.0;
const LEFT: f32 = 18.0;
const TOP: f32 = 96.0;
const LANE: f32 = 20.0;
const HEAD: f32 = 28.0;
const GAP: f32 = 10.0;
const BGAP: f32 = 26.0;
const SLOT: f32 = 7.0;
const ROWH: f32 = 17.0;
/// Room before the cable and after it: the zones' lines bend into it and
/// out of it there, not on top of each other.
const JOIN: f32 = 150.0;

/// The columns, with two more for each carrier around an inner tunnel.
#[derive(Debug, Clone)]
struct Columns {
    labels: Vec<String>,
    carrier: HashMap<String, String>,
    outward: HashMap<String, usize>,
    host: usize,
    last: usize,
    depth: usize,
}

impl Columns {
    fn new(scheme: &Scheme) -> Self {
        let mut carrier = HashMap::new();
        for r in &scheme.rows {
            let ids = std::iter::once(r.from.as_str()).chain(r.hops.iter().map(|h| h.to.as_str()));
            fn zone<'a>(id: &'a str, kind: &str) -> Option<&'a str> {
                let mut parts = id.split(':');
                if parts.next() != Some(kind) {
                    return None;
                }
                parts.next().filter(|z| !z.is_empty())
            }
            for pair in ids.collect::<Vec<_>>().windows(2) {
                if let (Some(inner), Some(outer)) = (zone(pair[0], "out"), zone(pair[1], "tun")) {
                    if inner != outer {
                        carrier.insert(inner.to_owned(), outer.to_owned());
                    }
                }
            }
        }
        let mut outward = HashMap::new();
        for inner in carrier.keys() {
            let mut n = 0;
            let mut at = inner.as_str();
            let mut seen = vec![at];
            while let Some(outer) = carrier.get(at) {
                n += 1;
                at = outer;
                if seen.contains(&at) {
                    break;
                }
                seen.push(at);
            }
            outward.insert(inner.clone(), n);
        }
        for outer in carrier.values() {
            outward.entry(outer.clone()).or_insert(0);
        }
        let depth = outward.values().copied().max().unwrap_or(0);
        let host = 6 + 2 * depth;
        let last = host + 4 + depth;
        let mut labels = vec![
            "Программа".to_owned(),
            "Сеть контейнера".to_owned(),
            "Привратник".to_owned(),
            "Вход в зону".to_owned(),
        ];
        for level in 0..=depth {
            let suffix = if depth > 0 {
                format!(" · слой {}", level + 1)
            } else {
                String::new()
            };
            labels.push(format!("Шифратор{suffix}"));
            labels.push(format!("Выход зоны{suffix}"));
        }
        labels.extend([
            "Интерфейс хоста".to_owned(),
            "Шлюз · сеть".to_owned(),
            "⋯ дальше ⋯".to_owned(),
        ]);
        for distance in 0..=depth {
            let suffix = if depth > 0 {
                format!(" · слой {}", depth - distance + 1)
            } else {
                String::new()
            };
            labels.push(format!("Сервер VPN{suffix}"));
        }
        labels.push("Куда".to_owned());
        Self {
            labels,
            carrier,
            outward,
            host,
            last,
            depth,
        }
    }

    fn of(&self, id: &str) -> usize {
        let mut parts = id.split(':');
        let kind = parts.next().unwrap_or("");
        let zone = parts.next().unwrap_or("");
        match kind {
            "prog" => 0,
            "tap" | "wall" => 1,
            "relay" => 2,
            "passt" => 3,
            "tun" | "leak" => {
                4 + 2 * self
                    .outward
                    .get(zone)
                    .map_or(0, |distance| self.depth - distance)
            }
            "out" if !host_start(id) => {
                5 + 2 * self
                    .outward
                    .get(zone)
                    .map_or(0, |distance| self.depth - distance)
            }
            "out" | "hostdns" | "hostapps" | "hostkernel" => 5,
            "if" => self.host,
            "lan" | "link" => self.host + 1,
            "isp" | "peer" => self.host + 2,
            "vpn" => self.host + 3 + self.outward.get(zone).copied().unwrap_or(0),
            _ => self.last,
        }
    }

    fn x(&self, col: usize) -> f32 {
        let col = col.min(self.last + 1);
        let c = col as f32;
        LEFT + c * COLW
            + if col >= self.host { JOIN } else { 0.0 }
            + if col >= self.host + 3 { JOIN } else { 0.0 }
    }

    fn cable(&self, col: usize) -> bool {
        (self.host..=self.host + 2).contains(&col)
    }
}

fn host_start(id: &str) -> bool {
    matches!(id, "hostdns" | "hostapps" | "hostkernel") || id.starts_with("peer:")
}

/// The zone a row is drawn in: `~host` for the host's own.
fn zone_of(r: &Row) -> String {
    if host_start(&r.from) || r.group == "host" {
        return "~host".to_owned();
    }
    for id in std::iter::once(&r.from).chain(r.hops.iter().map(|h| &h.to)) {
        let mut parts = id.split(':');
        if let (Some("tun" | "out" | "vpn" | "leak"), Some(name)) = (parts.next(), parts.next()) {
            return name.to_owned();
        }
    }
    r.group.strip_prefix("zone:").unwrap_or(&r.group).to_owned()
}

/// A station as laid out.
#[derive(Debug, Clone)]
pub struct Station {
    pub place: Place,
    col: usize,
    x: f32,
    y: f32,
    h: f32,
    /// No row goes through it.
    idle: bool,
    /// A start or an end: a box per row, not one for all.
    end: bool,
    /// The lanes through it, top down.
    lanes: Vec<usize>,
}

/// A row as laid out: its lane, its stations, its height at each.
#[derive(Debug, Clone)]
pub struct Lane {
    pub row: usize,
    pub zone: String,
    path: Vec<usize>,
    ys: Vec<f32>,
}

#[derive(Debug, Clone)]
struct Band {
    zone: String,
    top: f32,
    bottom: f32,
}

/// The scheme, laid out.
#[derive(Debug, Clone)]
pub struct Metro {
    /// The drawing's cache key; traffic-only readings keep it.
    pub stamp: u64,
    pub scheme: Scheme,
    pub stations: Vec<Station>,
    /// Drawn top down.
    pub lanes: Vec<Lane>,
    bands: Vec<Band>,
    columns: Columns,
    pub width: f32,
    pub height: f32,
}

impl Metro {
    pub fn new(scheme: Scheme) -> Metro {
        let columns = Columns::new(&scheme);
        // The rows, by zone (the host's last); in a zone its own rows
        // first (its tunnel's handshake, what comes in), then its
        // instances', by group, those that go furthest first, the seen
        // before the drawn by design, as given within that.
        let zoned: Vec<String> = scheme.rows.iter().map(zone_of).collect();
        let mut of_group: HashMap<&str, &str> = HashMap::new();
        for (r, z) in scheme.rows.iter().zip(&zoned) {
            if *z != r.group && z != "~host" {
                of_group.entry(&r.group).or_insert(z);
            }
        }
        let zone: Vec<String> = scheme
            .rows
            .iter()
            .zip(&zoned)
            .map(|(r, z)| {
                if *z == r.group {
                    of_group
                        .get(r.group.as_str())
                        .map_or(z.clone(), |g| (*g).to_owned())
                } else {
                    z.clone()
                }
            })
            .collect();
        let mut zones: Vec<&str> = Vec::new();
        for (g, _) in &scheme.groups {
            for (i, r) in scheme.rows.iter().enumerate() {
                if r.group == *g && !zones.contains(&zone[i].as_str()) {
                    zones.push(&zone[i]);
                }
            }
        }
        let zrank = |z: &str| {
            if z == "~host" {
                usize::MAX
            } else {
                zones.iter().position(|o| *o == z).unwrap_or(usize::MAX - 1)
            }
        };
        let grank = |g: &str| {
            scheme
                .groups
                .iter()
                .position(|(id, _)| id == g)
                .unwrap_or(99)
        };
        let path_of = |r: &Row| -> Vec<String> {
            std::iter::once(r.from.clone())
                .chain(r.hops.iter().map(|h| h.to.clone()))
                .collect()
        };
        let reach = |r: &Row| {
            path_of(r)
                .iter()
                .map(|id| columns.of(id))
                .max()
                .unwrap_or(0)
        };
        let key = |i: usize, first: usize| {
            let r = &scheme.rows[i];
            (
                zrank(&zone[i]),
                !r.group.starts_with("zone:"),
                grank(&r.group),
                std::cmp::Reverse(reach(r)),
                first,
                !r.observed,
                i,
            )
        };
        let mut order: Vec<usize> = (0..scheme.rows.len()).collect();
        order.sort_by_key(|&i| key(i, 0));
        // Rows through one station, together: else its box, from its
        // first lane to its last, would cover another's between them (the
        // DHCP drawn by design, through the container's network, after the
        // wall's counters). A row goes by the station it shares first.
        let boxed = |id: &str| {
            let col = columns.of(id);
            !(col == 0 || col == columns.last || host_start(id) || columns.cable(col))
        };
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (n, &i) in order.iter().enumerate() {
            for id in path_of(&scheme.rows[i]) {
                if boxed(&id) {
                    seen.entry(id).or_insert(n);
                }
            }
        }
        let first_of = |i: usize| {
            path_of(&scheme.rows[i])
                .iter()
                .filter_map(|id| seen.get(id))
                .min()
                .copied()
                .unwrap_or(usize::MAX)
        };
        order.sort_by_key(|&i| key(i, first_of(i)));

        let mut stations: Vec<Station> = Vec::new();
        let mut by_id: HashMap<String, usize> = HashMap::new();
        // A station by its place: the one there, else a new one.
        fn station(
            stations: &mut Vec<Station>,
            by_id: &mut HashMap<String, usize>,
            columns: &Columns,
            place: Place,
        ) -> usize {
            if let Some(&at) = by_id.get(&place.id) {
                return at;
            }
            let col = columns.of(&place.id);
            let end = col == 0 || col == columns.last || host_start(&place.id);
            by_id.insert(place.id.clone(), stations.len());
            stations.push(Station {
                place,
                col,
                x: columns.x(col) + (COLW - BOXW) / 2.0,
                y: 0.0,
                h: 0.0,
                idle: false,
                end,
                lanes: Vec::new(),
            });
            stations.len() - 1
        }
        for p in &scheme.places {
            station(&mut stations, &mut by_id, &columns, p.clone());
        }
        let mut lanes: Vec<Lane> = Vec::new();
        for &i in &order {
            let mut path = Vec::new();
            for id in path_of(&scheme.rows[i]) {
                let place = Place {
                    name: id.clone(),
                    id,
                    ..Place::default()
                };
                let at = station(&mut stations, &mut by_id, &columns, place);
                let lane = lanes.len();
                if !stations[at].lanes.contains(&lane) {
                    stations[at].lanes.push(lane);
                }
                path.push(at);
            }
            lanes.push(Lane {
                row: i,
                zone: zone[i].clone(),
                path,
                ys: Vec::new(),
            });
        }

        // The lanes, top down: a station's next zone's lanes below its
        // box; the zones' bands apart.
        let mut lane_y = vec![0.0; lanes.len()];
        let mut last: HashMap<usize, (usize, f32)> = HashMap::new();
        let mut bands: Vec<Band> = Vec::new();
        let mut y = TOP + HEAD;
        for (n, lane) in lanes.iter().enumerate() {
            if bands.last().is_none_or(|b| b.zone != lane.zone) {
                if !bands.is_empty() {
                    y += BGAP;
                }
                bands.push(Band {
                    zone: lane.zone.clone(),
                    top: y,
                    bottom: y,
                });
            }
            let packed = |s: &Station| s.end || columns.cable(s.col);
            for &at in &lane.path {
                let s = &stations[at];
                if packed(s) {
                    continue;
                }
                if let Some(&(before, by)) = last.get(&s.col) {
                    if before != at {
                        y = y.max(by + 8.0 + GAP + HEAD);
                    }
                }
            }
            lane_y[n] = y;
            for &at in &lane.path {
                if !packed(&stations[at]) {
                    last.insert(stations[at].col, (at, y));
                }
            }
            if let Some(b) = bands.last_mut() {
                b.bottom = y;
            }
            y += LANE;
        }
        let mut bottom = y;

        // Each station's box; a lane's height at each.
        let mut at_station: HashMap<(usize, usize), f32> = HashMap::new();
        for (at, s) in stations.iter_mut().enumerate() {
            if s.lanes.is_empty() {
                s.idle = true;
                continue;
            }
            s.lanes.sort_by(|a, b| lane_y[*a].total_cmp(&lane_y[*b]));
            let top = lane_y[s.lanes[0]];
            let low = lane_y[*s.lanes.last().unwrap_or(&s.lanes[0])];
            if s.end {
                s.y = top - ROWH / 2.0;
                s.h = low - top + ROWH;
            } else if !columns.cable(s.col) {
                s.y = top - HEAD - 4.0;
                s.h = low - s.y + 9.0;
            }
            if s.end || !columns.cable(s.col) {
                for &l in &s.lanes {
                    at_station.insert((at, l), lane_y[l]);
                }
            }
        }
        // The cable: each station's lines packed, zone by zone, at the
        // middle of its lanes; its column's stations pushed apart.
        for c in columns.host..=columns.host + 2 {
            let mut col: Vec<(usize, f32, Vec<f32>)> = Vec::new();
            for (at, s) in stations.iter_mut().enumerate() {
                if s.col != c || s.idle {
                    continue;
                }
                let mut offs = Vec::new();
                let mut o = 0.0;
                let mut prev: Option<&str> = None;
                for &l in &s.lanes {
                    if prev.is_some_and(|p| p != lanes[l].zone) {
                        o += 6.0;
                    }
                    offs.push(o);
                    o += SLOT;
                    prev = Some(&lanes[l].zone);
                }
                let mid = s.lanes.iter().map(|l| lane_y[*l]).sum::<f32>() / s.lanes.len() as f32;
                s.h = HEAD + 4.0 + o - SLOT + 9.0;
                col.push((at, mid - (HEAD + 4.0 + (o - SLOT) / 2.0), offs));
            }
            col.sort_by(|a, b| a.1.total_cmp(&b.1));
            let mut cursor = TOP;
            for (at, want, offs) in col {
                let s = &mut stations[at];
                s.y = cursor.max(want);
                cursor = s.y + s.h + GAP + 6.0;
                bottom = bottom.max(cursor);
                for (l, o) in s.lanes.iter().zip(offs) {
                    at_station.insert((at, *l), s.y + HEAD + 4.0 + o);
                }
            }
        }
        let mut idle = bottom + HEAD;
        for s in stations.iter_mut().filter(|s| s.idle) {
            s.y = idle;
            s.h = HEAD + 6.0;
            idle += HEAD + 16.0;
        }
        for (n, lane) in lanes.iter_mut().enumerate() {
            lane.ys = lane
                .path
                .iter()
                .map(|at| at_station.get(&(*at, n)).copied().unwrap_or(lane_y[n]))
                .collect();
        }
        static READINGS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Metro {
            stamp: READINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            scheme,
            stations,
            lanes,
            bands,
            width: columns.x(columns.last) + COLW + LEFT + 30.0,
            columns,
            height: bottom.max(idle) + 24.0,
        }
    }

    /// Whether a new reading needs either canvas cache cleared. Byte totals
    /// change the list, not the drawing; a zero counter becoming nonzero does.
    pub fn same_drawing(&self, other: &Metro) -> bool {
        self.scheme.places == other.scheme.places
            && self.scheme.groups == other.scheme.groups
            && self.scheme.rows.len() == other.scheme.rows.len()
            && self
                .scheme
                .rows
                .iter()
                .zip(&other.scheme.rows)
                .all(|(a, b)| {
                    a.id == b.id
                        && a.group == b.group
                        && a.name == b.name
                        && a.kind == b.kind
                        && a.from == b.from
                        && a.end == b.end
                        && a.end_text == b.end_text
                        && a.observed == b.observed
                        && a.hops == b.hops
                        && (a.count == 0) == (b.count == 0)
                })
    }

    pub fn row(&self, id: &str) -> Option<&Row> {
        self.scheme.rows.iter().find(|r| r.id == id)
    }

    /// A station's name, by its id.
    pub fn name_of<'a>(&'a self, id: &'a str) -> &'a str {
        self.scheme
            .places
            .iter()
            .find(|p| p.id == id)
            .map_or(id, |p| p.name.as_str())
    }

    pub fn group_title<'a>(&'a self, id: &'a str) -> &'a str {
        self.scheme
            .groups
            .iter()
            .find(|(g, _)| g == id)
            .map_or(id, |(_, t)| t.as_str())
    }

    /// A stretch's ends and its curve: out of the right edge into the
    /// left, or back (what comes in) out of the left into the right.
    fn stretch(&self, lane: &Lane, i: usize) -> (Point, Point, bool) {
        let (p, q) = (
            &self.stations[lane.path[i]],
            &self.stations[lane.path[i + 1]],
        );
        let back = q.col < p.col;
        let x1 = if back { p.x } else { p.x + BOXW };
        let x2 = if back { q.x + BOXW } else { q.x };
        (
            Point::new(x1, lane.ys[i]),
            Point::new(x2, lane.ys[i + 1]),
            back,
        )
    }

    /// The stretch under a point: `(lane, hop)`.
    fn hit(&self, at: Point) -> Option<(usize, usize)> {
        let mut best: Option<(f32, (usize, usize))> = None;
        for (n, lane) in self.lanes.iter().enumerate() {
            for i in 0..lane.path.len().saturating_sub(1) {
                let (a, b, _) = self.stretch(lane, i);
                if at.x < a.x.min(b.x) - 6.0 || at.x > a.x.max(b.x) + 6.0 {
                    continue;
                }
                let d = curve_distance(a, b, at);
                if d < 6.0 && best.is_none_or(|(e, _)| d < e) {
                    best = Some((d, (n, i)));
                }
            }
        }
        best.map(|(_, hit)| hit)
    }
}

/// A point of the stretch's curve from `a` to `b`, `t` along it.
fn curve_at(a: Point, b: Point, t: f32) -> Point {
    let mid = (a.x + b.x) / 2.0;
    let u = 1.0 - t;
    let (w0, w1, w2, w3) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
    Point::new(
        w0 * a.x + (w1 + w2) * mid + w3 * b.x,
        (w0 + w1) * a.y + (w2 + w3) * b.y,
    )
}

fn curve_distance(a: Point, b: Point, at: Point) -> f32 {
    const STEPS: usize = 16;
    let mut best = f32::MAX;
    let mut prev = a;
    for k in 1..=STEPS {
        let next = curve_at(a, b, k as f32 / STEPS as f32);
        let (dx, dy) = (next.x - prev.x, next.y - prev.y);
        let len = dx * dx + dy * dy;
        let t = if len > 0.0 {
            (((at.x - prev.x) * dx + (at.y - prev.y) * dy) / len).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let (px, py) = (prev.x + t * dx - at.x, prev.y + t * dy - at.y);
        best = best.min((px * px + py * py).sqrt());
        prev = next;
    }
    best
}

fn curve(a: Point, b: Point) -> Path {
    Path::new(|p| {
        p.move_to(a);
        if a.y == b.y {
            p.line_to(b);
        } else {
            let mid = (a.x + b.x) / 2.0;
            p.bezier_curve_to(Point::new(mid, a.y), Point::new(mid, b.y), b);
        }
    })
}

/// The colours, as the theme is light or dark.
#[derive(Debug, Clone, Copy)]
struct Ink {
    panel: Color,
    ink: Color,
    muted: Color,
    line: Color,
    band: Color,
    machine: Color,
    nobody: Color,
    server: Color,
    stranger: Color,
    gate: Color,
    unknown: Color,
}

impl Ink {
    fn of(theme: &Theme) -> Ink {
        let palette = theme.extended_palette();
        let hex = |v: u32| Color::from_rgb8((v >> 16) as u8, (v >> 8) as u8, v as u8);
        let (panel, ink) = (palette.background.base.color, palette.background.base.text);
        if palette.is_dark {
            Ink {
                panel,
                ink,
                muted: hex(0x98a0b2),
                line: hex(0x2e3442),
                band: hex(0x161a22),
                machine: hex(0x8a94a8),
                nobody: hex(0x5b93f5),
                server: ink,
                stranger: hex(0xff6b6b),
                gate: hex(0xf0a531),
                unknown: hex(0x6b7384),
            }
        } else {
            Ink {
                panel,
                ink,
                muted: hex(0x6b7384),
                line: hex(0xd5dae4),
                band: hex(0xeef1f6),
                machine: hex(0x7d8799),
                nobody: hex(0x2f6fde),
                server: ink,
                stranger: hex(0xd23c3c),
                gate: hex(0xc47a00),
                unknown: hex(0x9aa1af),
            }
        }
    }

    fn sees(&self, sees: &str) -> Color {
        match sees {
            "machine" => self.machine,
            "nobody" => self.nobody,
            "server" => self.server,
            _ => self.stranger,
        }
    }
}

/// How a row ends, for a person: its mark and its colour.
fn end_mark(r: &Row, ink: &Ink, with_hops: bool) -> (&'static str, Color) {
    let clear = with_hops && r.hops.iter().any(|h| h.sees == "stranger");
    if (r.end_text.starts_with('⚠') || (clear && r.end == "arrives")) && r.end != "leak" {
        return ("⚠", ink.gate);
    }
    match r.end.as_str() {
        "arrives" => ("✓", ink.nobody),
        "denied" | "cut" => ("✕", ink.stranger),
        "answered" => ("↩", ink.muted),
        "leak" => ("⚠", ink.stranger),
        _ => ("•", ink.muted),
    }
}

/// The mark of a row in the list beside the scheme.
pub fn list_mark(r: &Row, theme: &Theme) -> (&'static str, Color) {
    end_mark(r, &Ink::of(theme), false)
}

/// A row's kind, for a person.
pub fn kind_words(kind: &str) -> &str {
    match kind {
        "data" => "соединения",
        "dns" => "DNS",
        "denied" => "запрещено",
        "local" => "служебное ядра",
        "ping" => "ping",
        "handshake" => "туннель",
        "server-name" => "имя сервера",
        "host" => "вне cellward",
        "offline" => "без сети",
        "arp" => "ARP",
        "dropped" => "отброшено",
        "inbound" => "входящее",
        "service" => "служебное",
        other => other,
    }
}

/// Who can read a stretch, for a person.
pub fn sees_words(sees: &str) -> &str {
    match sees {
        "machine" => "только машина",
        "nobody" => "никто в пути",
        "server" => "сервер",
        _ => "посторонний",
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        let mut out: String = s.chars().take(n - 1).collect();
        out.push('…');
        out
    } else {
        s.to_owned()
    }
}

fn faded(c: Color, a: f32) -> Color {
    Color { a: c.a * a, ..c }
}

/// The drawing: the frames, the bands, the tubes, the stations, the
/// lines, their labels.
struct Pen<'a> {
    frame: &'a mut Frame,
    at: Point,
}

impl Pen<'_> {
    fn p(&self, x: f32, y: f32) -> Point {
        Point::new(self.at.x + x, self.at.y + y)
    }

    /// Text by its baseline, as the scheme's SVG prototype had it.
    #[allow(clippy::too_many_arguments)]
    fn text(
        &mut self,
        x: f32,
        base: f32,
        s: &str,
        size: f32,
        color: Color,
        weight: font::Weight,
        h: Horizontal,
    ) {
        self.frame.fill_text(Text {
            content: s.to_owned(),
            position: self.p(x, base - size * 0.35),
            color,
            size: size.into(),
            font: Font {
                weight,
                ..Font::DEFAULT
            },
            align_x: h.into(),
            align_y: Vertical::Center,
            shaping: Shaping::Advanced,
            ..Text::default()
        });
    }

    fn mono(&mut self, x: f32, base: f32, s: &str, size: f32, color: Color) {
        self.frame.fill_text(Text {
            content: s.to_owned(),
            position: self.p(x, base - size * 0.35),
            color,
            size: size.into(),
            font: Font::MONOSPACE,
            align_y: Vertical::Center,
            shaping: Shaping::Advanced,
            ..Text::default()
        });
    }

    fn rect(&self, x: f32, y: f32, w: f32, h: f32, r: f32) -> Path {
        Path::rounded_rectangle(self.p(x, y), Size::new(w, h), r.into())
    }

    fn stroke(&mut self, path: &Path, color: Color, width: f32, dash: &[f32]) {
        self.frame.stroke(
            path,
            Stroke {
                line_dash: LineDash {
                    segments: dash,
                    offset: 0,
                },
                ..Stroke::default().with_color(color).with_width(width)
            },
        );
    }
}

/// The scheme on a canvas: `focus` the row shown alone, `pinned` the one
/// chosen; `hover` and `pin` what the pointer says.
pub struct View<'a, M> {
    pub metro: &'a Metro,
    pub focus: Option<&'a str>,
    pub pinned: Option<&'a str>,
    pub hover: fn(Option<(String, usize)>) -> M,
    pub pin: fn(String) -> M,
}

/// The stretch under the pointer, `(lane, hop)`; the drawing kept, and
/// what it was drawn of.
#[derive(Default)]
pub struct Under {
    at: Option<(usize, usize)>,
    still: canvas::Cache,
    lines: canvas::Cache,
    #[cfg(test)]
    still_draws: std::cell::Cell<usize>,
    #[cfg(test)]
    line_draws: std::cell::Cell<usize>,
    #[allow(clippy::type_complexity)]
    drawn: std::cell::RefCell<Option<((u64, bool), (Option<String>, Option<String>))>>,
}

impl<M> canvas::Program<M> for View<'_, M> {
    type State = Under;

    fn update(
        &self,
        state: &mut Under,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<M>> {
        match event {
            canvas::Event::Mouse(mouse::Event::CursorMoved { .. })
            | canvas::Event::Mouse(mouse::Event::CursorLeft) => {
                let under = cursor.position_in(bounds).and_then(|p| self.metro.hit(p));
                if under == state.at {
                    return None;
                }
                state.at = under;
                let said = under.map(|(l, h)| {
                    (
                        self.metro.scheme.rows[self.metro.lanes[l].row].id.clone(),
                        h,
                    )
                });
                Some(canvas::Action::publish((self.hover)(said)))
            }
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                let (l, _) = state.at?;
                let id = self.metro.scheme.rows[self.metro.lanes[l].row].id.clone();
                Some(canvas::Action::publish((self.pin)(id)).and_capture())
            }
            _ => None,
        }
    }

    fn draw(
        &self,
        state: &Under,
        renderer: &Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        // Drawn anew only when it changes: the stations with the reading
        // (and the theme), the lines with what is shown alone or chosen —
        // not at each move of the pointer, each second's reload.
        let ink = Ink::of(theme);
        let key = (self.metro.stamp, theme.extended_palette().is_dark);
        let shown = (
            self.focus.map(str::to_owned),
            self.pinned.map(str::to_owned),
        );
        {
            let mut was = state.drawn.borrow_mut();
            match &*was {
                Some((k, s)) if *k == key && *s == shown => {}
                Some((k, _)) if *k == key => state.lines.clear(),
                _ => {
                    state.still.clear();
                    state.lines.clear();
                }
            }
            *was = Some((key, shown));
        }
        let size = bounds.size();
        vec![
            state.still.draw(renderer, size, |frame| {
                #[cfg(test)]
                state.still_draws.set(state.still_draws.get() + 1);
                self.still(frame, &ink);
            }),
            state.lines.draw(renderer, size, |frame| {
                #[cfg(test)]
                state.line_draws.set(state.line_draws.get() + 1);
                self.lines(frame, &ink);
            }),
        ]
    }

    fn mouse_interaction(
        &self,
        state: &Under,
        _bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if state.at.is_some() {
            mouse::Interaction::Pointer
        } else {
            mouse::Interaction::default()
        }
    }
}

impl<M> View<'_, M> {
    /// The frames, the bands, the tubes, the stations with their names.
    fn still(&self, frame: &mut Frame, ink: &Ink) {
        let ink = *ink;
        let m = self.metro;
        let at = Point::ORIGIN;
        let (bold, semi, normal) = (
            font::Weight::Bold,
            font::Weight::Semibold,
            font::Weight::Normal,
        );
        let left = Horizontal::Left;
        {
            let mut pen = Pen {
                frame: &mut *frame,
                at,
            };
            let machine_r = m.columns.x(m.columns.host) + COLW / 2.0;
            let lan_r = m.columns.x(m.columns.host + 2);
            let h = m.height;
            // The machine, each network of the host its own frame, the
            // unknown beyond.
            let frame = pen.rect(
                m.columns.x(0) + 2.0,
                8.0,
                machine_r - m.columns.x(0) - 4.0,
                h - 16.0,
                12.0,
            );
            pen.frame.fill(&frame, ink.band);
            pen.stroke(&frame, ink.line, 1.5, &[]);
            let mut nets: Vec<(&str, f32, f32)> = Vec::new();
            for s in &m.stations {
                let mut parts = s.place.id.split(':');
                let (Some("if" | "lan" | "link"), Some(dev)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if s.idle || dev.is_empty() {
                    continue;
                }
                match nets.iter_mut().find(|n| n.0 == dev) {
                    Some(n) => {
                        n.1 = n.1.min(s.y);
                        n.2 = n.2.max(s.y + s.h);
                    }
                    None => nets.push((dev, s.y, s.y + s.h)),
                }
            }
            for (dev, top, low) in nets {
                let r = pen.rect(
                    machine_r - COLW / 2.0 + 8.0,
                    top - 22.0,
                    lan_r - machine_r + COLW / 2.0 - 12.0,
                    low - top + 30.0,
                    10.0,
                );
                pen.stroke(&r, ink.line, 1.5, &[]);
                pen.text(
                    machine_r + 10.0,
                    top - 8.0,
                    &format!("Сеть {dev}"),
                    11.0,
                    ink.ink,
                    bold,
                    left,
                );
            }
            let beyond = pen.rect(
                lan_r + 2.0,
                8.0,
                m.columns.x(m.columns.last + 1) - lan_r - 4.0,
                h - 16.0,
                12.0,
            );
            pen.stroke(&beyond, ink.unknown, 1.5, &[6.0, 5.0]);
            pen.text(
                m.columns.x(0) + 14.0,
                28.0,
                "Твоя машина",
                13.0,
                ink.ink,
                bold,
                left,
            );
            pen.text(
                machine_r + 12.0,
                28.0,
                "Сети хоста",
                13.0,
                ink.ink,
                bold,
                left,
            );
            pen.text(
                lan_r + 12.0,
                28.0,
                "Дальше — не известно, что",
                13.0,
                ink.muted,
                bold,
                left,
            );
            for (a, label) in [
                (0, "контейнер"),
                (3, "зона · программ"),
                (5, "зона · выход"),
            ] {
                pen.text(
                    m.columns.x(a) + 14.0,
                    46.0,
                    label,
                    11.0,
                    ink.muted,
                    normal,
                    left,
                );
                if a != 0 {
                    let line =
                        Path::line(pen.p(m.columns.x(a), 38.0), pen.p(m.columns.x(a), h - 14.0));
                    pen.stroke(&line, ink.line, 1.0, &[2.0, 4.0]);
                }
            }
            for (c, name) in m.columns.labels.iter().enumerate() {
                pen.text(
                    m.columns.x(c) + COLW / 2.0,
                    66.0,
                    name,
                    11.0,
                    ink.muted,
                    normal,
                    Horizontal::Center,
                );
            }
            // Each zone's band, named at its left.
            for b in &m.bands {
                let r = pen.rect(
                    m.columns.x(0) + 8.0,
                    b.top - HEAD - 8.0,
                    m.columns.x(m.columns.last + 1) - m.columns.x(0) - 16.0,
                    b.bottom - b.top + HEAD + 18.0,
                    8.0,
                );
                pen.stroke(&r, ink.line, 1.0, &[1.0, 4.0]);
                let title = if b.zone == "~host" {
                    "сам хост — вне cellward".to_owned()
                } else if let Some(outer) = m.columns.carrier.get(&b.zone) {
                    format!("зона {} · этот VPN вложен в VPN {}", b.zone, outer)
                } else {
                    format!("зона {}", b.zone)
                };
                pen.text(
                    m.columns.x(0) + 16.0,
                    b.top - HEAD + 6.0,
                    &title,
                    11.0,
                    ink.muted,
                    bold,
                    left,
                );
            }
            self.tubes(&mut pen, &ink);
        }

        // The stations, their names over them.
        {
            let mut pen = Pen {
                frame: &mut *frame,
                at,
            };
            for s in &m.stations {
                if s.end && !s.idle {
                    for &l in &s.lanes {
                        let lane = &m.lanes[l];
                        let r = &m.scheme.rows[lane.row];
                        let y = lane.ys[lane
                            .path
                            .iter()
                            .position(|a| m.stations[*a].place.id == s.place.id)
                            .unwrap_or(0)];
                        let b = pen.rect(s.x, y - ROWH / 2.0, BOXW, ROWH, 5.0);
                        pen.frame.fill(&b, ink.panel);
                        pen.stroke(&b, ink.line, 1.0, &[]);
                        // A shared start (the container's programs and
                        // kernel, for each counter of its wall) says the
                        // row's own name.
                        let name = if s.col == m.columns.last {
                            if s.place.tech.is_empty() {
                                &s.place.name
                            } else {
                                &s.place.tech
                            }
                        } else if s.place.id.ends_with(":*") || s.place.id == "hostkernel" {
                            &r.name
                        } else {
                            &s.place.name
                        };
                        pen.text(
                            s.x + 7.0,
                            y + 4.0,
                            &clip(name, 22),
                            11.0,
                            ink.ink,
                            semi,
                            left,
                        );
                    }
                    continue;
                }
                let alpha = if s.idle { 0.6 } else { 1.0 };
                let (line, width) = if s.place.gate {
                    (ink.gate, 2.0)
                } else if s.place.unknown {
                    (ink.unknown, 1.2)
                } else {
                    (ink.line, 1.2)
                };
                let dash: &[f32] = if s.place.unknown || s.idle {
                    &[4.0, 4.0]
                } else {
                    &[]
                };
                let shape = if s.place.translates {
                    // A translator — takes packets in and makes them
                    // anew: cut corners, and ⇄ by its name.
                    let (k, x, y, w, h) = (9.0, s.x, s.y, BOXW, s.h);
                    pen.text(
                        s.x + BOXW - 8.0,
                        s.y + 13.0,
                        "⇄",
                        12.0,
                        faded(ink.muted, alpha),
                        bold,
                        Horizontal::Right,
                    );
                    Path::new(|p| {
                        p.move_to(pen.p(x + k, y));
                        p.line_to(pen.p(x + w - k, y));
                        p.line_to(pen.p(x + w, y + k));
                        p.line_to(pen.p(x + w, y + h - k));
                        p.line_to(pen.p(x + w - k, y + h));
                        p.line_to(pen.p(x + k, y + h));
                        p.line_to(pen.p(x, y + h - k));
                        p.line_to(pen.p(x, y + k));
                        p.close();
                    })
                } else {
                    pen.rect(s.x, s.y, BOXW, s.h, 7.0)
                };
                pen.frame.fill(&shape, faded(ink.panel, alpha));
                pen.stroke(&shape, faded(line, alpha), width, dash);
                // A gate: its colour says so (no glyph of a shield in every font).
                let title = s.place.name.clone();
                pen.text(
                    s.x + 8.0,
                    s.y + 13.0,
                    &clip(&title, 20),
                    11.5,
                    faded(ink.ink, alpha),
                    semi,
                    left,
                );
                pen.mono(
                    s.x + 8.0,
                    s.y + 24.0,
                    &clip(&s.place.tech, 25),
                    9.0,
                    faded(ink.muted, alpha),
                );
            }
        }
    }

    /// The lines, their arrows, their ends; the chosen row's stretches named.
    fn lines(&self, frame: &mut Frame, ink: &Ink) {
        let ink = *ink;
        let m = self.metro;
        let at = Point::ORIGIN;
        let (bold, normal) = (font::Weight::Bold, font::Weight::Normal);
        let left = Horizontal::Left;
        let mut pen = Pen { frame, at };
        let mut ended: HashMap<usize, usize> = HashMap::new();
        // The chosen row's stretches named: over every line, after them.
        let mut pills: Vec<(f32, f32, String, Color)> = Vec::new();
        for lane in &m.lanes {
            let r = &m.scheme.rows[lane.row];
            // A counter that dropped nothing: there, faint.
            let quiet = r.id.contains(":wall:") && r.count == 0;
            let alpha = match self.focus {
                Some(f) if f == r.id => 1.0,
                Some(_) => 0.1,
                None if quiet => 0.45,
                None => 1.0,
            };
            let style = |sees: &str| {
                let dash: &'static [f32] = if !r.observed {
                    &[3.0, 4.0]
                } else if sees == "stranger" {
                    &[7.0, 4.0]
                } else {
                    &[]
                };
                (
                    faded(ink.sees(sees), alpha),
                    if r.observed { 3.0 } else { 2.0 },
                    dash,
                )
            };
            for (i, &at_s) in lane.path.iter().enumerate() {
                let s = &m.stations[at_s];
                let y = lane.ys[i];
                if let Some(h) = r
                    .hops
                    .get(i)
                    .or_else(|| i.checked_sub(1).and_then(|j| r.hops.get(j)))
                {
                    if !s.end {
                        let (c, w, d) = style(&h.sees);
                        let through = Path::line(pen.p(s.x, y), pen.p(s.x + BOXW, y));
                        pen.stroke(&through, c, w, d);
                    }
                }
                if i + 1 >= lane.path.len() {
                    continue;
                }
                let Some(hop) = r.hops.get(i) else { continue };
                let (a, b, back) = m.stretch(lane, i);
                let (c, w, d) = style(&hop.sees);
                pen.stroke(&curve(pen.p(a.x, a.y), pen.p(b.x, b.y)), c, w, d);
                // What comes in: an arrow at the stretch's end, its way.
                if back {
                    pen.text(b.x + 2.0, b.y + 4.0, "◀", 9.0, c, normal, left);
                }
                if self.pinned == Some(r.id.as_str()) {
                    pills.push(((a.x + b.x) / 2.0, (a.y + b.y) / 2.0, clip(&hop.wrap, 24), c));
                }
            }
            // The end, by the last station: on its far side from where
            // the row came — left for what comes in —; the marks of rows
            // ending at one station apart, where the lines are packed.
            let Some(&last_at) = lane.path.last() else {
                continue;
            };
            let last = &m.stations[last_at];
            let (mark, color) = end_mark(r, &ink, true);
            let back =
                lane.path.len() > 1 && m.stations[lane.path[lane.path.len() - 2]].col > last.col;
            let nth = if m.columns.cable(last.col) {
                let n = ended.entry(last_at).or_insert(0);
                *n += 1;
                *n - 1
            } else {
                0
            } as f32;
            let mx = if back {
                last.x - 12.0 - nth * 11.0
            } else {
                last.x + BOXW + 5.0 + nth * 11.0
            };
            let y = *lane.ys.last().unwrap_or(&0.0);
            pen.text(mx, y + 4.0, mark, 12.0, faded(color, alpha), bold, left);
        }
        for (mid, my, label, c) in pills {
            let w = label.chars().count() as f32 * 6.4 + 14.0;
            let pill = pen.rect(mid - w / 2.0, my - 8.0, w, 16.0, 8.0);
            pen.frame.fill(&pill, ink.panel);
            pen.stroke(&pill, c, 1.0, &[]);
            pen.text(mid, my + 3.5, &label, 9.5, c, normal, Horizontal::Center);
        }
    }

    /// Tubes: a zone's lines that go together between two stations,
    /// cased — its tunnel blue; under the stations, seen between them.
    fn tubes(&self, pen: &mut Pen<'_>, ink: &Ink) {
        let m = self.metro;
        // By (zone, from, to): the stretches in it, `(lane, hop)`, and who
        // can read them.
        type Tube<'a> = ((&'a str, usize, usize), Vec<(usize, usize)>, &'a str);
        let mut segs: Vec<Tube<'_>> = Vec::new();
        for (n, lane) in m.lanes.iter().enumerate() {
            let r = &m.scheme.rows[lane.row];
            if !r.observed {
                continue;
            }
            for i in 0..lane.path.len().saturating_sub(1) {
                let key = (lane.zone.as_str(), lane.path[i], lane.path[i + 1]);
                match segs.iter_mut().find(|s| s.0 == key) {
                    Some(s) => s.1.push((n, i)),
                    None => segs.push((
                        key,
                        vec![(n, i)],
                        r.hops.get(i).map_or("", |h| h.sees.as_str()),
                    )),
                }
            }
        }
        for ((_, a, b), rows, sees) in segs {
            let tunnel = sees == "nobody";
            let nested = m.stations[a]
                .place
                .id
                .strip_prefix("out:")
                .zip(m.stations[b].place.id.strip_prefix("tun:"))
                .filter(|(inner, outer)| inner != outer)
                .map(|(_, outer)| outer);
            if !tunnel && rows.len() < 2 {
                continue;
            }
            let span = |k: usize| {
                let ys = rows.iter().map(|(n, i)| m.lanes[*n].ys[i + k]);
                let (lo, hi) = ys.fold((f32::MAX, f32::MIN), |(lo, hi), y| (lo.min(y), hi.max(y)));
                (lo - 5.0, hi + 5.0)
            };
            let ((ta, ba), (tb, bb)) = (span(0), span(1));
            let (pa, pb) = (&m.stations[a], &m.stations[b]);
            let (x1, x2, m1, m2) = (pa.x, pb.x + BOXW, pa.x + BOXW, pb.x);
            let mid = (m1 + m2) / 2.0;
            let tube = Path::new(|p| {
                p.move_to(pen.p(x1, ta));
                p.line_to(pen.p(m1, ta));
                p.bezier_curve_to(pen.p(mid, ta), pen.p(mid, tb), pen.p(m2, tb));
                p.line_to(pen.p(x2, tb));
                p.line_to(pen.p(x2, bb));
                p.line_to(pen.p(m2, bb));
                p.bezier_curve_to(pen.p(mid, bb), pen.p(mid, ba), pen.p(m1, ba));
                p.line_to(pen.p(x1, ba));
                p.close();
            });
            let c = if tunnel { ink.nobody } else { ink.machine };
            pen.frame.fill(
                &tube,
                faded(
                    c,
                    if nested.is_some() {
                        0.24
                    } else if tunnel {
                        0.16
                    } else {
                        0.09
                    },
                ),
            );
            pen.stroke(
                &tube,
                faded(c, if tunnel { 0.5 } else { 0.25 }),
                if nested.is_some() { 1.8 } else { 1.0 },
                &[],
            );
            if let Some(outer) = nested {
                pen.text(
                    mid,
                    (ta + tb) / 2.0 - 9.0,
                    &format!("внутри VPN {outer}"),
                    10.0,
                    ink.nobody,
                    font::Weight::Semibold,
                    Horizontal::Center,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/scheme.lines");
    const CHAIN: &str = include_str!("../tests/scheme-chain.lines");

    #[test]
    fn the_lines_read_back_whole() {
        let s = parse(SAMPLE);
        assert!(s.places.len() > 20, "{}", s.places.len());
        assert!(!s.groups.is_empty());
        assert!(s.rows.len() > 30, "{}", s.rows.len());
        // A row of one station (a way out's upkeep): read too.
        assert!(s.rows.iter().any(|r| r.hops.is_empty()));
        assert!(s.rows.iter().any(|r| r.hops.len() > 3));
        // A line of another shape: skipped, not a row half read.
        let odd = parse("row\tonly\ttwo\nplace\tx\n");
        assert!(odd.rows.is_empty() && odd.places.is_empty());
    }

    #[test]
    fn every_row_has_its_lane_and_every_station_its_place() {
        let m = Metro::new(parse(SAMPLE));
        assert_eq!(m.lanes.len(), m.scheme.rows.len());
        for lane in &m.lanes {
            assert_eq!(lane.ys.len(), lane.path.len());
            assert!(
                lane.ys.iter().all(|y| *y > TOP && *y < m.height),
                "{:?}",
                lane.ys
            );
        }
        for s in &m.stations {
            assert!(
                s.h > 0.0 && s.y + s.h <= m.height,
                "{}: {} + {}",
                s.place.id,
                s.y,
                s.h
            );
            assert!(s.x >= 0.0 && s.x + BOXW <= m.width);
        }
        // The host's own rows: the last band.
        assert_eq!(m.bands.last().map(|b| b.zone.as_str()), Some("~host"));
    }

    #[test]
    fn stations_of_a_column_do_not_overlap() {
        let m = Metro::new(parse(SAMPLE));
        for a in &m.stations {
            for b in &m.stations {
                if a.place.id >= b.place.id || a.col != b.col || a.end || b.end {
                    continue;
                }
                let apart = a.y + a.h <= b.y || b.y + b.h <= a.y;
                assert!(apart, "{} and {} overlap", a.place.id, b.place.id);
            }
        }
    }

    #[test]
    fn a_zones_rows_stay_together() {
        let m = Metro::new(parse(SAMPLE));
        let mut seen: Vec<&str> = Vec::new();
        for lane in &m.lanes {
            if seen.last() != Some(&lane.zone.as_str()) {
                assert!(
                    !seen.contains(&lane.zone.as_str()),
                    "zone {} split",
                    lane.zone
                );
                seen.push(&lane.zone);
            }
        }
    }

    #[test]
    fn a_stretch_is_found_under_the_pointer() {
        let m = Metro::new(parse(SAMPLE));
        let lane = &m.lanes[0];
        let (a, b, _) = m.stretch(lane, 0);
        let mid = curve_at(a, b, 0.5);
        assert!(m.hit(mid).is_some(), "nothing under the stretch's middle");
        assert!(m.hit(Point::new(1.0, 1.0)).is_none());
    }

    #[test]
    fn repeated_readings_and_hover_reuse_the_canvas_caches() {
        use iced::widget::canvas::Program as _;

        let renderer = iced::Renderer::new(iced::Font::default(), iced::Pixels(16.0));
        let metro = Metro::new(parse(SAMPLE));
        let under = Under::default();
        let bounds = Rectangle::with_size(Size::new(metro.width, metro.height));
        let draw = |metro: &Metro, focus: Option<&str>| {
            let view = View::<()> {
                metro,
                focus,
                pinned: None,
                hover: |_| (),
                pin: |_| (),
            };
            std::hint::black_box(view.draw(
                &under,
                &renderer,
                &Theme::Light,
                bounds,
                mouse::Cursor::Unavailable,
            ));
        };
        let draws = || (under.still_draws.get(), under.line_draws.get());

        draw(&metro, None);
        assert_eq!(draws(), (1, 1));
        draw(&metro, None);
        assert_eq!(draws(), (1, 1));

        let mut traffic = Metro::new(metro.scheme.clone());
        traffic.stamp = metro.stamp;
        traffic.scheme.rows[0].out_bytes += 500;
        traffic.scheme.rows[0].count += 1;
        draw(&traffic, None);
        assert_eq!(draws(), (1, 1));

        let focused = metro.scheme.rows[0].id.clone();
        draw(&metro, Some(&focused));
        assert_eq!(draws(), (1, 2));
        draw(&metro, Some(&focused));
        assert_eq!(draws(), (1, 2));

        let lane = &metro.lanes[0];
        let (a, b, _) = metro.stretch(lane, 0);
        let mid = curve_at(a, b, 0.5);
        let view = View::<()> {
            metro: &metro,
            focus: None,
            pinned: None,
            hover: |_| (),
            pin: |_| (),
        };
        let mut pointer = Under::default();
        let event = canvas::Event::Mouse(mouse::Event::CursorMoved { position: mid });
        let cursor = mouse::Cursor::Available(mid);
        assert!(view.update(&mut pointer, &event, bounds, cursor).is_some());
        assert!(view.update(&mut pointer, &event, bounds, cursor).is_none());
    }

    #[test]
    fn nested_tunnels_advance_through_their_own_columns() {
        let m = Metro::new(parse(CHAIN));
        let lane = m
            .lanes
            .iter()
            .find(|lane| m.scheme.rows[lane.row].id == "i:Firefox:data")
            .unwrap();
        let ids: Vec<&str> = lane
            .path
            .iter()
            .map(|at| m.stations[*at].place.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "prog:i:Firefox",
                "tap:i",
                "relay:i",
                "passt:i",
                "tun:inner",
                "out:inner",
                "tun:outer",
                "out:outer",
                "if:eth1",
                "lan:eth1",
                "isp:eth1",
                "vpn:outer",
                "vpn:inner",
                "dst:i:Firefox",
            ]
        );
        let cols: Vec<usize> = lane.path.iter().map(|at| m.stations[*at].col).collect();
        assert!(cols.windows(2).all(|pair| pair[0] < pair[1]), "{cols:?}");
        assert_eq!(
            m.columns.carrier.get("inner").map(String::as_str),
            Some("outer")
        );
        assert_eq!(m.columns.labels[4], "Шифратор · слой 1");
        assert_eq!(m.columns.labels[6], "Шифратор · слой 2");
        assert_eq!(m.columns.labels[11], "Сервер VPN · слой 2");
        assert_eq!(m.columns.labels[12], "Сервер VPN · слой 1");
    }

    #[test]
    fn byte_totals_do_not_change_the_cached_drawing() {
        let a = Metro::new(parse(SAMPLE));
        let mut b = Metro::new(a.scheme.clone());
        b.scheme.rows[0].out_bytes += 100;
        b.scheme.rows[0].in_bytes += 100;
        b.scheme.rows[0].count += 1;
        assert!(a.same_drawing(&b));
        b.scheme.rows[0].count = 0;
        assert_eq!(a.same_drawing(&b), a.scheme.rows[0].count == 0);
        b.scheme.rows[0].hops[0].sees = "stranger".into();
        assert!(!a.same_drawing(&b));
    }

    #[test]
    #[ignore = "performance measurement; run explicitly with --nocapture"]
    fn scheme_performance_metro() {
        use iced::advanced::graphics::geometry::Renderer as _;
        use iced::advanced::renderer::Headless as _;
        use iced::advanced::Renderer as _;
        use iced::widget::canvas::Program as _;

        fn median(mut samples: Vec<f64>) -> f64 {
            samples.sort_by(f64::total_cmp);
            samples[samples.len() / 2]
        }

        let started = std::time::Instant::now();
        let metro = Metro::new(many_flows(parse(SAMPLE), 500));
        println!("scheme rows: {}", metro.lanes.len());
        println!(
            "metro layout (off UI thread): {:.3} ms",
            started.elapsed().as_secs_f64() * 1000.0
        );

        let points: Vec<Point> = metro
            .lanes
            .iter()
            .take(100)
            .flat_map(|lane| {
                (0..lane.path.len().saturating_sub(1)).map(|i| {
                    let (a, b, _) = metro.stretch(lane, i);
                    curve_at(a, b, 0.5)
                })
            })
            .collect();
        let hits = median(
            (0..7)
                .map(|_| {
                    let started = std::time::Instant::now();
                    for point in &points {
                        std::hint::black_box(metro.hit(*point));
                    }
                    started.elapsed().as_secs_f64() * 1000.0 / points.len() as f64
                })
                .collect(),
        );
        println!(
            "hit-test / pointer event: {hits:.3} ms ({} curved points)",
            points.len()
        );

        let mut renderer = iced::Renderer::new(iced::Font::default(), iced::Pixels(16.0));
        let under = Under::default();
        let bounds = Rectangle::with_size(Size::new(metro.width, metro.height));
        let draw = |focus: Option<&str>, under: &Under, renderer: &iced::Renderer| {
            let view = View::<()> {
                metro: &metro,
                focus,
                pinned: None,
                hover: |_| (),
                pin: |_| (),
            };
            view.draw(
                under,
                renderer,
                &Theme::Light,
                bounds,
                mouse::Cursor::Unavailable,
            )
        };
        let geometry = |samples: usize, alternate: bool| {
            median(
                (0..samples)
                    .map(|n| {
                        let focus = alternate
                            .then_some(metro.scheme.rows[n % metro.scheme.rows.len()].id.as_str());
                        let started = std::time::Instant::now();
                        std::hint::black_box(draw(focus, &under, &renderer));
                        started.elapsed().as_secs_f64() * 1000.0
                    })
                    .collect(),
            )
        };
        let cold = median(
            (0..5)
                .map(|_| {
                    let under = Under::default();
                    let started = std::time::Instant::now();
                    std::hint::black_box(draw(None, &under, &renderer));
                    started.elapsed().as_secs_f64() * 1000.0
                })
                .collect(),
        );
        println!("canvas geometry cold: {cold:.3} ms");
        println!("canvas geometry warm cache: {:.3} ms", geometry(15, false));
        println!(
            "canvas geometry hover/line invalidation: {:.3} ms",
            geometry(7, true)
        );

        let viewport = Rectangle::with_size(Size::new(1280.0, 720.0));
        let mut raster = |samples: usize, alternate: bool| {
            let measured: Vec<(f64, u64)> = (0..samples)
                .map(|n| {
                    let focus = alternate
                        .then_some(metro.scheme.rows[n % metro.scheme.rows.len()].id.as_str());
                    renderer.reset(viewport);
                    renderer.start_layer(viewport);
                    for geometry in draw(focus, &under, &renderer) {
                        renderer.draw_geometry(geometry);
                    }
                    renderer.end_layer();
                    let started = std::time::Instant::now();
                    let pixels = renderer.screenshot(Size::new(1280, 720), 1.0, Color::WHITE);
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&pixels, &mut hasher);
                    let hash = std::hash::Hasher::finish(&hasher);
                    std::hint::black_box(pixels);
                    (started.elapsed().as_secs_f64() * 1000.0, hash)
                })
                .collect();
            (
                median(measured.iter().map(|(time, _)| *time).collect()),
                measured.last().unwrap().1,
            )
        };
        let (warm, warm_hash) = raster(5, false);
        println!("tiny-skia raster warm cache: {warm:.3} ms");
        println!("tiny-skia warm RGBA hash: {warm_hash:016x}");
        let (hover, hover_hash) = raster(5, true);
        println!("tiny-skia raster hover/line invalidation: {hover:.3} ms");
        println!("tiny-skia hover RGBA hash: {hover_hash:016x}");
    }
}
