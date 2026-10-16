//! **Схема** of the cellward window: one zone as it is linked — the
//! programs of its containers, the zone's own network space with its
//! tunnel, the host's way out of it, every interface of the host (the one
//! the zone goes by marked), the gateway, the server, the internet — and
//! where its names go. Drawn from `cellward _panel` alone, each second.
//!
//! The lines say what goes on them: grey inside the machine (not
//! encrypted, never leaves it), blue and doubled the tunnel (encrypted from
//! the zone to the server), dark past the server (as any way out to the
//! internet), dashed the names asked — green to a resolver on the VPN's
//! side, red to a public one past the server in clear —, dotted orange the
//! server's name the host resolved once.

use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke, Text};
use iced::{mouse, Color, Point, Rectangle, Renderer, Size, Theme};

/// A container of the zone, with what it sends and receives now, per
/// second.
#[derive(Debug, Clone, PartialEq)]
pub struct Cont {
    pub name: String,
    pub out: f64,
    pub inb: f64,
}

/// One of the host's interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub kind: String,
    pub up: bool,
    pub addrs: Vec<String>,
}

/// One server of the zone's tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub raw: String,
    pub addr: Option<String>,
    pub named: bool,
    pub dev: Option<String>,
    pub via: Option<String>,
}

/// What one zone's scheme is drawn from.
#[derive(Debug, Clone, PartialEq)]
pub struct Scheme {
    pub zone: String,
    pub up: bool,
    pub color: Color,
    /// `amneziawg`, `wireguard`, `openconnect`, `host`, `system`, `offline`.
    pub kind: String,
    pub servers: Vec<Server>,
    /// `vpn`, `public`, `-`, and what it says.
    pub dns: (String, String),
    pub conts: Vec<Cont>,
    pub ifaces: Vec<Iface>,
}

/// The logical size the scheme is laid out in, scaled to fit.
const W: f32 = 1200.0;
const H: f32 = 600.0;

const GREY: Color = Color::from_rgb(0.55, 0.55, 0.58);
const BLUE: Color = Color::from_rgb(0.20, 0.45, 0.85);
const GREEN: Color = Color::from_rgb(0.18, 0.62, 0.33);
const RED: Color = Color::from_rgb(0.82, 0.23, 0.23);
const ORANGE: Color = Color::from_rgb(0.90, 0.55, 0.12);

fn kind_words(kind: &str) -> &str {
    match kind {
        "amneziawg" => "AmneziaWG",
        "wireguard" => "WireGuard",
        "openconnect" => "OpenConnect",
        "host" => "сеть хоста, без туннеля",
        "system" => "через системную зону",
        _ => "без сети",
    }
}

fn iface_words(kind: &str) -> &str {
    match kind {
        "ethernet" => "кабель",
        "wifi" => "Wi-Fi",
        "loopback" => "петля",
        _ => "виртуальный",
    }
}

/// A rate for a person.
pub fn rate(bytes: f64) -> String {
    match bytes {
        b if b >= 1_048_576.0 => format!("{:.1} МБ/с", b / 1_048_576.0),
        b if b >= 1024.0 => format!("{:.0} КБ/с", b / 1024.0),
        b => format!("{b:.0} Б/с"),
    }
}

/// The port of a server as written (`host:port`, `[v6]:port`).
fn port_of(raw: &str) -> &str {
    raw.rsplit_once(':').map_or("", |(_, p)| p)
}

/// The subnet of an interface's address (`192.168.1.5/24` → `192.168.1.0/24`).
pub fn subnet(addr: &str) -> Option<String> {
    let (ip, len) = addr.split_once('/')?;
    let len: u32 = len.parse().ok()?;
    let v4: std::net::Ipv4Addr = ip.parse().ok()?;
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - len.min(32))
    };
    Some(format!(
        "{}/{len}",
        std::net::Ipv4Addr::from(u32::from(v4) & mask)
    ))
}

struct Pen<'a> {
    frame: &'a mut Frame,
    k: f32,
    text: Color,
    back: Color,
}

impl Pen<'_> {
    fn p(&self, x: f32, y: f32) -> Point {
        Point::new(x * self.k, y * self.k)
    }

    // A box: its place and size, then how it is drawn.
    #[allow(clippy::too_many_arguments)]
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, line: Color, width: f32, fill: Color) {
        let path = Path::rounded_rectangle(
            self.p(x, y),
            Size::new(w * self.k, h * self.k),
            (8.0 * self.k).into(),
        );
        self.frame.fill(&path, fill);
        self.frame
            .stroke(&path, Stroke::default().with_color(line).with_width(width));
    }

    fn text(&mut self, x: f32, y: f32, words: &str, size: f32, color: Color, max: f32) {
        self.frame.fill_text(Text {
            content: words.to_owned(),
            position: self.p(x, y),
            color,
            size: (size * self.k).into(),
            max_width: max * self.k,
            ..Text::default()
        });
    }

    /// A box with its title and a line under it.
    // A box: its place and size, then how it is drawn.
    #[allow(clippy::too_many_arguments)]
    fn boxed(&mut self, x: f32, y: f32, w: f32, h: f32, line: Color, title: &str, under: &str) {
        let (text, back) = (self.text, self.back);
        self.rect(x, y, w, h, line, 1.5, back);
        self.text(x + 10.0, y + 8.0, title, 15.0, text, w - 20.0);
        if !under.is_empty() {
            self.text(x + 10.0, y + 28.0, under, 12.0, GREY, w - 20.0);
        }
    }

    /// An arrow from `a` to `b`: `dash` for names asked, `double` for the
    /// tunnel.
    fn arrow(&mut self, a: (f32, f32), b: (f32, f32), color: Color, dash: &[f32], double: bool) {
        let (from, to) = (self.p(a.0, a.1), self.p(b.0, b.1));
        let stroke = |w: f32| Stroke {
            line_dash: canvas::LineDash {
                segments: dash,
                offset: 0,
            },
            ..Stroke::default().with_color(color).with_width(w)
        };
        if double {
            let (dx, dy) = (to.x - from.x, to.y - from.y);
            let len = (dx * dx + dy * dy).sqrt().max(1.0);
            let (nx, ny) = (-dy / len * 2.5 * self.k, dx / len * 2.5 * self.k);
            for s in [1.0, -1.0] {
                let path = Path::line(
                    Point::new(from.x + nx * s, from.y + ny * s),
                    Point::new(to.x + nx * s, to.y + ny * s),
                );
                self.frame.stroke(&path, stroke(1.6 * self.k));
            }
        } else {
            self.frame
                .stroke(&Path::line(from, to), stroke(1.6 * self.k));
        }
        // The head.
        let (dx, dy) = (to.x - from.x, to.y - from.y);
        let len = (dx * dx + dy * dy).sqrt().max(1.0);
        let (ux, uy) = (dx / len, dy / len);
        let s = 9.0 * self.k;
        let head = Path::new(|p| {
            p.move_to(to);
            p.line_to(Point::new(
                to.x - ux * s - uy * s * 0.5,
                to.y - uy * s + ux * s * 0.5,
            ));
            p.line_to(Point::new(
                to.x - ux * s + uy * s * 0.5,
                to.y - uy * s - ux * s * 0.5,
            ));
            p.close();
        });
        self.frame.fill(&head, color);
    }
}

impl<Message> canvas::Program<Message> for Scheme {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let palette = theme.extended_palette();
        let k = (bounds.width / W).min(bounds.height / H);
        let mut pen = Pen {
            frame: &mut frame,
            k,
            text: palette.background.base.text,
            back: palette.background.weak.color,
        };
        let text = pen.text;
        let dark = text;

        // The programs, by container.
        pen.text(20.0, 18.0, "Программы в контейнерах", 14.0, GREY, 200.0);
        let mut ys = Vec::new();
        if self.conts.is_empty() {
            pen.boxed(
                20.0,
                60.0,
                200.0,
                56.0,
                GREY,
                "нет запущенных",
                "программ этой сети",
            );
            ys.push(88.0);
        }
        for (i, c) in self.conts.iter().take(6).enumerate() {
            let y = 60.0 + i as f32 * 66.0;
            pen.boxed(
                20.0,
                y,
                200.0,
                56.0,
                self.color,
                &format!("контейнер {}", c.name),
                &format!("↑ {}  ↓ {}", rate(c.out), rate(c.inb)),
            );
            ys.push(y + 28.0);
        }

        // The zone: a network space of its own, its tunnel in it.
        let zone_fill = Color {
            a: 0.07,
            ..self.color
        };
        pen.rect(260.0, 40.0, 320.0, 330.0, self.color, 2.0, zone_fill);
        pen.text(
            275.0,
            50.0,
            &format!(
                "зона {}{} — своё сетевое пространство",
                self.zone,
                if self.up {
                    ""
                } else {
                    " (не поднята)"
                }
            ),
            15.0,
            text,
            300.0,
        );
        pen.boxed(
            275.0,
            90.0,
            290.0,
            56.0,
            GREY,
            "вход контейнеров (passt)",
            "их DNS — 10.254.255.253",
        );
        pen.boxed(
            275.0,
            175.0,
            290.0,
            56.0,
            BLUE,
            &format!("туннель {}", kind_words(&self.kind)),
            if matches!(self.kind.as_str(), "host" | "offline") {
                "не шифрует"
            } else {
                "шифрует всё, что идёт наружу"
            },
        );
        let (side, words) = &self.dns;
        let dns_color = match side.as_str() {
            "public" => RED,
            "vpn" => GREEN,
            _ => GREY,
        };
        pen.rect(275.0, 255.0, 290.0, 100.0, dns_color, 1.5, pen.back);
        pen.text(285.0, 263.0, "DNS программ", 14.0, text, 270.0);
        pen.text(285.0, 283.0, words, 12.0, dns_color, 270.0);

        for y in &ys {
            pen.arrow((220.0, *y), (275.0, 118.0), GREY, &[], false);
        }
        pen.text(
            222.0,
            380.0,
            "серое — внутри машины, не шифруется",
            12.0,
            GREY,
            340.0,
        );
        pen.arrow((420.0, 146.0), (420.0, 175.0), GREY, &[], false);
        // The names asked go into the tunnel with everything else.
        pen.arrow(
            (520.0, 255.0),
            (520.0, 231.0),
            dns_color,
            &[7.0, 5.0],
            false,
        );

        // The host's way out: pasta, the interfaces, the gateway.
        let tunnel = !matches!(self.kind.as_str(), "offline");
        let used = self.servers.first().and_then(|s| s.dev.clone());
        if tunnel {
            pen.boxed(
                610.0,
                175.0,
                140.0,
                56.0,
                BLUE,
                "pasta",
                "выход зоны в сеть хоста",
            );
            pen.arrow((565.0, 203.0), (610.0, 203.0), BLUE, &[], true);
        }
        pen.text(780.0, 18.0, "Интерфейсы хоста", 14.0, GREY, 200.0);
        let shown: Vec<&Iface> = self
            .ifaces
            .iter()
            .filter(|i| i.kind != "loopback")
            .take(6)
            .collect();
        let mut used_y = None;
        for (i, f) in shown.iter().enumerate() {
            let y = 50.0 + i as f32 * 70.0;
            let mine = used.as_deref() == Some(f.name.as_str());
            if mine {
                used_y = Some(y + 30.0);
            }
            let under = format!(
                "{} · {}{}{}",
                iface_words(&f.kind),
                f.addrs.first().map_or("нет адреса", String::as_str),
                if f.up { "" } else { " · выключен" },
                if mine {
                    " · по нему идёт зона"
                } else {
                    ""
                }
            );
            let line = if mine { BLUE } else { GREY };
            pen.boxed(780.0, y, 190.0, 60.0, line, &f.name, &under);
        }
        if let (true, Some(y)) = (tunnel, used_y) {
            pen.arrow((750.0, 203.0), (780.0, y), BLUE, &[], true);
        }

        // The gateway, the server, the internet, the local network.
        let server = self.servers.first();
        let iy = used_y.unwrap_or(203.0);
        if tunnel {
            let via = server.and_then(|s| s.via.as_ref());
            if let Some(via) = via {
                pen.boxed(1000.0, 50.0, 180.0, 60.0, GREY, "шлюз (роутер)", via);
                pen.arrow((970.0, iy), (1000.0, 80.0), BLUE, &[], true);
            }
            if let Some(s) = server {
                let at = s
                    .addr
                    .clone()
                    .unwrap_or_else(|| "адрес ещё не известен".to_owned());
                let under = if s.named {
                    format!("{at} · по имени {}", s.raw)
                } else {
                    format!("{at}:{}", port_of(&s.raw))
                };
                pen.boxed(1000.0, 165.0, 180.0, 70.0, BLUE, "сервер VPN", &under);
                let from = if via.is_some() {
                    (1090.0, 110.0)
                } else {
                    (970.0, iy)
                };
                pen.arrow(from, (1090.0, 165.0), BLUE, &[], true);
                pen.text(
                    1000.0,
                    240.0,
                    &format!(
                        "двойное синее — туннель, UDP {}, зашифрован",
                        port_of(&s.raw)
                    ),
                    11.0,
                    BLUE,
                    190.0,
                );
                if s.named {
                    pen.boxed(
                        780.0,
                        470.0,
                        190.0,
                        70.0,
                        ORANGE,
                        "DNS хоста",
                        "имя сервера, один раз: провайдер хоста видит его",
                    );
                    pen.arrow(
                        (875.0, iy + 30.0),
                        (875.0, 470.0),
                        ORANGE,
                        &[2.0, 4.0],
                        false,
                    );
                }
            }
            pen.boxed(
                1000.0,
                300.0,
                180.0,
                60.0,
                dark,
                "интернет",
                "от сервера — открыто",
            );
            pen.arrow((1090.0, 235.0), (1090.0, 300.0), dark, &[], false);
            let lan = shown
                .iter()
                .find(|f| Some(f.name.as_str()) == used.as_deref())
                .and_then(|f| f.addrs.first())
                .and_then(|a| subnet(a));
            if let Some(lan) = lan {
                let open = self.kind == "host";
                pen.boxed(
                    1000.0,
                    400.0,
                    180.0,
                    70.0,
                    if open { ORANGE } else { GREY },
                    "локальная сеть",
                    &format!(
                        "{lan} · {}",
                        if open {
                            "открыта программам зоны"
                        } else {
                            "программам зоны недоступна"
                        }
                    ),
                );
            }
            // The names go the way everything goes — into the tunnel, inside
            // it to the server —, and only there part: answered at the
            // server's side, or asked of a public resolver past it, in clear.
            let resolver = words
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .trim_end_matches(',');
            if side == "public" {
                pen.arrow((1150.0, 235.0), (1150.0, 300.0), RED, &[7.0, 5.0], false);
                pen.text(
                    1000.0,
                    365.0,
                    &format!("DNS к {resolver} — отсюда открытым текстом"),
                    11.0,
                    RED,
                    190.0,
                );
            } else if side == "vpn" {
                pen.text(
                    1000.0,
                    258.0,
                    &format!("DNS {resolver} отвечает здесь, у сервера VPN"),
                    11.0,
                    GREEN,
                    190.0,
                );
            }
        }
        pen.text(
            20.0,
            H - 24.0,
            "пунктир — DNS: идёт в туннеле вместе с данными; зелёный — отвечает сервер VPN, \
             красный — публичный резолвер, за сервером открытым текстом; точки — имя \
             сервера через DNS хоста",
            12.0,
            GREY,
            740.0,
        );
        vec![frame.into_geometry()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schemes_words() {
        assert_eq!(subnet("192.168.1.5/24").as_deref(), Some("192.168.1.0/24"));
        assert_eq!(subnet("10.0.0.7/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(subnet("fe80::1/64"), None);
        assert_eq!(port_of("vpn.example.org:51820"), "51820");
        assert_eq!(port_of("[2001:db8::1]:443"), "443");
        assert_eq!(rate(2048.0), "2 КБ/с");
        assert_eq!(kind_words("amneziawg"), "AmneziaWG");
    }
}
