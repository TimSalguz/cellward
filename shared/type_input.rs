//! Host-to-launch typing requests. Text is carried only on private sockets.

pub const PREFIX: &[u8] = b"\0cellward-type-1";
pub const MAX_TEXT: usize = 32 * 1024;
pub const MAX_REQUEST: usize = MAX_TEXT + 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Unicode,
    Keycodes,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unicode => "Символы Unicode",
            Self::Keycodes => "Физические клавиши (US)",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub start_ms: u16,
    pub between_ms: u16,
    pub hold_ms: u16,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            start_ms: 300,
            between_ms: 30,
            hold_ms: 10,
        }
    }
}

impl Timing {
    pub fn valid(self) -> bool {
        self.start_ms <= 5000
            && (1..=5000).contains(&self.between_ms)
            && (1..=1000).contains(&self.hold_ms)
    }
}

pub enum Request {
    Select {
        token: u64,
    },
    Cancel {
        token: u64,
    },
    Type {
        token: u64,
        timing: Timing,
        mode: Mode,
        allow_newlines: bool,
        text: String,
    },
}

impl Request {
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = PREFIX.to_vec();
        match self {
            Self::Select { token } => {
                out.push(0);
                out.extend_from_slice(&token.to_le_bytes());
            }
            Self::Cancel { token } => {
                out.push(2);
                out.extend_from_slice(&token.to_le_bytes());
            }
            Self::Type {
                token,
                timing,
                mode,
                allow_newlines,
                text,
            } => {
                out.push(1);
                out.extend_from_slice(&token.to_le_bytes());
                for ms in [timing.start_ms, timing.between_ms, timing.hold_ms] {
                    out.extend_from_slice(&ms.to_le_bytes());
                }
                out.push(
                    (match mode {
                        Mode::Unicode => 0,
                        Mode::Keycodes => 1,
                    }) | if *allow_newlines { 2 } else { 0 },
                );
                out.extend_from_slice(text.as_bytes());
            }
        }
        out
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_REQUEST {
            return None;
        }
        let bytes = bytes.strip_prefix(PREFIX)?;
        let token = u64::from_le_bytes(bytes.get(1..9)?.try_into().ok()?);
        if token == 0 {
            return None;
        }
        match bytes.first()? {
            0 if bytes.len() == 9 => Some(Self::Select { token }),
            2 if bytes.len() == 9 => Some(Self::Cancel { token }),
            1 => {
                let timing = Timing {
                    start_ms: u16::from_le_bytes(bytes.get(9..11)?.try_into().ok()?),
                    between_ms: u16::from_le_bytes(bytes.get(11..13)?.try_into().ok()?),
                    hold_ms: u16::from_le_bytes(bytes.get(13..15)?.try_into().ok()?),
                };
                let flags = *bytes.get(15)?;
                if flags & !3 != 0 {
                    return None;
                }
                let allow_newlines = flags & 2 != 0;
                let mode = match flags & 1 {
                    0 => Mode::Unicode,
                    1 => Mode::Keycodes,
                    _ => return None,
                };
                let text = std::str::from_utf8(bytes.get(16..)?).ok()?;
                if !timing.valid()
                    || text.is_empty()
                    || text.len() > MAX_TEXT
                    || (!allow_newlines && text.contains(['\n', '\r']))
                {
                    return None;
                }
                Some(Self::Type {
                    token,
                    timing,
                    mode,
                    allow_newlines,
                    text: text.to_owned(),
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stroke {
    pub key: u32,
    pub shift: bool,
}

pub struct Plan {
    pub keys: Vec<Stroke>,
    /// A complete XKB keymap including its terminating NUL, when needed.
    pub keymap: Option<Vec<u8>>,
}

impl Plan {
    pub fn new(text: &str, mode: Mode) -> Result<Self, &'static str> {
        if text.is_empty() || text.len() > MAX_TEXT {
            return Err("Текст пуст или длиннее 32 КиБ");
        }
        let text = text.replace("\r\n", "\n");
        let mut symbols = Vec::new();
        let mut keys = Vec::new();
        for c in text.chars() {
            if c.is_control() && !matches!(c, '\n' | '\t') {
                return Err("Текст содержит управляющие символы, которые нельзя печатать");
            }
            if keys.len() >= 8192 {
                return Err("Можно напечатать не больше 8192 символов за раз");
            }
            let stroke = match mode {
                Mode::Keycodes => us_key(c).ok_or(
                    "Для физических клавиш нужен текст US; для других символов выберите Unicode",
                )?,
                Mode::Unicode => {
                    let at = match symbols.iter().position(|&s| s == c) {
                        Some(at) => at,
                        None => {
                            symbols.push(c);
                            symbols.len() - 1
                        }
                    };
                    if at >= 232 {
                        return Err("В тексте больше 232 разных символов; разделите его на части");
                    }
                    Stroke {
                        key: 16 + at as u32,
                        shift: false,
                    }
                }
            };
            keys.push(stroke);
        }
        let keymap = (mode == Mode::Unicode).then(|| {
            let mut codes = String::new();
            let mut syms = String::new();
            for (i, c) in symbols.into_iter().enumerate() {
                codes.push_str(&format!("<T{i:03}> = {};\n", 24 + i));
                let sym = match c { '\n' => "Return".to_owned(), '\t' => "Tab".to_owned(), c => format!("U{:04X}", c as u32) };
                syms.push_str(&format!("key <T{i:03}> {{ type=\"ONE_LEVEL\", [ {sym} ] }};\n"));
            }
            format!("xkb_keymap {{\nxkb_keycodes \"cellward\" {{ minimum=8; maximum=255;\n{codes}}};\nxkb_types \"cellward\" {{ type \"ONE_LEVEL\" {{ modifiers=None; map[None]=Level1; level_name[Level1]=\"Any\"; }}; }};\nxkb_compatibility \"cellward\" {{}};\nxkb_symbols \"cellward\" {{\n{syms}}};\n}};\0").into_bytes()
        });
        Ok(Self { keys, keymap })
    }
}

fn us_key(c: char) -> Option<Stroke> {
    let (key, shift) = match c {
        '\n' => (28, false),
        '\t' => (15, false),
        ' ' => (57, false),
        c if c.is_ascii_alphabetic() => {
            let codes = [
                30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22,
                47, 17, 45, 21, 44,
            ];
            (
                codes[(c.to_ascii_lowercase() as u8 - b'a') as usize],
                c.is_ascii_uppercase(),
            )
        }
        c => {
            let plain = "1234567890-=[]\\;',./`";
            let upper = "!@#$%^&*()_+{}|:\"<>?~";
            let codes = [
                2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 26, 27, 43, 39, 40, 51, 52, 53, 41,
            ];
            if let Some(i) = plain.chars().position(|s| s == c) {
                (codes[i], false)
            } else if let Some(i) = upper.chars().position(|s| s == c) {
                (codes[i], true)
            } else {
                return None;
            }
        }
    };
    Some(Stroke { key, shift })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newline_permission_is_enforced_by_wire_parser() {
        for text in ["command\n", "command\r", "command\r\n"] {
            let mut request = Request::Type {
                token: 1,
                timing: Timing::default(),
                mode: Mode::Unicode,
                allow_newlines: false,
                text: text.into(),
            };
            assert!(Request::parse(&request.bytes()).is_none());
            if let Request::Type { allow_newlines, .. } = &mut request {
                *allow_newlines = true;
            }
            assert!(Request::parse(&request.bytes()).is_some());
        }
    }
    #[test]
    fn typing_is_bounded_and_keeps_unicode_out_of_shell_arguments() {
        let request = Request::Type {
            token: 42,
            timing: Timing::default(),
            mode: Mode::Unicode,
            allow_newlines: true,
            text: "Ab Я🙂\n".into(),
        };
        let bytes = request.bytes();
        let Some(Request::Type { text, token, .. }) = Request::parse(&bytes) else {
            panic!("request not read")
        };
        assert_eq!(token, 42);
        let plan = Plan::new(&text, Mode::Unicode).unwrap();
        assert_eq!(plan.keys.len(), 6);
        let map = String::from_utf8(plan.keymap.unwrap()).unwrap();
        assert!(map.contains("U042F") && map.contains("U1F642") && map.contains("Return"));
        assert!(Plan::new("a\0b", Mode::Unicode).is_err());
        assert!(Plan::new("Я", Mode::Keycodes).is_err());
        assert_eq!(
            Plan::new("A!", Mode::Keycodes).unwrap().keys,
            [
                Stroke {
                    key: 30,
                    shift: true
                },
                Stroke {
                    key: 2,
                    shift: true
                }
            ]
        );
        let mut bad = bytes;
        bad[PREFIX.len() + 13..PREFIX.len() + 15].copy_from_slice(&0u16.to_le_bytes());
        assert!(Request::parse(&bad).is_none());
    }
}
