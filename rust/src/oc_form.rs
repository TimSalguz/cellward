//! The OpenConnect login as its gateway asks it (`docs/PERMISSIONS.md`
//! §11.17): what `cellward-oc-auth` and the process that runs it say to each
//! other, one JSON object per line.
//!
//! A gateway's login is a chain of forms, and the gateway sets them: an
//! AnyConnect one asks for the group, the user and the password in one form
//! and for a one-time code in the next; others ask otherwise. The helper —
//! the one binary linked with libopenconnect — goes through them, and hands
//! each form out as it comes ([`Said::Form`]); the answers come back
//! ([`Answer`]). What comes out of a login is the session's cookie, never
//! the password: it goes to the client on its standard input
//! (`--cookie-on-stdin`), as the password did.
//!
//! Everything here is plain data, so that it can be tested without a
//! gateway; the helper is `src/bin/cellward-oc-auth.rs`.
//!
//! What a gateway says — a form's text, its fields' names and labels — is
//! the gateway's, not ours: it is bounded here ([`bounded`]) and shown as
//! the gateway's words, never taken for ours.

use std::collections::BTreeMap;

use crate::json::{self, Value};
use crate::openconnect::OcConfig;

/// The longest text of a gateway's that is kept: a banner, a message.
pub const MAX_TEXT: usize = 4000;
/// The longest name or label of a field or a choice.
pub const MAX_LABEL: usize = 200;
/// The most fields of one form, and choices of one field, that are kept.
pub const MAX_ITEMS: usize = 256;

/// What the helper is to do: log in, or only look (`probe`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub server: String,
    pub port: Option<u16>,
    pub protocol: String,
    /// The pinned certificate (`pin-sha256:…`): the gateway's certificate
    /// must be this one, whoever signed it — the system's authorities are
    /// then not asked at all.
    pub pin: Option<String>,
    /// `--usergroup`: the path of the first request.
    pub usergroup: Option<String>,
    pub useragent: Option<String>,
    pub os: Option<String>,
    pub version_string: Option<String>,
    pub sni: Option<String>,
    pub local_hostname: Option<String>,
    pub no_xmlpost: bool,
    /// Only look: does the server answer as this protocol, with which
    /// certificate, and what does its first form ask? Nothing is sent, and
    /// the certificate is taken whoever signed it — it is shown, to be
    /// pinned.
    pub probe: bool,
}

impl Request {
    /// A login to the network of this config: its server, its protocol, its
    /// pin, and those of its `Args` that the login phase uses.
    pub fn of(cfg: &OcConfig) -> Self {
        let mut req = Self {
            server: cfg.server.clone(),
            port: cfg.port,
            protocol: cfg.protocol.clone(),
            pin: cfg.server_cert.clone(),
            ..Self::default()
        };
        for arg in &cfg.extra {
            let (flag, value) = match arg.split_once('=') {
                Some((flag, value)) => (flag, Some(value.to_owned())),
                None => (arg.as_str(), None),
            };
            match flag {
                "--usergroup" => req.usergroup = value,
                "--useragent" => req.useragent = value,
                "--os" => req.os = value,
                "--version-string" => req.version_string = value,
                "--sni" => req.sni = value,
                "--local-hostname" => req.local_hostname = value,
                "--no-xmlpost" => req.no_xmlpost = true,
                _ => {}
            }
        }
        req
    }

    pub fn encode(&self) -> String {
        let opt = |v: &Option<String>| v.as_deref().map_or("null".to_owned(), json::quote);
        format!(
            "{{\"server\":{},\"port\":{},\"protocol\":{},\"pin\":{},\"usergroup\":{},\
             \"useragent\":{},\"os\":{},\"version_string\":{},\"sni\":{},\
             \"local_hostname\":{},\"no_xmlpost\":{},\"probe\":{}}}",
            json::quote(&self.server),
            self.port.map_or("null".to_owned(), |p| p.to_string()),
            json::quote(&self.protocol),
            opt(&self.pin),
            opt(&self.usergroup),
            opt(&self.useragent),
            opt(&self.os),
            opt(&self.version_string),
            opt(&self.sni),
            opt(&self.local_hostname),
            self.no_xmlpost,
            self.probe,
        )
    }

    pub fn decode(line: &str) -> Result<Self, String> {
        let v = json::parse(line)?;
        let text = |key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
        let server = text("server").ok_or("no server")?;
        let protocol = text("protocol").ok_or("no protocol")?;
        let port = match v.get("port") {
            None | Some(Value::Null) => None,
            Some(p) => Some(
                p.as_i64()
                    .and_then(|p| u16::try_from(p).ok())
                    .ok_or("a bad port")?,
            ),
        };
        Ok(Self {
            server,
            port,
            protocol,
            pin: text("pin"),
            usergroup: text("usergroup"),
            useragent: text("useragent"),
            os: text("os"),
            version_string: text("version_string"),
            sni: text("sni"),
            local_hostname: text("local_hostname"),
            no_xmlpost: v.get("no_xmlpost").and_then(Value::as_bool) == Some(true),
            probe: v.get("probe").and_then(Value::as_bool) == Some(true),
        })
    }
}

/// What a field of a form asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    /// Shown as dots, and never kept but in the keyring.
    Password,
    /// One of the field's choices — the group is one.
    Select,
    /// A code from a token: asked, never kept.
    Token,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Password => "password",
            Self::Select => "select",
            Self::Token => "token",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "text" => Some(Self::Text),
            "password" => Some(Self::Password),
            "select" => Some(Self::Select),
            "token" => Some(Self::Token),
            _ => None,
        }
    }
}

/// A choice of a [`Kind::Select`] field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub name: String,
    pub label: String,
}

/// A field of a gateway's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The gateway's name of it: what an answer is given by.
    pub name: String,
    pub label: String,
    pub kind: Kind,
    /// What it holds now: a select's choice; empty for the rest.
    pub value: String,
    pub choices: Vec<Choice>,
}

/// A form of the gateway's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Form {
    pub banner: String,
    pub message: String,
    /// What went wrong with the last answer, in the gateway's words.
    pub error: String,
    pub fields: Vec<Field>,
    /// The field that is the group, when one is: a new choice there brings
    /// the form of that group.
    pub group: Option<String>,
}

/// What the helper says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    /// A form to answer: one [`Answer`] line comes back.
    Form(Form),
    /// A look ([`Request::probe`]): the server answered as its protocol,
    /// with this certificate, and asks this first.
    Probe {
        fingerprint: String,
        form: Option<Form>,
    },
    /// Logged in: what the client connects with.
    Done {
        cookie: String,
        connect_url: String,
        fingerprint: String,
        /// The address the login went to — and the client has to go to.
        address: String,
    },
    Failed {
        why: String,
    },
    /// A line of the library's progress, for the journal.
    Log {
        text: String,
    },
}

/// An answer to a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// By field name.
    Values(BTreeMap<String, String>),
    Cancel,
}

/// At most `max` characters of `text`, without control characters — but
/// line breaks where `lines` allows them.
pub fn bounded(text: &str, max: usize, lines: bool) -> String {
    text.chars()
        .filter(|&c| !c.is_control() || (lines && c == '\n'))
        .filter(|&c| !crate::focus::reorders(c))
        .take(max)
        .collect()
}

fn encode_form(form: &Form) -> String {
    let fields: Vec<String> = form
        .fields
        .iter()
        .map(|f| {
            let choices: Vec<String> = f
                .choices
                .iter()
                .map(|c| {
                    format!(
                        "{{\"name\":{},\"label\":{}}}",
                        json::quote(&c.name),
                        json::quote(&c.label)
                    )
                })
                .collect();
            format!(
                "{{\"name\":{},\"label\":{},\"kind\":{},\"value\":{},\"choices\":[{}]}}",
                json::quote(&f.name),
                json::quote(&f.label),
                json::quote(f.kind.as_str()),
                json::quote(&f.value),
                choices.join(",")
            )
        })
        .collect();
    format!(
        "{{\"banner\":{},\"message\":{},\"error\":{},\"fields\":[{}],\"group\":{}}}",
        json::quote(&form.banner),
        json::quote(&form.message),
        json::quote(&form.error),
        fields.join(","),
        form.group.as_deref().map_or("null".to_owned(), json::quote)
    )
}

/// A form back from its JSON, bounded again: the reader does not trust the
/// writer to have done it.
fn decode_form(v: &Value) -> Result<Form, String> {
    let text = |v: &Value, key: &str, max: usize, lines: bool| {
        bounded(v.get(key).and_then(Value::as_str).unwrap_or(""), max, lines)
    };
    let mut fields = Vec::new();
    for f in v
        .get("fields")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .take(MAX_ITEMS)
    {
        let kind = f
            .get("kind")
            .and_then(Value::as_str)
            .and_then(Kind::parse)
            .ok_or("a field of no known kind")?;
        let choices = f
            .get("choices")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .take(MAX_ITEMS)
            .map(|c| Choice {
                name: text(c, "name", MAX_LABEL, false),
                label: text(c, "label", MAX_LABEL, false),
            })
            .collect();
        fields.push(Field {
            name: text(f, "name", MAX_LABEL, false),
            label: text(f, "label", MAX_LABEL, false),
            kind,
            value: text(f, "value", MAX_LABEL, false),
            choices,
        });
    }
    Ok(Form {
        banner: text(v, "banner", MAX_TEXT, true),
        message: text(v, "message", MAX_TEXT, true),
        error: text(v, "error", MAX_TEXT, true),
        fields,
        group: v
            .get("group")
            .and_then(Value::as_str)
            .map(|g| bounded(g, MAX_LABEL, false)),
    })
}

impl Said {
    pub fn encode(&self) -> String {
        match self {
            Self::Form(form) => format!("{{\"form\":{}}}", encode_form(form)),
            Self::Probe { fingerprint, form } => format!(
                "{{\"probe\":{{\"fingerprint\":{},\"form\":{}}}}}",
                json::quote(fingerprint),
                form.as_ref().map_or("null".to_owned(), encode_form)
            ),
            Self::Done {
                cookie,
                connect_url,
                fingerprint,
                address,
            } => format!(
                "{{\"done\":{{\"cookie\":{},\"connect_url\":{},\"fingerprint\":{},\"address\":{}}}}}",
                json::quote(cookie),
                json::quote(connect_url),
                json::quote(fingerprint),
                json::quote(address)
            ),
            Self::Failed { why } => format!("{{\"failed\":{}}}", json::quote(why)),
            Self::Log { text } => format!("{{\"log\":{}}}", json::quote(text)),
        }
    }

    pub fn decode(line: &str) -> Result<Self, String> {
        let v = json::parse(line)?;
        if let Some(form) = v.get("form") {
            return decode_form(form).map(Self::Form);
        }
        if let Some(p) = v.get("probe") {
            let form = match p.get("form") {
                None | Some(Value::Null) => None,
                Some(form) => Some(decode_form(form)?),
            };
            return Ok(Self::Probe {
                fingerprint: p
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .ok_or("a probe with no fingerprint")?
                    .to_owned(),
                form,
            });
        }
        if let Some(d) = v.get("done") {
            let text = |key: &str| {
                d.get(key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("done with no {key}"))
            };
            return Ok(Self::Done {
                cookie: text("cookie")?,
                connect_url: text("connect_url")?,
                fingerprint: text("fingerprint")?,
                address: text("address")?,
            });
        }
        if let Some(why) = v.get("failed").and_then(Value::as_str) {
            return Ok(Self::Failed {
                why: bounded(why, MAX_TEXT, true),
            });
        }
        if let Some(text) = v.get("log").and_then(Value::as_str) {
            return Ok(Self::Log {
                text: bounded(text, MAX_TEXT, false),
            });
        }
        Err("nothing the helper says".to_owned())
    }
}

impl Answer {
    pub fn encode(&self) -> String {
        match self {
            Self::Cancel => "{\"cancel\":true}".to_owned(),
            Self::Values(values) => {
                let items: Vec<String> = values
                    .iter()
                    .map(|(k, v)| format!("{}:{}", json::quote(k), json::quote(v)))
                    .collect();
                format!("{{\"answers\":{{{}}}}}", items.join(","))
            }
        }
    }

    pub fn decode(line: &str) -> Result<Self, String> {
        let v = json::parse(line)?;
        if v.get("cancel").and_then(Value::as_bool) == Some(true) {
            return Ok(Self::Cancel);
        }
        let Some(Value::Object(map)) = v.get("answers") else {
            return Err("neither answers nor cancel".to_owned());
        };
        let mut values = BTreeMap::new();
        for (key, value) in map {
            let value = value.as_str().ok_or("an answer that is not text")?;
            values.insert(key.clone(), value.to_owned());
        }
        Ok(Self::Values(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> Form {
        Form {
            banner: "Welcome\nto work".into(),
            message: "Please enter your username and password.".into(),
            error: String::new(),
            fields: vec![
                Field {
                    name: "group_list".into(),
                    label: "GROUP:".into(),
                    kind: Kind::Select,
                    value: "Employees".into(),
                    choices: vec![
                        Choice {
                            name: "Employees".into(),
                            label: "Employees".into(),
                        },
                        Choice {
                            name: "Contractors".into(),
                            label: "Подрядчики".into(),
                        },
                    ],
                },
                Field {
                    name: "username".into(),
                    label: "Username:".into(),
                    kind: Kind::Text,
                    value: String::new(),
                    choices: vec![],
                },
                Field {
                    name: "password".into(),
                    label: "Password:".into(),
                    kind: Kind::Password,
                    value: String::new(),
                    choices: vec![],
                },
            ],
            group: Some("group_list".into()),
        }
    }

    #[test]
    fn what_the_helper_says_goes_there_and_back() {
        for said in [
            Said::Form(form()),
            Said::Probe {
                fingerprint: "pin-sha256:abc=".into(),
                form: Some(form()),
            },
            Said::Probe {
                fingerprint: "pin-sha256:abc=".into(),
                form: None,
            },
            Said::Done {
                cookie: "webvpn=A1B2\"C3".into(),
                connect_url: "https://vpn.example.org/".into(),
                fingerprint: "pin-sha256:abc=".into(),
                address: "192.0.2.10".into(),
            },
            Said::Failed {
                why: "Login failed.\nTry again".into(),
            },
            Said::Log {
                text: "SSL negotiation with vpn.example.org".into(),
            },
        ] {
            let line = said.encode();
            assert!(!line.contains('\n'), "one line: {line}");
            assert_eq!(Said::decode(&line).unwrap(), said);
        }
        assert!(Said::decode("{\"nonsense\":1}").is_err());
    }

    #[test]
    fn a_request_goes_there_and_back_and_takes_the_logins_args() {
        let cfg = OcConfig::parse(
            b"[OpenConnect]\nServer = vpn.example.org:4443\nProtocol = gp\n\
              ServerCert = pin-sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\
              Args = --usergroup=portal --os=win --no-xmlpost --no-dtls\n",
        )
        .unwrap();
        let req = Request::of(&cfg);
        assert_eq!(req.server, "vpn.example.org");
        assert_eq!(req.port, Some(4443));
        assert_eq!(req.protocol, "gp");
        assert!(req.pin.as_deref().unwrap().starts_with("pin-sha256:"));
        assert_eq!(req.usergroup.as_deref(), Some("portal"));
        assert_eq!(req.os.as_deref(), Some("win"));
        assert!(req.no_xmlpost && !req.probe);
        assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        let probe = Request {
            probe: true,
            port: None,
            ..req
        };
        assert_eq!(Request::decode(&probe.encode()).unwrap(), probe);
        assert!(Request::decode("{\"server\":\"a\",\"protocol\":\"gp\",\"port\":70000}").is_err());
    }

    #[test]
    fn answers_go_there_and_back() {
        let mut values = BTreeMap::new();
        values.insert("username".to_owned(), "ivan".to_owned());
        values.insert("password".to_owned(), "p\"a\\ss\nw".to_owned());
        let answer = Answer::Values(values);
        assert_eq!(Answer::decode(&answer.encode()).unwrap(), answer);
        assert_eq!(
            Answer::decode(&Answer::Cancel.encode()).unwrap(),
            Answer::Cancel
        );
        assert!(Answer::decode("{\"answers\":{\"a\":1}}").is_err());
        assert!(Answer::decode("{}").is_err());
    }

    /// A gateway's words are bounded, and stripped of what could hide or
    /// reorder them; a message keeps its lines, a label does not.
    #[test]
    fn a_gateways_words_are_bounded() {
        assert_eq!(bounded("a\u{202E}b\tc\nd", 100, true), "abc\nd");
        assert_eq!(bounded("a\nb", 100, false), "ab");
        assert_eq!(bounded(&"x".repeat(500), MAX_LABEL, false).len(), MAX_LABEL);
        let mut long = form();
        long.fields[1].label = "L".repeat(1000);
        let back = Said::decode(&Said::Form(long).encode()).unwrap();
        let Said::Form(back) = back else {
            panic!("a form")
        };
        assert_eq!(back.fields[1].label.len(), MAX_LABEL);
    }
}
