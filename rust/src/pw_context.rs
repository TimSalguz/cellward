//! `pipewire-context` — the PipeWire socket a hermetic zone gets (owner,
//! 2026-09-25; `docs/LEAK-MODEL.md` §20).
//!
//! **Why.** Every zone used to get the host's `pipewire-0` as it is. PipeWire's
//! `module-access` in its legacy mode makes a client that is not a Flatpak
//! "unrestricted", and WirePlumber gives it every permission on every object:
//! it records the monitor of any output (everything the host plays), moves and
//! kills other programs' streams, links any port to any port and changes other
//! clients' permissions. The sound filter (`crate::pulse_filter`) guards the
//! PulseAudio protocol; the native one went around it.
//!
//! **What.** PipeWire's own door for sandboxes, the security context
//! (`PipeWire:Interface:SecurityContext`, v3). This process — on the host, as
//! the user, started by the zone's unit like the sound filter (`zone::Helpers`)
//! — makes the zone's listening socket (0600, in the zone's directory; bound
//! into a hermetic zone as `pipewire-0` by `zone::seal_runtime`) and hands it
//! to the daemon with `create(listen_fd, close_fd, props)`. A client that
//! connects there carries [`context_props`]: `pipewire.sec.engine` =
//! `vpn-zone`, `pipewire.sec.app-id` = the zone, `pipewire.sec.instance-id` =
//! the holder's pid, `pipewire.access` = `restricted` — properties the client
//! cannot change (the daemon refuses a client's update of a `pipewire.` key it
//! already has). `restricted`, and never an access value of our own:
//! `module-access` leaves a client whose access is set alone, and a stock
//! WirePlumber grants everything to an access it does not know. The
//! `close_fd` is a pipe's write end whose read end stays here: the daemon
//! stops listening when this process ends — with the zone, or when it closes
//! the context itself.
//!
//! **The policy is WirePlumber's** (`module/wireplumber/policy.lua`): a
//! restricted client gets from a stock WirePlumber read and execute on every
//! object — every other program's node, every monitor, the link factory. The
//! script gives the zone's clients their own nodes, the sinks to play to, the
//! microphones only when the zone may record, and no link it did not make; it
//! announces itself with the key [`POLICY_KEY`] = [`POLICY_VERSION`] in the
//! metadata object [`METADATA`] it makes. Only then is the socket handed to
//! the daemon ([`wanted`]). Until then — no WirePlumber, a stock one, one
//! restarted without the script — the socket does not even listen: a
//! program's `connect` is refused, the zone has only the pulse path, and the
//! program learns that at once. (Taking the connection and closing it hung
//! OpenAL Soft for good — [`listen`].) When the key goes
//! (WirePlumber restarted), the context is closed: the daemon stops
//! listening AND destroys every client that came through it
//! (`module-protocol-native`: a broken `close_fd` destroys the server, and
//! the server its clients). Fail-closed by construction — no permission a
//! policy gave outlives the policy; the zone's programs connect again, to a
//! socket that takes and closes each connection until the policy is back (a
//! socket cannot stop listening once it has: for the moments WirePlumber
//! restarts).
//!
//! **The daemon restarts**: this process keeps its own descriptor of the
//! socket, so the socket stays bound and listening; this process connects
//! again every [`TICK`] and hands the same descriptor to the new daemon.
//!
//! **The microphone** (`crate::microphone`): the zone's setting — made
//! stricter by the own setting of every container with a program running in
//! the zone, since this path does not know its clients' containers yet
//! (`docs/PERMISSIONS.md` §11.10) — is published in the same metadata, [`MICROPHONE_KEY`]`<zone>` = `yes` or `no`: as soon
//! as the metadata is bound, again right before the socket is handed out (on
//! the same connection, so WirePlumber has it before any client of the zone
//! — the key outlives a helper, and an earlier run's `yes` must not decide),
//! whenever the metadata says otherwise, and read again every [`TICK`] — a
//! change applies at once, as on the pulse path. The
//! policy lets the zone's clients see capture sources, and be linked to one,
//! only on `yes`. `ask` is `no` here: the question is asked on the pulse path,
//! where the sound filter can hold the request; a question for a native
//! stream is a follow-up (ROADMAP §17).
//!
//! **What this does not hold.** A client of the raw socket — an ordinary zone,
//! an audio-manager one (`hermetic::audio_manager`), any program of the host —
//! may write the marker itself or change any client's permissions: such a
//! zone is trusted with the sound by the owner's choice. The native protocol
//! is spoken here from Rust (no libpipewire): the few messages this needs are
//! the ones [`request`] builds and [`event`] reads.
//!
//! Usage: `vpn-zone-core pipewire-context --listen <socket> --upstream
//! <pipewire-0> --zone <name> --zone-dir <dir> --config <dir> --profiles <dir>
//! --instance <pid>`.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::microphone::Setting;

/// The zone's listening socket, in its directory.
pub const SOCKET: &str = "pipewire-context";
/// What this process says about itself, in the zone's directory, for the
/// doctor: one of [`State`]'s words.
pub const STATE_FILE: &str = "pipewire-context.state";
/// `pipewire.sec.engine` of the zones' clients: what the policy knows them by.
pub const ENGINE: &str = "vpn-zone";
/// The metadata object the WirePlumber policy makes.
pub const METADATA: &str = "vpn-zones";
/// The policy's marker in it (subject 0).
pub const POLICY_KEY: &str = "vpn-zones.policy";
/// The marker's value this build hands the socket out for: a policy of
/// another shape is no policy.
pub const POLICY_VERSION: &str = "1";
/// The zone's microphone in it, `<prefix><zone>` = `yes` | `no`.
pub const MICROPHONE_KEY: &str = "vpn-zones.microphone.";
/// How often the setting is read again and the daemon looked for.
pub const TICK: Duration = Duration::from_secs(1);

const TYPE_SECURITY_CONTEXT: &str = "PipeWire:Interface:SecurityContext";
const TYPE_METADATA: &str = "PipeWire:Interface:Metadata";
const VERSION_CORE: i32 = 4;
const VERSION_REGISTRY: i32 = 3;
const VERSION_METADATA: i32 = 3;
const VERSION_SECURITY_CONTEXT: i32 = 3;

/// The ids of this client's objects: the core and the client are there from
/// the start, the rest are numbered in the order they are made — the daemon
/// accepts a new id only right after the last one (`pw_map_insert_at`).
const CORE: u32 = 0;
const CLIENT: u32 = 1;
const REGISTRY: u32 = 2;
const FIRST_FREE: u32 = 3;

// Methods (`pipewire/core.h`, `client.h`, `extensions/metadata.h`,
// `extensions/security-context.h`): the opcode is the method's index.
const CORE_HELLO: u8 = 1;
const CORE_PONG: u8 = 3;
const CORE_GET_REGISTRY: u8 = 5;
const CLIENT_UPDATE_PROPERTIES: u8 = 2;
const REGISTRY_BIND: u8 = 1;
const METADATA_SET_PROPERTY: u8 = 1;
const SECURITY_CONTEXT_CREATE: u8 = 1;
// Events.
const CORE_DONE: u8 = 1;
const CORE_PING: u8 = 2;
const CORE_ERROR: u8 = 3;
const CORE_REMOVE_ID: u8 = 4;
const REGISTRY_GLOBAL: u8 = 0;
const REGISTRY_GLOBAL_REMOVE: u8 = 1;
const METADATA_PROPERTY: u8 = 0;

/// A message's header: id, opcode and size, sequence, descriptors
/// (protocol-native v3, `connection.c`).
const HEADER: usize = 16;
/// The largest message read from the daemon; one larger is a broken stream.
/// A registry announcement is some hundreds of bytes.
const MESSAGE_MAX: usize = 4 << 20;
/// Descriptors taken with one read; the daemon sends ours none, and any that
/// come are closed.
const FDS_MAX: usize = 32;

/// The SPA POD values this needs (`spa/pod/pod.h`): every value is a 32-bit
/// size of its body, a 32-bit type and the body, padded to 8 bytes; a struct's
/// body is its members one after another. Native byte order: the socket is a
/// Unix one.
pub mod pod {
    const NONE: u32 = 1;
    const INT: u32 = 4;
    const LONG: u32 = 5;
    const STRING: u32 = 8;
    const STRUCT: u32 = 14;
    const FD: u32 = 18;
    /// Structs within structs read at most this deep.
    const DEPTH_MAX: usize = 8;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        None,
        Int(i32),
        Long(i64),
        String(String),
        /// An index into the message's descriptors.
        Fd(i64),
        Struct(Vec<Value>),
        /// A type this does not read, by its number.
        Other(u32),
    }

    impl Value {
        pub fn int(&self) -> Option<i32> {
            match self {
                Self::Int(v) => Some(*v),
                _ => None,
            }
        }

        /// A string, or `Some(None)` for the none value that stands for a
        /// missing one; `None` for anything else.
        pub fn string(&self) -> Option<Option<&str>> {
            match self {
                Self::String(s) => Some(Some(s)),
                Self::None => Some(None),
                _ => None,
            }
        }

        pub fn members(&self) -> Option<&[Value]> {
            match self {
                Self::Struct(m) => Some(m),
                _ => None,
            }
        }
    }

    fn header(out: &mut Vec<u8>, size: usize, kind: u32) {
        out.extend_from_slice(&(size as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
    }

    fn pad(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
    }

    /// `value` at the end of `out`, which is 8-aligned.
    pub fn encode(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::None | Value::Other(_) => header(out, 0, NONE),
            Value::Int(v) => {
                header(out, 4, INT);
                out.extend_from_slice(&v.to_ne_bytes());
            }
            Value::Long(v) => {
                header(out, 8, LONG);
                out.extend_from_slice(&v.to_ne_bytes());
            }
            Value::Fd(v) => {
                header(out, 8, FD);
                out.extend_from_slice(&v.to_ne_bytes());
            }
            Value::String(s) => {
                header(out, s.len() + 1, STRING);
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            Value::Struct(members) => {
                // A struct's size counts its members' padding (spa's builder
                // pads every member and adds the padding to the frame).
                let mut body = Vec::new();
                for m in members {
                    encode(m, &mut body);
                }
                header(out, body.len(), STRUCT);
                out.extend_from_slice(&body);
            }
        }
        pad(out);
    }

    /// The value at the front of `buf`, and how many bytes it takes with its
    /// padding.
    pub fn decode(buf: &[u8]) -> Result<(Value, usize), String> {
        decode_at(buf, 0)
    }

    fn word(buf: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
    }

    fn decode_at(buf: &[u8], depth: usize) -> Result<(Value, usize), String> {
        let (Some(size), Some(kind)) = (word(buf, 0), word(buf, 4)) else {
            return Err("a value cut short".to_owned());
        };
        let end = 8usize
            .checked_add(size as usize)
            .filter(|&end| end <= buf.len())
            .ok_or("a value longer than its message")?;
        let body = &buf[8..end];
        let taken = end.div_ceil(8).saturating_mul(8).min(buf.len());
        let fixed = |n: usize| {
            body.get(..n)
                .ok_or_else(|| format!("a value of type {kind} with {size} bytes"))
        };
        let value = match kind {
            NONE => Value::None,
            INT => Value::Int(i32::from_ne_bytes(fixed(4)?.try_into().unwrap_or([0; 4]))),
            LONG => Value::Long(i64::from_ne_bytes(fixed(8)?.try_into().unwrap_or([0; 8]))),
            FD => Value::Fd(i64::from_ne_bytes(fixed(8)?.try_into().unwrap_or([0; 8]))),
            STRING => {
                // NUL-terminated, the NUL counted in the size: a string that
                // is not is no string.
                let Some((0, text)) = body.split_last() else {
                    return Err("a string without its NUL".to_owned());
                };
                let text = text.split(|&b| b == 0).next().unwrap_or_default();
                Value::String(String::from_utf8_lossy(text).into_owned())
            }
            STRUCT => {
                if depth >= DEPTH_MAX {
                    return Err("structs nested too deep".to_owned());
                }
                let mut members = Vec::new();
                let mut at = 0;
                while at < body.len() {
                    let (m, n) = decode_at(&body[at..], depth + 1)?;
                    members.push(m);
                    at += n;
                }
                Value::Struct(members)
            }
            other => Value::Other(other),
        };
        Ok((value, taken))
    }
}

use pod::Value;

/// One message as it goes on the wire: the header, then `body`.
pub fn message(id: u32, opcode: u8, seq: u32, n_fds: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(&id.to_ne_bytes());
    out.extend_from_slice(
        &((u32::from(opcode) << 24) | (body.len() as u32 & 0xff_ffff)).to_ne_bytes(),
    );
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&n_fds.to_ne_bytes());
    out.extend_from_slice(body);
    out
}

/// A message from the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub id: u32,
    pub opcode: u8,
    pub body: Vec<u8>,
}

/// The message at the front of `buf` and its whole length, once it is all
/// there; an error for one no daemon sends.
pub fn next_message(buf: &[u8]) -> Result<Option<(Incoming, usize)>, String> {
    if buf.len() < HEADER {
        return Ok(None);
    }
    let word = |at: usize| u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    let size = (word(4) & 0xff_ffff) as usize;
    if size > MESSAGE_MAX {
        return Err(format!("a message of {size} bytes"));
    }
    if buf.len() < HEADER + size {
        return Ok(None);
    }
    Ok(Some((
        Incoming {
            id: word(0),
            opcode: (word(4) >> 24) as u8,
            body: buf[HEADER..HEADER + size].to_vec(),
        },
        HEADER + size,
    )))
}

fn body(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    pod::encode(value, &mut out);
    out
}

/// A dictionary as the protocol writes one: the count, then key and value.
fn dict(items: &[(&str, &str)]) -> Value {
    let mut members = vec![Value::Int(items.len() as i32)];
    for (k, v) in items {
        members.push(Value::String((*k).to_owned()));
        members.push(Value::String((*v).to_owned()));
    }
    Value::Struct(members)
}

/// The requests this client makes: `(object id, opcode, body, descriptors
/// it carries)`.
pub mod request {
    use super::*;

    /// The first message; the daemon reads the protocol's version from it.
    pub fn hello() -> (u32, u8, Vec<u8>, u32) {
        (
            CORE,
            CORE_HELLO,
            body(&Value::Struct(vec![Value::Int(VERSION_CORE)])),
            0,
        )
    }

    /// The client's own name, for WirePlumber's log and `pw-cli`.
    pub fn client_properties(items: &[(&str, &str)]) -> (u32, u8, Vec<u8>, u32) {
        (
            CLIENT,
            CLIENT_UPDATE_PROPERTIES,
            body(&Value::Struct(vec![dict(items)])),
            0,
        )
    }

    pub fn get_registry() -> (u32, u8, Vec<u8>, u32) {
        (
            CORE,
            CORE_GET_REGISTRY,
            body(&Value::Struct(vec![
                Value::Int(VERSION_REGISTRY),
                Value::Int(REGISTRY as i32),
            ])),
            0,
        )
    }

    pub fn pong(id: i32, seq: i32) -> (u32, u8, Vec<u8>, u32) {
        (
            CORE,
            CORE_PONG,
            body(&Value::Struct(vec![Value::Int(id), Value::Int(seq)])),
            0,
        )
    }

    /// Bind the global `global` of `kind` as this client's object `new_id`.
    pub fn bind(global: u32, kind: &str, version: i32, new_id: u32) -> (u32, u8, Vec<u8>, u32) {
        (
            REGISTRY,
            REGISTRY_BIND,
            body(&Value::Struct(vec![
                Value::Int(global as i32),
                Value::String(kind.to_owned()),
                Value::Int(version),
                Value::Int(new_id as i32),
            ])),
            0,
        )
    }

    /// `key` = `value` on the metadata object `metadata`, subject 0; `None`
    /// removes the key.
    pub fn set_property(metadata: u32, key: &str, value: Option<&str>) -> (u32, u8, Vec<u8>, u32) {
        (
            metadata,
            METADATA_SET_PROPERTY,
            body(&Value::Struct(vec![
                Value::Int(0),
                Value::String(key.to_owned()),
                Value::None,
                value.map_or(Value::None, |v| Value::String(v.to_owned())),
            ])),
            0,
        )
    }

    /// `create(listen_fd, close_fd, props)` on the security context object
    /// `context`: the two descriptors go with the message, in this order, and
    /// the values name them by their index in it.
    pub fn create_context(context: u32, props: &[(&str, &str)]) -> (u32, u8, Vec<u8>, u32) {
        (
            context,
            SECURITY_CONTEXT_CREATE,
            body(&Value::Struct(vec![
                Value::Fd(0),
                Value::Fd(1),
                dict(props),
            ])),
            2,
        )
    }
}

/// What the daemon says, of what this client listens to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Ping {
        id: i32,
        seq: i32,
    },
    Error {
        id: i32,
        res: i32,
        message: String,
    },
    /// A global appeared: its id, interface and properties.
    Global {
        id: u32,
        kind: String,
        props: HashMap<String, String>,
    },
    GlobalRemove {
        id: u32,
    },
    /// A key of the bound metadata object, or all of them (`key` `None`)
    /// removed.
    Property {
        subject: u32,
        key: Option<String>,
        value: Option<String>,
    },
    /// Something this client does not act on.
    Other,
}

fn members(msg: &Incoming) -> Result<Vec<Value>, String> {
    match pod::decode(&msg.body)? {
        (Value::Struct(m), _) => Ok(m),
        _ => Err(format!(
            "message {} of object {} is not a struct",
            msg.opcode, msg.id
        )),
    }
}

fn int_at(m: &[Value], i: usize) -> Result<i32, String> {
    m.get(i)
        .and_then(Value::int)
        .ok_or_else(|| format!("no number at {i}"))
}

fn string_at(m: &[Value], i: usize) -> Result<Option<String>, String> {
    m.get(i)
        .and_then(Value::string)
        .map(|s| s.map(str::to_owned))
        .ok_or_else(|| format!("no string at {i}"))
}

/// A dictionary as the protocol writes one, into a map; a key given twice is
/// the last one's.
fn read_dict(v: Option<&Value>) -> Result<HashMap<String, String>, String> {
    let m = v.and_then(Value::members).ok_or("no dictionary")?;
    let n = int_at(m, 0)?;
    let n = usize::try_from(n).map_err(|_| "a dictionary of a negative size")?;
    if m.len() != 1 + 2 * n {
        return Err(format!("a dictionary of {n} with {} values", m.len()));
    }
    let mut out = HashMap::new();
    for i in 0..n {
        let key = string_at(m, 1 + 2 * i)?.unwrap_or_default();
        let value = string_at(m, 2 + 2 * i)?.unwrap_or_default();
        out.insert(key, value);
    }
    Ok(out)
}

/// The event `msg` is, `metadata` being the id this client bound the
/// policy's metadata object as.
pub fn event(msg: &Incoming, metadata: Option<u32>) -> Result<Event, String> {
    let as_id = |v: i32| u32::from_ne_bytes(v.to_ne_bytes());
    Ok(match (msg.id, msg.opcode) {
        (CORE, CORE_PING) => {
            let m = members(msg)?;
            Event::Ping {
                id: int_at(&m, 0)?,
                seq: int_at(&m, 1)?,
            }
        }
        (CORE, CORE_ERROR) => {
            let m = members(msg)?;
            Event::Error {
                id: int_at(&m, 0)?,
                res: int_at(&m, 2)?,
                message: string_at(&m, 3)?.unwrap_or_default(),
            }
        }
        (CORE, CORE_DONE | CORE_REMOVE_ID) => Event::Other,
        (REGISTRY, REGISTRY_GLOBAL) => {
            let m = members(msg)?;
            Event::Global {
                id: as_id(int_at(&m, 0)?),
                kind: string_at(&m, 2)?.unwrap_or_default(),
                props: read_dict(m.get(4))?,
            }
        }
        (REGISTRY, REGISTRY_GLOBAL_REMOVE) => {
            let m = members(msg)?;
            Event::GlobalRemove {
                id: as_id(int_at(&m, 0)?),
            }
        }
        (id, METADATA_PROPERTY) if Some(id) == metadata => {
            let m = members(msg)?;
            Event::Property {
                subject: as_id(int_at(&m, 0)?),
                key: string_at(&m, 1)?,
                value: string_at(&m, 3)?,
            }
        }
        _ => Event::Other,
    })
}

/// The properties every client of the zone's socket carries.
pub fn context_props(zone: &str, instance: u32) -> Vec<(&'static str, String)> {
    vec![
        ("pipewire.sec.engine", ENGINE.to_owned()),
        ("pipewire.sec.app-id", zone.to_owned()),
        ("pipewire.sec.instance-id", instance.to_string()),
        // Never a value of our own: a stock WirePlumber grants everything to
        // an access it does not know.
        ("pipewire.access", "restricted".to_owned()),
    ]
}

/// Whether the socket is to be handed to the daemon: it has a security
/// context to make one with, and the policy says it is there, in the shape
/// this build knows.
pub fn wanted(security_context: Option<u32>, policy: Option<&str>) -> bool {
    security_context.is_some() && policy == Some(POLICY_VERSION)
}

/// What the zone's microphone setting is on the PipeWire path: `ask` is
/// `no` — nothing asks here (the pulse path does).
pub fn published(setting: Setting) -> &'static str {
    match setting {
        Setting::Yes => "yes",
        Setting::No | Setting::Ask => "no",
    }
}

/// What this process says about the zone's socket, for the doctor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Handed to the daemon: the zone's programs reach PipeWire through the
    /// policy.
    Active,
    /// The daemon is there, the policy is not: connections are refused.
    NoPolicy,
    /// No daemon to reach: connections are refused.
    NoPipewire,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::NoPolicy => "no-policy",
            Self::NoPipewire => "no-pipewire",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        [Self::Active, Self::NoPolicy, Self::NoPipewire]
            .into_iter()
            .find(|s| s.word() == word.trim())
    }
}

/// The state a zone's helper last wrote, `None` when it wrote none (no
/// helper: an ordinary or an audio-manager zone, or one from before it).
pub fn read_state(zone_dir: &Path) -> Option<State> {
    State::parse(&fs::read_to_string(zone_dir.join(STATE_FILE)).ok()?)
}

/// `vpn-zone-core pipewire-context` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub listen: PathBuf,
    pub upstream: PathBuf,
    pub zone: String,
    pub zone_dir: PathBuf,
    pub config: PathBuf,
    /// `~/.local/state/vpn-profiles`: which containers are still ones
    /// (`crate::origin`).
    pub profiles: PathBuf,
    /// The holder's pid: `pipewire.sec.instance-id`.
    pub instance: u32,
}

impl Args {
    /// Every flag is required.
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut listen = None;
        let mut upstream = None;
        let mut zone = None;
        let mut zone_dir = None;
        let mut config = None;
        let mut profiles = None;
        let mut instance = None;
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
            let path = PathBuf::from(value);
            match flag.to_str() {
                Some("--listen") => listen = Some(path),
                Some("--upstream") => upstream = Some(path),
                Some("--zone") => {
                    // A name, never a path or a key of its own making: it is
                    // the policy's key and the clients' app-id.
                    zone = Some(
                        value
                            .to_str()
                            .filter(|z| {
                                !z.is_empty() && z.chars().all(|c| c.is_ascii_graphic() && c != '/')
                            })
                            .ok_or("--zone is not a zone's name")?
                            .to_owned(),
                    )
                }
                Some("--zone-dir") => zone_dir = Some(path),
                Some("--config") => config = Some(path),
                Some("--profiles") => profiles = Some(path),
                Some("--instance") => {
                    instance = Some(
                        value
                            .to_str()
                            .and_then(|v| v.parse::<u32>().ok())
                            .ok_or("--instance is not a pid")?,
                    )
                }
                _ => return Err(format!("unknown flag {}", flag.to_string_lossy())),
            }
        }
        Ok(Self {
            listen: listen.ok_or("--listen is required")?,
            upstream: upstream.ok_or("--upstream is required")?,
            zone: zone.ok_or("--zone is required")?,
            zone_dir: zone_dir.ok_or("--zone-dir is required")?,
            config: config.ok_or("--config is required")?,
            profiles: profiles.ok_or("--profiles is required")?,
            instance: instance.ok_or("--instance is required")?,
        })
    }
}

/// Where this helper reads the zone's microphone setting.
pub trait MicSource {
    fn setting(&self) -> Setting;
}

/// The zone's setting, made stricter by every container with a program
/// running in the zone (`crate::microphone::strictest_running`): this path
/// decides for all the zone's clients at once, and does not know their
/// containers yet — a container's "no" must not be passed by its zone's
/// "yes" here either.
pub struct ZoneMic {
    pub zone: String,
    pub zone_dir: PathBuf,
    pub config: PathBuf,
    pub profiles: PathBuf,
}

impl MicSource for ZoneMic {
    fn setting(&self) -> Setting {
        crate::microphone::strictest_running(
            &self.zone_dir,
            &self.config,
            &self.profiles,
            &self.zone,
        )
    }
}

/// One line on stderr (the zone's unit journal) — not the same one twice in
/// a row: a daemon that refuses the same way every second is said once.
struct Say {
    zone: String,
    last: Option<String>,
}

impl Say {
    fn say(&mut self, what: String) {
        if self.last.as_deref() != Some(what.as_str()) {
            eprintln!("pipewire-context: zone {}: {what}", self.zone);
            self.last = Some(what);
        }
    }
}

/// The helper's side of one connection to the daemon.
struct Session<'a> {
    stream: UnixStream,
    listener: &'a UnixListener,
    zone: &'a str,
    instance: u32,
    buf: Vec<u8>,
    seq: u32,
    next_id: u32,
    security_context: Option<u32>,
    security_context_proxy: Option<u32>,
    metadata: Option<u32>,
    metadata_proxy: Option<u32>,
    policy: Option<String>,
    /// The pipe's read end: while it is held, the daemon listens.
    context: Option<OwnedFd>,
    /// Where the zone's microphone setting is read.
    mic: &'a dyn MicSource,
    /// What was last published for the microphone, on this metadata object.
    mic_published: Option<&'static str>,
}

impl<'a> Session<'a> {
    fn send(
        &mut self,
        (id, opcode, body, n_fds): (u32, u8, Vec<u8>, u32),
        fds: &[i32],
    ) -> io::Result<()> {
        debug_assert_eq!(n_fds as usize, fds.len());
        self.seq = self.seq.wrapping_add(1);
        let msg = message(id, opcode, self.seq, n_fds, &body);
        crate::sys::send_with_fds(self.stream.as_raw_fd(), &msg, fds)
    }

    fn start(&mut self) -> io::Result<()> {
        self.send(request::hello(), &[])?;
        let zone = format!("{} ({})", self.zone, ENGINE);
        self.send(
            request::client_properties(&[
                ("application.name", "vpn-zone pipewire-context"),
                ("vpn-zones.zone", zone.as_str()),
            ]),
            &[],
        )?;
        self.send(request::get_registry(), &[])
    }

    fn fresh_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Read what the daemon sent and act on it. `Ok(false)` at its end.
    fn read(&mut self, say: &mut Say) -> io::Result<bool> {
        let mut chunk = vec![0u8; 64 * 1024];
        let (n, _fds, truncated) =
            crate::sys::recv_into_with_fds(self.stream.as_raw_fd(), &mut chunk, FDS_MAX)?;
        if n == 0 {
            return Ok(false);
        }
        if truncated {
            return Err(io::Error::other("descriptors lost in a read"));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        while let Some((msg, len)) = next_message(&self.buf).map_err(io::Error::other)? {
            self.buf.drain(..len);
            let ev = event(&msg, self.metadata_proxy).map_err(io::Error::other)?;
            self.act(ev, say)?;
        }
        Ok(true)
    }

    fn act(&mut self, ev: Event, say: &mut Say) -> io::Result<()> {
        match ev {
            Event::Ping { id, seq } => self.send(request::pong(id, seq), &[])?,
            Event::Error { id, res, message } => {
                // Whatever it was about, this connection is not trusted to be
                // in the state this process thinks: a new one is made.
                return Err(io::Error::other(format!(
                    "the daemon refused (object {id}, {res}): {message}"
                )));
            }
            Event::Global { id, kind, props } => {
                if kind == TYPE_SECURITY_CONTEXT && self.security_context.is_none() {
                    self.security_context = Some(id);
                } else if kind == TYPE_METADATA
                    && props.get("metadata.name").map(String::as_str) == Some(METADATA)
                    && self.metadata.is_none()
                {
                    let proxy = self.fresh_id();
                    self.send(
                        request::bind(id, TYPE_METADATA, VERSION_METADATA, proxy),
                        &[],
                    )?;
                    self.metadata = Some(id);
                    self.metadata_proxy = Some(proxy);
                    self.policy = None;
                    self.mic_published = None;
                    // At once, not on the next tick: whatever the metadata
                    // holds for this zone was left by an earlier run.
                    self.publish(false)?;
                }
            }
            Event::GlobalRemove { id } => {
                if Some(id) == self.metadata {
                    self.metadata = None;
                    self.metadata_proxy = None;
                    self.policy = None;
                    self.mic_published = None;
                }
                if Some(id) == self.security_context {
                    self.security_context = None;
                    self.security_context_proxy = None;
                }
            }
            Event::Property {
                subject: 0,
                key: Some(key),
                value,
            } if key == POLICY_KEY => self.policy = value,
            // The zone's own key, as the metadata holds it now: an earlier
            // run's value (the key outlives a helper — WirePlumber keeps it
            // for as long as it runs), or somebody else's write. Put right at
            // once; its own value coming back changes nothing.
            Event::Property {
                subject: 0,
                key: Some(key),
                value,
            } if key == self.mic_key() => {
                if value.as_deref() != self.mic_published {
                    self.mic_published = None;
                    self.publish(false)?;
                }
            }
            Event::Property { key: None, .. } => {
                self.policy = None;
                self.mic_published = None;
                self.publish(false)?;
            }
            Event::Property { .. } | Event::Other => {}
        }
        self.settle(say)
    }

    /// Hand the socket to the daemon, or take it back, as [`wanted`] says.
    fn settle(&mut self, say: &mut Say) -> io::Result<()> {
        let want = wanted(self.security_context, self.policy.as_deref());
        if want && self.context.is_none() {
            let Some(global) = self.security_context else {
                return Ok(());
            };
            // The microphone as it is NOW, before the socket is handed
            // out, on this same connection: the daemon passes the value on
            // to WirePlumber's metadata before it can accept a client of the
            // zone, so the policy never decides by a value an earlier run
            // left (`yes`, then `vpn-zone microphone <zone> no` while the
            // zone was down: a program connecting at once would record until
            // the next tick). Sent again even when it is what was published:
            // the setting may have changed since the last tick.
            self.publish(true)?;
            let proxy = match self.security_context_proxy {
                Some(p) => p,
                None => {
                    let p = self.fresh_id();
                    self.send(
                        request::bind(global, TYPE_SECURITY_CONTEXT, VERSION_SECURITY_CONTEXT, p),
                        &[],
                    )?;
                    self.security_context_proxy = Some(p);
                    p
                }
            };
            start_listening(self.listener)?;
            let (read_end, write_end) = crate::sys::pipe()?;
            let props = context_props(self.zone, self.instance);
            let props: Vec<(&str, &str)> = props.iter().map(|(k, v)| (*k, v.as_str())).collect();
            self.send(
                request::create_context(proxy, &props),
                &[self.listener.as_raw_fd(), write_end.as_raw_fd()],
            )?;
            // Only the daemon holds the write end now: its end of the pipe
            // breaks when the read end here is dropped.
            drop(write_end);
            self.context = Some(read_end);
            say.say(
                "the WirePlumber policy is active — the zone's PipeWire socket is open".to_owned(),
            );
        } else if !want && self.context.is_some() {
            self.context = None;
            say.say(
                "the WirePlumber policy is gone — the zone's PipeWire socket is closed (the pulse path stays)"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// The zone's microphone key in the metadata.
    fn mic_key(&self) -> String {
        format!("{MICROPHONE_KEY}{}", self.zone)
    }

    /// The microphone setting, published when it changed (`always`: sent
    /// whatever was published before).
    fn publish(&mut self, always: bool) -> io::Result<()> {
        let Some(proxy) = self.metadata_proxy else {
            return Ok(());
        };
        let value = published(self.mic.setting());
        if always || self.mic_published != Some(value) {
            let key = self.mic_key();
            self.send(request::set_property(proxy, &key, Some(value)), &[])?;
            self.mic_published = Some(value);
        }
        Ok(())
    }

    fn state(&self) -> State {
        if self.context.is_some() {
            State::Active
        } else {
            State::NoPolicy
        }
    }
}

/// Take every connection waiting on the socket and close it: nothing is
/// behind the socket now. Said once, not per connection (`Say`).
fn refuse_waiting(listener: &UnixListener, say: &mut Say, why: &str) {
    while let Ok((stream, _)) = listener.accept() {
        drop(stream);
        say.say(format!("a program connected — closed: {why}"));
    }
}

/// `poll(2)` on `fds` for input, for at most `timeout`; which are readable
/// (or closed).
fn poll_in(fds: &[i32], timeout: Duration) -> io::Result<Vec<bool>> {
    let mut polls: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: a valid array of pollfd of the length given.
    let n = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, ms) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(vec![false; fds.len()]);
        }
        return Err(e);
    }
    Ok(polls.iter().map(|p| p.revents != 0).collect())
}

/// Serve one connection to the daemon until it ends. `report` is told the
/// state whenever it may have changed.
fn serve(
    stream: UnixStream,
    listener: &UnixListener,
    zone: &str,
    instance: u32,
    mic: &dyn MicSource,
    say: &mut Say,
    report: &mut dyn FnMut(State),
) -> io::Result<()> {
    let mut s = Session {
        stream,
        listener,
        zone,
        instance,
        buf: Vec::new(),
        seq: 0,
        next_id: FIRST_FREE,
        security_context: None,
        security_context_proxy: None,
        metadata: None,
        metadata_proxy: None,
        policy: None,
        context: None,
        mic,
        mic_published: None,
    };
    s.start()?;
    report(s.state());
    let mut next_tick = Instant::now();
    loop {
        let mut fds = vec![s.stream.as_raw_fd()];
        if s.context.is_none() && is_listening(listener) {
            fds.push(listener.as_raw_fd());
        }
        let wait = next_tick.saturating_duration_since(Instant::now());
        let ready = poll_in(&fds, wait)?;
        if ready[0] && !s.read(say)? {
            return Ok(());
        }
        if s.context.is_none() && ready.get(1).copied().unwrap_or(false) {
            refuse_waiting(listener, say, "no WirePlumber policy of cellward");
        }
        if Instant::now() >= next_tick {
            s.publish(false)?;
            next_tick = Instant::now() + TICK;
        }
        report(s.state());
    }
}

/// Write the state for the doctor, if it changed.
fn write_state(zone_dir: &Path, state: State, last: &mut Option<State>) {
    if *last == Some(state) {
        return;
    }
    let file = zone_dir.join(STATE_FILE);
    let tmp = zone_dir.join(format!("{STATE_FILE}.tmp"));
    if fs::write(&tmp, state.word())
        .and_then(|()| fs::rename(&tmp, &file))
        .is_ok()
    {
        *last = Some(state);
    }
}

/// The zone's socket, 0600 (in the zone's directory, which is the user's and
/// closed anyway), bound and NOT listening yet: until the socket is first
/// handed to the daemon ([`start_listening`]), a program's `connect` is
/// refused at once and it takes the pulse path. Taking the connection and
/// closing it was a hang: OpenAL Soft (Telegram Desktop and its forks,
/// games) connects, then waits for its first `done` forever when the
/// connection closes under it (found on the owner's machine, 2026-09-25,
/// without the policy installed). Not blocking: a flag of the open file
/// that the daemon's copy shares, and the daemon's loop must never block in
/// `accept`.
fn listen(path: &Path) -> io::Result<UnixListener> {
    let _ = fs::remove_file(path);
    let bytes = path.as_os_str().as_encoded_bytes();
    // SAFETY: sockaddr_un is plain data.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: plain constants.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor of ours.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: a valid descriptor and an address of the length given.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(UnixListener::from(sock))
}

/// Start listening on the zone's socket, right before it is handed to the
/// daemon. It cannot stop again: once the policy has been there, a
/// connection that comes while it is gone is taken and closed
/// ([`refuse_waiting`]) — only for the moments WirePlumber restarts, and the
/// socket is handed out again when it is back.
fn start_listening(listener: &UnixListener) -> io::Result<()> {
    // SAFETY: a descriptor we hold.
    if unsafe { libc::listen(listener.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the socket listens: a stream socket that does not is "hung up"
/// to `poll`, and its `accept` fails — polled, it would spin.
fn is_listening(listener: &UnixListener) -> bool {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a descriptor we hold and an int of the length given.
    let rc = unsafe {
        libc::getsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    rc == 0 && value != 0
}

pub fn run(args: &Args) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    // Out of reach through /proc/<pid>/ of the same uid, as the sound filter
    // (`pulse_filter::run`): its fds hold the host's raw PipeWire socket.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let listener = match listen(&args.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "pipewire-context: cannot listen on {}: {e}",
                args.listen.display()
            );
            return 1;
        }
    };
    let mic = ZoneMic {
        zone: args.zone.clone(),
        zone_dir: args.zone_dir.clone(),
        config: args.config.clone(),
        profiles: args.profiles.clone(),
    };
    let mut say = Say {
        zone: args.zone.clone(),
        last: None,
    };
    if mic.setting() == Setting::Ask {
        eprintln!(
            "pipewire-context: zone {}: microphone \"ask\" — refused on the PipeWire path \
             (nothing asks there); the pulse path asks",
            args.zone
        );
    }
    let mut last_state = None;
    loop {
        match UnixStream::connect(&args.upstream) {
            Ok(stream) => {
                let zone_dir = args.zone_dir.clone();
                let mut report = |state: State| write_state(&zone_dir, state, &mut last_state);
                let result = serve(
                    stream,
                    &listener,
                    &args.zone,
                    args.instance,
                    &mic,
                    &mut say,
                    &mut report,
                );
                match result {
                    Ok(()) => say.say("PipeWire went away — waiting for it".to_owned()),
                    Err(e) => say.say(format!("PipeWire: {e} — connecting again")),
                }
            }
            Err(e) => say.say(format!(
                "no PipeWire at {} ({e}) — waiting for it",
                args.upstream.display()
            )),
        }
        write_state(&args.zone_dir, State::NoPipewire, &mut last_state);
        // Until the daemon is back, what connects is refused — by the
        // socket itself if it never listened, else closed here.
        if !is_listening(&listener) {
            std::thread::sleep(TICK);
            continue;
        }
        let until = Instant::now() + TICK;
        while let Ok(ready) = poll_in(
            &[listener.as_raw_fd()],
            until.saturating_duration_since(Instant::now()),
        ) {
            if ready[0] {
                refuse_waiting(&listener, &mut say, "PipeWire is not reachable");
            }
            if Instant::now() >= until {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::sync::mpsc;
    use std::thread;

    fn roundtrip(v: &Value) -> Value {
        let mut out = Vec::new();
        pod::encode(v, &mut out);
        assert_eq!(out.len() % 8, 0);
        let (back, n) = pod::decode(&out).unwrap();
        assert_eq!(n, out.len());
        back
    }

    fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks(4)
            .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
            .collect()
    }

    /// Hello as libpipewire writes it: id 0, opcode 1, a struct of one int.
    #[test]
    fn hello_is_what_libpipewire_sends() {
        let (id, opcode, b, n_fds) = request::hello();
        let msg = message(id, opcode, 7, n_fds, &b);
        assert_eq!(
            words(&msg),
            [
                0,
                (1 << 24) | 24,
                7,
                0,
                // struct: 16 bytes of body
                16,
                14,
                // int 4
                4,
                4,
                4,
                0
            ]
        );
    }

    /// A string counts its NUL and is padded to 8; a struct counts its
    /// members' padding.
    #[test]
    fn values_are_padded_as_spa_pads_them() {
        let mut out = Vec::new();
        pod::encode(&Value::String("pipewire".into()), &mut out);
        assert_eq!(out.len(), 8 + 16);
        assert_eq!(words(&out[..8]), [9, 8]);
        assert_eq!(&out[8..17], b"pipewire\0");
        assert!(out[17..].iter().all(|&b| b == 0));
        for v in [
            Value::None,
            Value::Int(-3),
            Value::Long(1 << 40),
            Value::Fd(1),
            Value::String(String::new()),
            Value::Struct(vec![]),
            Value::Struct(vec![
                Value::Int(1),
                Value::String("a".into()),
                Value::Struct(vec![Value::None]),
            ]),
        ] {
            assert_eq!(roundtrip(&v), v);
        }
    }

    /// The security context's create: two descriptors by index, then the
    /// dictionary — `pipewire.access` restricted, never a word of our own.
    #[test]
    fn create_names_its_two_descriptors_and_the_zone() {
        let props = context_props("nl", 4242);
        let props: Vec<(&str, &str)> = props.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (id, opcode, b, n_fds) = request::create_context(4, &props);
        assert_eq!((id, opcode, n_fds), (4, 1, 2));
        let (v, _) = pod::decode(&b).unwrap();
        let m = v.members().unwrap();
        assert_eq!(m[0], Value::Fd(0));
        assert_eq!(m[1], Value::Fd(1));
        let dict = read_dict(m.get(2)).unwrap();
        assert_eq!(dict["pipewire.sec.engine"], "vpn-zone");
        assert_eq!(dict["pipewire.sec.app-id"], "nl");
        assert_eq!(dict["pipewire.sec.instance-id"], "4242");
        assert_eq!(dict["pipewire.access"], "restricted");
        assert_eq!(dict.len(), 4);
    }

    #[test]
    fn metadata_keys_are_set_and_removed_on_subject_zero() {
        let (id, opcode, b, _) = request::set_property(3, "vpn-zones.microphone.nl", Some("yes"));
        assert_eq!((id, opcode), (3, 1));
        let (v, _) = pod::decode(&b).unwrap();
        assert_eq!(
            v,
            Value::Struct(vec![
                Value::Int(0),
                Value::String("vpn-zones.microphone.nl".into()),
                Value::None,
                Value::String("yes".into()),
            ])
        );
        let (_, _, b, _) = request::set_property(3, "k", None);
        let (v, _) = pod::decode(&b).unwrap();
        assert_eq!(v.members().unwrap()[3], Value::None);
    }

    /// A registry announcement as the daemon writes it, bytes by hand.
    #[test]
    fn a_global_reads_as_the_daemon_writes_it() {
        let mut b: Vec<u8> = Vec::new();
        let w = |b: &mut Vec<u8>, x: u32| b.extend_from_slice(&x.to_ne_bytes());
        // struct { int 42, int 0x1c8 (rwxm), string "PipeWire:Interface:Metadata",
        //          int 3, struct { int 1, string "metadata.name", string "vpn-zones" } }
        let t = b"PipeWire:Interface:Metadata\0"; // 28 bytes, padded to 32
        let dict_body = 16 + (8 + 16) + (8 + 16);
        let body = 16 + 16 + (8 + 32) + 16 + (8 + dict_body);
        w(&mut b, body as u32);
        w(&mut b, 14);
        for x in [42u32, 0o710] {
            w(&mut b, 4);
            w(&mut b, 4);
            w(&mut b, x);
            w(&mut b, 0);
        }
        w(&mut b, t.len() as u32);
        w(&mut b, 8);
        b.extend_from_slice(t);
        b.extend_from_slice(&[0; 4]);
        w(&mut b, 4);
        w(&mut b, 4);
        w(&mut b, 3);
        w(&mut b, 0);
        w(&mut b, dict_body as u32);
        w(&mut b, 14);
        w(&mut b, 4);
        w(&mut b, 4);
        w(&mut b, 1);
        w(&mut b, 0);
        for s in [&b"metadata.name\0"[..], &b"vpn-zones\0"[..]] {
            w(&mut b, s.len() as u32);
            w(&mut b, 8);
            b.extend_from_slice(s);
            b.extend(std::iter::repeat_n(0, 16 - s.len()));
        }
        let msg = message(REGISTRY, REGISTRY_GLOBAL, 0, 0, &b);
        let (incoming, len) = next_message(&msg).unwrap().unwrap();
        assert_eq!(len, msg.len());
        let Event::Global { id, kind, props } = event(&incoming, None).unwrap() else {
            panic!("not a global");
        };
        assert_eq!((id, kind.as_str()), (42, TYPE_METADATA));
        assert_eq!(props["metadata.name"], METADATA);
        // Cut anywhere, it is not there yet; one byte short of its size,
        // neither.
        for cut in [0, 5, HEADER, msg.len() - 1] {
            assert_eq!(next_message(&msg[..cut]).unwrap(), None);
        }
    }

    /// Nothing the daemon sends is trusted to be well made: a string
    /// without its NUL, a value longer than its message, a dictionary that
    /// counts wrong, structs nested without end — an error, never a panic.
    #[test]
    fn a_broken_message_is_an_error() {
        let mut s = Vec::new();
        s.extend_from_slice(&4u32.to_ne_bytes());
        s.extend_from_slice(&8u32.to_ne_bytes());
        s.extend_from_slice(b"abcd\0\0\0\0");
        assert!(pod::decode(&s).is_err());
        let mut long = Vec::new();
        long.extend_from_slice(&100u32.to_ne_bytes());
        long.extend_from_slice(&4u32.to_ne_bytes());
        long.extend_from_slice(&[0; 8]);
        assert!(pod::decode(&long).is_err());
        assert!(pod::decode(&[1, 2, 3]).is_err());
        let wrong = Value::Struct(vec![Value::Int(2), Value::String("k".into())]);
        assert!(read_dict(Some(&wrong)).is_err());
        let mut deep = Value::Int(0);
        for _ in 0..20 {
            deep = Value::Struct(vec![deep]);
        }
        let mut out = Vec::new();
        pod::encode(&deep, &mut out);
        assert!(pod::decode(&out).is_err());
        let mut huge = message(0, 0, 0, 0, &[]);
        huge[4..8].copy_from_slice(&0x00ff_ffffu32.to_ne_bytes());
        assert!(next_message(&huge).is_err());
        let not_struct = Incoming {
            id: REGISTRY,
            opcode: REGISTRY_GLOBAL,
            body: body(&Value::Int(1)),
        };
        assert!(event(&not_struct, None).is_err());
    }

    /// The socket is handed out only with a security context to make one
    /// with and the policy's own word; the microphone is yes only on yes.
    #[test]
    fn the_socket_goes_out_only_for_the_policy_and_ask_is_no_here() {
        assert!(wanted(Some(5), Some("1")));
        assert!(!wanted(None, Some("1")));
        assert!(!wanted(Some(5), None));
        assert!(!wanted(Some(5), Some("")));
        assert!(!wanted(Some(5), Some("2")));
        assert!(!wanted(Some(5), Some("1 ")));
        assert_eq!(published(Setting::Yes), "yes");
        assert_eq!(published(Setting::No), "no");
        assert_eq!(published(Setting::Ask), "no");
        for s in [State::Active, State::NoPolicy, State::NoPipewire] {
            assert_eq!(State::parse(s.word()), Some(s));
        }
        assert_eq!(State::parse("on"), None);
    }

    #[test]
    fn every_flag_is_required_and_the_zone_is_a_name() {
        let args = |list: &[&str]| -> Vec<OsString> { list.iter().map(OsString::from).collect() };
        let full = [
            "--listen",
            "/s",
            "--upstream",
            "/u",
            "--zone",
            "nl",
            "--zone-dir",
            "/z",
            "--config",
            "/c",
            "--instance",
            "77",
            "--profiles",
            "/p",
        ];
        let parsed = Args::parse(&args(&full)).unwrap();
        assert_eq!(parsed.instance, 77);
        assert_eq!(parsed.zone, "nl");
        for i in (0..full.len()).step_by(2) {
            let mut less = full.to_vec();
            less.drain(i..i + 2);
            assert!(Args::parse(&args(&less)).is_err(), "{less:?}");
        }
        for bad in ["", "a b", "a/b", "зона"] {
            let mut list = full.to_vec();
            list[5] = bad;
            assert!(Args::parse(&args(&list)).is_err(), "{bad:?}");
        }
        let mut list = full.to_vec();
        list[11] = "-1";
        assert!(Args::parse(&args(&list)).is_err());
    }

    struct FixedMic(Setting);
    impl MicSource for FixedMic {
        fn setting(&self) -> Setting {
            self.0
        }
    }

    /// A stand-in daemon on the other end of a socket pair: reads the
    /// helper's messages, with their descriptors.
    struct Daemon {
        sock: UnixStream,
        buf: Vec<u8>,
        fds: Vec<OwnedFd>,
    }

    impl Daemon {
        fn next(&mut self) -> (Incoming, Vec<OwnedFd>) {
            loop {
                if let Some((msg, len)) = next_message(&self.buf).unwrap() {
                    let n_fds = u32::from_ne_bytes(self.buf[12..16].try_into().unwrap()) as usize;
                    self.buf.drain(..len);
                    let fds: Vec<OwnedFd> = self.fds.drain(..n_fds).collect();
                    return (msg, fds);
                }
                let mut chunk = vec![0u8; 65536];
                let (n, fds, _) =
                    crate::sys::recv_into_with_fds(self.sock.as_raw_fd(), &mut chunk, 8).unwrap();
                assert!(n > 0, "the helper hung up");
                self.buf.extend_from_slice(&chunk[..n]);
                self.fds.extend(fds);
            }
        }

        fn send(&mut self, id: u32, opcode: u8, v: &Value) {
            let msg = message(id, opcode, 0, 0, &body(v));
            crate::sys::send_with_fds(self.sock.as_raw_fd(), &msg, &[]).unwrap();
        }

        fn global(&mut self, id: u32, kind: &str, props: &[(&str, &str)]) {
            self.send(
                REGISTRY,
                REGISTRY_GLOBAL,
                &Value::Struct(vec![
                    Value::Int(id as i32),
                    Value::Int(0o710),
                    Value::String(kind.into()),
                    Value::Int(3),
                    dict(props),
                ]),
            );
        }

        fn property(&mut self, proxy: u32, key: &str, value: Option<&str>) {
            self.send(
                proxy,
                METADATA_PROPERTY,
                &Value::Struct(vec![
                    Value::Int(0),
                    Value::String(key.into()),
                    Value::None,
                    value.map_or(Value::None, |v| Value::String(v.into())),
                ]),
            );
        }
    }

    /// A message that sets the zone "nl"'s microphone to `value`.
    fn assert_mic(m: &Incoming, value: &str) {
        assert_eq!((m.id, m.opcode), (3, METADATA_SET_PROPERTY));
        let (v, _) = pod::decode(&m.body).unwrap();
        assert_eq!(
            v.members().unwrap()[1],
            Value::String("vpn-zones.microphone.nl".into())
        );
        assert_eq!(v.members().unwrap()[3], Value::String(value.into()));
    }

    /// Whether the pipe's read end is gone, waiting up to `ms` for it — what
    /// the daemon's loop watches `close_fd` for (no events asked: an error
    /// is always reported).
    fn pipe_closed(write_end: &OwnedFd, ms: i32) -> bool {
        let mut p = libc::pollfd {
            fd: write_end.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        // SAFETY: one pollfd for a descriptor we hold.
        unsafe { libc::poll(&mut p, 1, ms) };
        p.revents & libc::POLLERR != 0
    }

    /// The whole exchange against a stand-in daemon: nothing is handed out
    /// before the policy's marker; with it, the listening socket and a pipe
    /// go to the daemon with the zone's properties; the microphone is
    /// published; when the metadata object goes, the pipe breaks.
    #[test]
    fn the_socket_is_handed_over_with_the_marker_and_taken_back_without() {
        let dir = std::env::temp_dir().join(format!("vpn-zone-pwctx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SOCKET);
        let listener = listen(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Before the policy the socket does not listen: a program is refused
        // at once, and does not wait on a connection that closes under it.
        assert!(!is_listening(&listener));
        let refused = UnixStream::connect(&path).unwrap_err();
        assert_eq!(
            refused.kind(),
            io::ErrorKind::ConnectionRefused,
            "{refused}"
        );
        let (helper, daemon) = UnixStream::pair().unwrap();
        let (states_tx, states_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut say = Say {
                zone: "nl".into(),
                last: None,
            };
            let mut report = |s: State| {
                let _ = states_tx.send(s);
            };
            serve(
                helper,
                &listener,
                "nl",
                4242,
                &FixedMic(Setting::Ask),
                &mut say,
                &mut report,
            )
        });
        let mut d = Daemon {
            sock: daemon,
            buf: Vec::new(),
            fds: Vec::new(),
        };
        let (m, _) = d.next();
        assert_eq!((m.id, m.opcode), (CORE, CORE_HELLO));
        let (m, _) = d.next();
        assert_eq!((m.id, m.opcode), (CLIENT, CLIENT_UPDATE_PROPERTIES));
        let (m, _) = d.next();
        assert_eq!((m.id, m.opcode), (CORE, CORE_GET_REGISTRY));

        // A metadata object of another name is not bound.
        d.global(30, TYPE_METADATA, &[("metadata.name", "default")]);
        d.global(31, TYPE_SECURITY_CONTEXT, &[]);
        d.global(32, TYPE_METADATA, &[("metadata.name", METADATA)]);
        let (m, _) = d.next();
        assert_eq!((m.id, m.opcode), (REGISTRY, REGISTRY_BIND));
        let (v, _) = pod::decode(&m.body).unwrap();
        assert_eq!(v.members().unwrap()[0], Value::Int(32));
        assert_eq!(v.members().unwrap()[3], Value::Int(3));
        // The microphone ("ask" is "no" here), at once.
        let (m, _) = d.next();
        assert_mic(&m, "no");
        // A value an earlier run left (the metadata keeps it for as long as
        // WirePlumber runs) is put right at once; the helper's own value
        // coming back changes nothing.
        d.property(3, "vpn-zones.microphone.nl", Some("yes"));
        let (m, _) = d.next();
        assert_mic(&m, "no");
        d.property(3, "vpn-zones.microphone.nl", Some("no"));
        // Another zone's key is not this helper's business.
        d.property(3, "vpn-zones.microphone.other", Some("yes"));
        // A marker of another shape is no marker: nothing is created.
        d.property(3, POLICY_KEY, Some("2"));
        // A ping is answered — and proves the marker above was read first.
        d.send(
            CORE,
            CORE_PING,
            &Value::Struct(vec![Value::Int(0), Value::Int(9)]),
        );
        let (m, _) = d.next();
        assert_eq!((m.id, m.opcode), (CORE, CORE_PONG));
        assert!(states_rx.try_iter().all(|s| s == State::NoPolicy));
        assert_eq!(
            UnixStream::connect(&path).unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );

        d.property(3, POLICY_KEY, Some(POLICY_VERSION));
        // The microphone again, BEFORE the socket goes out: the policy sees
        // this run's value when the zone's first client comes.
        let (m, _) = d.next();
        assert_mic(&m, "no");
        let (m, _) = d.next();
        assert_eq!((m.id, m.opcode), (REGISTRY, REGISTRY_BIND));
        let (v, _) = pod::decode(&m.body).unwrap();
        assert_eq!(v.members().unwrap()[0], Value::Int(31));
        assert_eq!(v.members().unwrap()[3], Value::Int(4));
        let (m, fds) = d.next();
        assert_eq!((m.id, m.opcode), (4, SECURITY_CONTEXT_CREATE));
        assert_eq!(fds.len(), 2);
        // The first is the zone's listening socket: a connection to its path
        // is waiting on it.
        let _client = UnixStream::connect(&path).unwrap();
        // SAFETY: accept on a descriptor we hold; no address wanted.
        let accepted = unsafe {
            libc::accept(
                fds[0].as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(accepted >= 0, "{}", io::Error::last_os_error());
        // SAFETY: just accepted, ours.
        drop(unsafe { OwnedFd::from_raw_fd(accepted) });
        let (v, _) = pod::decode(&m.body).unwrap();
        let dict = read_dict(v.members().unwrap().get(2)).unwrap();
        assert_eq!(dict["pipewire.sec.app-id"], "nl");
        assert_eq!(dict["pipewire.access"], "restricted");
        // The second is the pipe's write end, whole while the helper holds
        // the read end.
        assert!(!pipe_closed(&fds[1], 200));

        // The policy's metadata object goes: the context with it.
        d.send(
            REGISTRY,
            REGISTRY_GLOBAL_REMOVE,
            &Value::Struct(vec![Value::Int(32)]),
        );
        assert!(
            pipe_closed(&fds[1], 5000),
            "the daemon would go on listening"
        );
        drop(d);
        handle.join().unwrap().unwrap();
        let states: Vec<State> = states_rx.try_iter().collect();
        assert!(states.contains(&State::Active), "{states:?}");
        assert_eq!(states.last(), Some(&State::NoPolicy));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A refusal from the daemon ends the session — a new connection starts
    /// from a known state.
    #[test]
    fn an_error_from_the_daemon_ends_the_session() {
        let dir = std::env::temp_dir().join(format!("vpn-zone-pwctx-err-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let listener = listen(&dir.join(SOCKET)).unwrap();
        let (helper, daemon) = UnixStream::pair().unwrap();
        let mut d = Daemon {
            sock: daemon,
            buf: Vec::new(),
            fds: Vec::new(),
        };
        d.send(
            CORE,
            CORE_ERROR,
            &Value::Struct(vec![
                Value::Int(4),
                Value::Int(0),
                Value::Int(-1),
                Value::String("Nested security context is not allowed".into()),
            ]),
        );
        let mut say = Say {
            zone: "nl".into(),
            last: None,
        };
        let e = serve(
            helper,
            &listener,
            "nl",
            1,
            &FixedMic(Setting::Yes),
            &mut say,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("Nested"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }
}
