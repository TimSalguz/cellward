//! `pulse-filter` — the PulseAudio socket a zone gets (review 2026-09-25).
//!
//! **Why.** Every zone, the hermetic and the `offline` ones too, got the host's
//! `pulse/native`: the sound server's control socket, where a client may do
//! more than play and record. `LOAD_MODULE` with `module-tunnel-sink`,
//! `module-rtp-send` or `module-native-protocol-tcp` makes the HOST's sound
//! server connect out, or listen, in the host's network — the real address,
//! and data leaving in an audio stream, from a zone that has no network at all.
//! pipewire-pulse allows module loading by default, and a client without
//! `/.flatpak-info` is a client on the host to it. And a client may record
//! the monitor of any output: everything the host plays.
//!
//! **What.** A filter in front of the socket, started by the zone's unit on
//! the host — in the host's user namespace, out of the zone's reach through
//! `/proc` (`zone::Helpers`) — and bound into the zone as `pulse/native`. It reads the protocol's
//! frames — a 20-byte descriptor (length, channel, offset, flags; big-endian)
//! and a payload — and passes on only what an ordinary program needs:
//!
//! - **commands by an allow-list** (`rule`): the handshake, playing and
//!   recording and the control of the program's own streams, reading about
//!   the devices, events, the sample cache. Everything else — a module, the
//!   default device, moving a stream, ports, profiles, suspending, the
//!   extensions, killing, the volume of a device or of another program's
//!   stream, a number the table does not know — is answered `ERROR` with
//!   `ACCESS`, as the server answers a client it does not let, and never
//!   reaches the server;
//! - **property lists by an allow-list** (`property_allowed`): pipewire-pulse
//!   copies a client's properties into its PipeWire node, where `target.object`,
//!   `stream.capture.sink` or `media.class` would choose what a stream records
//!   (or make a record stream a sink of the host). Only the descriptive keys
//!   PulseAudio defines for clients pass; the rest are cut out of the frame;
//! - **no recording of what the host plays** (`record_refused`,
//!   `record_source_refused`): see "Monitors" below;
//! - **every tag new** (`Session::tag_refused`): the filter pairs the
//!   server's replies with the program's requests by their tags, which a
//!   program could otherwise reuse to have one reply stand for another;
//! - **a bounded read** (`MAX_VALUES`): a packet is read only for a command
//!   that may pass, after `AUTH`, and one of more values than any real
//!   command has is refused unread — a 16 MiB frame of one-byte values would
//!   otherwise cost the host some 800 MiB of the filter's memory.
//!
//! **Monitors.** A monitor is a sink's output as a source. How a record
//! stream reaches one: by the monitor's name (`<sink>.monitor`,
//! `@DEFAULT_MONITOR@`), by an index — a monitor has its sink's index in
//! pipewire-pulse, and a name that starts like a number is an index to it
//! (`atoi`, `spa_atou32`: `"0x10"` records the monitor of sink 16) —, by
//! `direct_on_input` (one stream of another program), by a target in the
//! properties, by the server's own restore of a stream it takes for another
//! program's (`application.name` is the client's word), or by the default
//! source when it is a monitor or when the server falls back to one. Names
//! alone cannot tell a monitor: a sink's plain name is not recognised as one,
//! and an index is ambiguous by construction. Two other ways were weighed and
//! not taken. Learning the source list from the client's own `GET_*` replies
//! refuses a microphone a program saved by name and did not list this time.
//! Asking the server first (`GET_SOURCE_INFO` on a connection of the filter's
//! own) answers for that moment; the stream is linked later, by the session
//! manager, which may restore or fall back to something else — the question
//! would still need the answer below. So the filter refuses, before the
//! server sees it, what names a monitor or a number (`record_refused`: a clean
//! `ERROR` for a program that asked for one), and then takes the SERVER'S
//! word: the reply to `CREATE_RECORD_STREAM` and every `RECORD_STREAM_MOVED`
//! name the source the stream is actually linked to — both servers call a
//! monitor `<sink>.monitor` there (pipewire-pulse adds the suffix itself for a
//! sink's node). A record stream the server links to a monitor, or to nothing
//! it names, closes the connection before its reply, and so before any of its
//! data, reaches the program. The server sends a record stream's data only
//! after the reply; data on a channel the filter has not seen answered is
//! dropped. A move to a monitor may let the few milliseconds of sound between
//! the relink and the server's word through; a stream the filter checked is
//! pinned to a real source, so only a device change on the host moves it. A
//! microphone and the default source (the zone can no longer change the
//! default) stay recordable — the default only while it is not a monitor,
//! and either only as the zone's microphone setting allows (below).
//!
//! **The microphone** (owner, 2026-09-25; `crate::microphone`): a record
//! stream that is not refused above goes on only as the setting of the
//! program's container says (the zone's for a program with none, or with no
//! setting of its own — `docs/PERMISSIONS.md` §11.10), read when the stream
//! is asked for. Whose program is on the other end is looked at once, when
//! it connects, by the launch it descends from (`crate::origin`) — `yes` passes it, `no` answers it
//! `ERROR`/`ACCESS`, `ask` answers it silent (`Up::Ghost`, 2026-09-29: the
//! microphone, until it is allowed, is silent) while the person on the host is
//! asked. A silent stream is the filter's own: its reply is made to be the
//! server's, it sounds silence at its rate, and the server has no stream of it
//! — nothing on the host records, nothing shows the microphone in use.
//! Allowed, the filter asks the server for the real stream itself and links it
//! to the channel the program knows (record channels are translated both ways
//! from then on: `Session::record_up`, `record_down`); refused, it stays
//! silent, and so does every later one of the connection, not asked about. The
//! connection's other commands go on meanwhile. The program's name in the
//! question is what its own properties say (`application.name`, of the stream
//! or the client), shown as its word; the zone is the one this filter was
//! started for, the container the one its launch was for.
//!
//! Descriptors (a sound server's shared memory) travel with the frame they
//! came with: on a Unix stream socket a read never runs across the start of a
//! message that carries some, so the frame that begins where such a read
//! began is theirs.
//!
//! Usage: `vpn-zone-core pulse-filter --listen <socket> --upstream <socket>
//! --zone <name> --zone-dir <dir> --config <dir> --profiles <dir> --kdialog
//! <program> [--window <program>]`.

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::microphone::{Policy, Verdict};
use crate::origin::Who;
use crate::sys;

/// The descriptor in front of every frame.
const DESCRIPTOR: usize = 20;
/// The largest frame the server accepts (pipewire-pulse `FRAME_SIZE_MAX_ALLOW`).
const FRAME_MAX: usize = 16 * 1024 * 1024;
/// The channel of a command packet; any other is a memory block of a stream.
const COMMAND_CHANNEL: u32 = u32::MAX;
/// "No index" (`PA_INVALID_INDEX`, `SPA_ID_INVALID`).
const INVALID: u32 = u32::MAX;
/// The oldest protocol the filter reads: 13 (PulseAudio 0.9.11, 2008) put the
/// property lists and `direct_on_input` into the stream requests, and every
/// libpulse since speaks 32 or newer.
const PROTOCOL_MIN: u32 = 13;
/// The protocol version in `AUTH`; above it, flags (shared memory, memfd).
const PROTOCOL_VERSION_MASK: u32 = 0xffff;
/// Streams and unanswered requests a connection may have: the filter keeps a
/// line for each, and a program does not need thousands.
const MAX_STREAMS: usize = 1024;
/// The values `parse` reads from one packet — its own values and the entries
/// of its property lists together — before it gives the packet up as
/// unreadable. A frame may be 16 MiB, and a value as short as one byte (`1`,
/// `0`, `N`) is a line of the filter's own 48 bytes: unbounded, one frame
/// would cost the host ~800 MiB, and a zone opens many connections. The
/// largest real command — a stream request with a few dozen properties and
/// its formats — has some hundreds.
const MAX_VALUES: usize = 4096;

// The tags of a packet's values (pipewire-pulse `message.h`, PulseAudio
// `tagstruct.h`): every value says what it is.
const TAG_STRING: u8 = b't';
const TAG_STRING_NULL: u8 = b'N';
const TAG_U32: u8 = b'L';
const TAG_U8: u8 = b'B';
const TAG_U64: u8 = b'R';
const TAG_S64: u8 = b'r';
const TAG_SAMPLE_SPEC: u8 = b'a';
const TAG_ARBITRARY: u8 = b'x';
const TAG_TRUE: u8 = b'1';
const TAG_FALSE: u8 = b'0';
const TAG_TIMEVAL: u8 = b'T';
const TAG_USEC: u8 = b'U';
const TAG_CHANNEL_MAP: u8 = b'm';
const TAG_CVOLUME: u8 = b'v';
const TAG_PROPLIST: u8 = b'P';
const TAG_VOLUME: u8 = b'V';
const TAG_FORMAT_INFO: u8 = b'f';

/// The commands, numbered as in pipewire-pulse `commands.h` (and PulseAudio
/// `native-common.h`): the name of command `n` is `COMMANDS[n]`.
const COMMANDS: [&str; 105] = [
    "ERROR",
    "TIMEOUT",
    "REPLY",
    "CREATE_PLAYBACK_STREAM",
    "DELETE_PLAYBACK_STREAM",
    "CREATE_RECORD_STREAM",
    "DELETE_RECORD_STREAM",
    "EXIT",
    "AUTH",
    "SET_CLIENT_NAME",
    "LOOKUP_SINK",
    "LOOKUP_SOURCE",
    "DRAIN_PLAYBACK_STREAM",
    "STAT",
    "GET_PLAYBACK_LATENCY",
    "CREATE_UPLOAD_STREAM",
    "DELETE_UPLOAD_STREAM",
    "FINISH_UPLOAD_STREAM",
    "PLAY_SAMPLE",
    "REMOVE_SAMPLE",
    "GET_SERVER_INFO",
    "GET_SINK_INFO",
    "GET_SINK_INFO_LIST",
    "GET_SOURCE_INFO",
    "GET_SOURCE_INFO_LIST",
    "GET_MODULE_INFO",
    "GET_MODULE_INFO_LIST",
    "GET_CLIENT_INFO",
    "GET_CLIENT_INFO_LIST",
    "GET_SINK_INPUT_INFO",
    "GET_SINK_INPUT_INFO_LIST",
    "GET_SOURCE_OUTPUT_INFO",
    "GET_SOURCE_OUTPUT_INFO_LIST",
    "GET_SAMPLE_INFO",
    "GET_SAMPLE_INFO_LIST",
    "SUBSCRIBE",
    "SET_SINK_VOLUME",
    "SET_SINK_INPUT_VOLUME",
    "SET_SOURCE_VOLUME",
    "SET_SINK_MUTE",
    "SET_SOURCE_MUTE",
    "CORK_PLAYBACK_STREAM",
    "FLUSH_PLAYBACK_STREAM",
    "TRIGGER_PLAYBACK_STREAM",
    "SET_DEFAULT_SINK",
    "SET_DEFAULT_SOURCE",
    "SET_PLAYBACK_STREAM_NAME",
    "SET_RECORD_STREAM_NAME",
    "KILL_CLIENT",
    "KILL_SINK_INPUT",
    "KILL_SOURCE_OUTPUT",
    "LOAD_MODULE",
    "UNLOAD_MODULE",
    "ADD_AUTOLOAD",
    "REMOVE_AUTOLOAD",
    "GET_AUTOLOAD_INFO",
    "GET_AUTOLOAD_INFO_LIST",
    "GET_RECORD_LATENCY",
    "CORK_RECORD_STREAM",
    "FLUSH_RECORD_STREAM",
    "PREBUF_PLAYBACK_STREAM",
    "REQUEST",
    "OVERFLOW",
    "UNDERFLOW",
    "PLAYBACK_STREAM_KILLED",
    "RECORD_STREAM_KILLED",
    "SUBSCRIBE_EVENT",
    "MOVE_SINK_INPUT",
    "MOVE_SOURCE_OUTPUT",
    "SET_SINK_INPUT_MUTE",
    "SUSPEND_SINK",
    "SUSPEND_SOURCE",
    "SET_PLAYBACK_STREAM_BUFFER_ATTR",
    "SET_RECORD_STREAM_BUFFER_ATTR",
    "UPDATE_PLAYBACK_STREAM_SAMPLE_RATE",
    "UPDATE_RECORD_STREAM_SAMPLE_RATE",
    "PLAYBACK_STREAM_SUSPENDED",
    "RECORD_STREAM_SUSPENDED",
    "PLAYBACK_STREAM_MOVED",
    "RECORD_STREAM_MOVED",
    "UPDATE_RECORD_STREAM_PROPLIST",
    "UPDATE_PLAYBACK_STREAM_PROPLIST",
    "UPDATE_CLIENT_PROPLIST",
    "REMOVE_RECORD_STREAM_PROPLIST",
    "REMOVE_PLAYBACK_STREAM_PROPLIST",
    "REMOVE_CLIENT_PROPLIST",
    "STARTED",
    "EXTENSION",
    "GET_CARD_INFO",
    "GET_CARD_INFO_LIST",
    "SET_CARD_PROFILE",
    "CLIENT_EVENT",
    "PLAYBACK_STREAM_EVENT",
    "RECORD_STREAM_EVENT",
    "PLAYBACK_BUFFER_ATTR_CHANGED",
    "RECORD_BUFFER_ATTR_CHANGED",
    "SET_SINK_PORT",
    "SET_SOURCE_PORT",
    "SET_SOURCE_OUTPUT_VOLUME",
    "SET_SOURCE_OUTPUT_MUTE",
    "SET_PORT_LATENCY_OFFSET",
    "ENABLE_SRBCHANNEL",
    "DISABLE_SRBCHANNEL",
    "REGISTER_MEMFD_SHMID",
    "SEND_OBJECT_MESSAGE",
];

const COMMAND_ERROR: u32 = 0;
const COMMAND_REPLY: u32 = 2;
const COMMAND_CREATE_PLAYBACK_STREAM: u32 = 3;
const COMMAND_DELETE_PLAYBACK_STREAM: u32 = 4;
const COMMAND_CREATE_RECORD_STREAM: u32 = 5;
const COMMAND_DELETE_RECORD_STREAM: u32 = 6;
const COMMAND_AUTH: u32 = 8;
const COMMAND_SET_CLIENT_NAME: u32 = 9;
const COMMAND_LOOKUP_SINK: u32 = 10;
const COMMAND_LOOKUP_SOURCE: u32 = 11;
const COMMAND_DRAIN_PLAYBACK_STREAM: u32 = 12;
const COMMAND_STAT: u32 = 13;
const COMMAND_GET_PLAYBACK_LATENCY: u32 = 14;
const COMMAND_CREATE_UPLOAD_STREAM: u32 = 15;
const COMMAND_DELETE_UPLOAD_STREAM: u32 = 16;
const COMMAND_FINISH_UPLOAD_STREAM: u32 = 17;
const COMMAND_PLAY_SAMPLE: u32 = 18;
const COMMAND_GET_SERVER_INFO: u32 = 20;
const COMMAND_GET_SINK_INFO: u32 = 21;
const COMMAND_GET_SINK_INFO_LIST: u32 = 22;
const COMMAND_GET_SOURCE_INFO: u32 = 23;
const COMMAND_GET_SOURCE_INFO_LIST: u32 = 24;
const COMMAND_GET_SINK_INPUT_INFO: u32 = 29;
const COMMAND_GET_SOURCE_OUTPUT_INFO: u32 = 31;
const COMMAND_GET_SAMPLE_INFO: u32 = 33;
const COMMAND_GET_SAMPLE_INFO_LIST: u32 = 34;
const COMMAND_SUBSCRIBE: u32 = 35;
const COMMAND_SET_SINK_INPUT_VOLUME: u32 = 37;
const COMMAND_CORK_PLAYBACK_STREAM: u32 = 41;
const COMMAND_FLUSH_PLAYBACK_STREAM: u32 = 42;
const COMMAND_TRIGGER_PLAYBACK_STREAM: u32 = 43;
const COMMAND_SET_PLAYBACK_STREAM_NAME: u32 = 46;
const COMMAND_SET_RECORD_STREAM_NAME: u32 = 47;
#[cfg(test)]
const COMMAND_KILL_CLIENT: u32 = 48;
#[cfg(test)]
const COMMAND_LOAD_MODULE: u32 = 51;
#[cfg(test)]
const COMMAND_UNLOAD_MODULE: u32 = 52;
const COMMAND_GET_RECORD_LATENCY: u32 = 57;
const COMMAND_CORK_RECORD_STREAM: u32 = 58;
const COMMAND_FLUSH_RECORD_STREAM: u32 = 59;
const COMMAND_PREBUF_PLAYBACK_STREAM: u32 = 60;
const COMMAND_PLAYBACK_STREAM_KILLED: u32 = 64;
const COMMAND_RECORD_STREAM_KILLED: u32 = 65;
const COMMAND_SET_SINK_INPUT_MUTE: u32 = 69;
const COMMAND_SET_PLAYBACK_STREAM_BUFFER_ATTR: u32 = 72;
const COMMAND_SET_RECORD_STREAM_BUFFER_ATTR: u32 = 73;
const COMMAND_UPDATE_PLAYBACK_STREAM_SAMPLE_RATE: u32 = 74;
const COMMAND_UPDATE_RECORD_STREAM_SAMPLE_RATE: u32 = 75;
const COMMAND_RECORD_STREAM_MOVED: u32 = 79;
const COMMAND_UPDATE_RECORD_STREAM_PROPLIST: u32 = 80;
const COMMAND_UPDATE_PLAYBACK_STREAM_PROPLIST: u32 = 81;
const COMMAND_UPDATE_CLIENT_PROPLIST: u32 = 82;
const COMMAND_GET_CARD_INFO: u32 = 88;
const COMMAND_GET_CARD_INFO_LIST: u32 = 89;
const COMMAND_RECORD_STREAM_SUSPENDED: u32 = 77;
const COMMAND_RECORD_STREAM_EVENT: u32 = 93;
const COMMAND_RECORD_BUFFER_ATTR_CHANGED: u32 = 95;
const COMMAND_SET_SOURCE_OUTPUT_VOLUME: u32 = 98;
const COMMAND_SET_SOURCE_OUTPUT_MUTE: u32 = 99;
/// A ring buffer in shared memory for the rest of the connection: after it,
/// commands go through it and past this filter. pipewire-pulse refuses it
/// (`do_error_access`, as `REGISTER_MEMFD_SHMID`); a PulseAudio server offers
/// it — and then the connection is closed rather than filtered no more.
const COMMAND_ENABLE_SRBCHANNEL: u32 = 101;
const COMMAND_REGISTER_MEMFD_SHMID: u32 = 103;
/// `ERR_ACCESS`.
const ERR_ACCESS: u32 = 1;
/// `ERR_NOENTITY`.
const ERR_NOENTITY: u32 = 5;

const READ_CHUNK: usize = 64 * 1024;
const MAX_FDS_PER_READ: usize = 16;
const MAX_CONNECTIONS: u32 = 128;

/// What the filter was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub listen: PathBuf,
    pub upstream: PathBuf,
    /// The zone this filter serves: the one a microphone question names.
    pub zone: String,
    /// Its state directory, where its microphone marker is.
    pub zone_dir: PathBuf,
    /// `~/.config/vpn-zones`, where `declared/microphone` is, and the
    /// containers' own settings.
    pub config: PathBuf,
    /// `~/.local/state/vpn-profiles`: the containers' data, by which a
    /// container is known to be one (`crate::origin`).
    pub profiles: PathBuf,
    /// What asks the person where there is no window.
    pub kdialog: PathBuf,
    /// The launch window (`--window`, optional), which asks first: guarded,
    /// `crate::window::question`.
    pub window: PathBuf,
    /// `--container <word>`: a container's instance's filter
    /// (`crate::instance`) — whose programs its clients are, by the instance
    /// and not by a launch in the registry (`origin::Who::from_word`).
    pub container: Option<Who>,
    /// `--userns <dev>:<ino>`: the instance's user namespace; a client not
    /// in it or below it is not known (the socket is bound into the
    /// instance alone: a second look).
    pub userns: Option<(u64, u64)>,
    /// `--network-file <path>`: the instance's `network` file — the zone
    /// whose microphone setting counts is the network the instance is in
    /// now (`microphone::Policy::following`), not only `--zone`.
    pub network: Option<PathBuf>,
}

impl Args {
    /// Every flag is required: a filter that did not know its zone could not
    /// read its microphone setting, and would have to refuse every record
    /// stream anyway.
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut listen = None;
        let mut upstream = None;
        let mut zone = None;
        let mut zone_dir = None;
        let mut config = None;
        let mut profiles = None;
        let mut kdialog = None;
        let mut window = PathBuf::new();
        let mut container = None;
        let mut userns = None;
        let mut network = None;
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
                    zone = Some(
                        value
                            .to_str()
                            .filter(|z| !z.is_empty())
                            .ok_or("--zone is not a zone's name")?
                            .to_owned(),
                    )
                }
                Some("--zone-dir") => zone_dir = Some(path),
                Some("--config") => config = Some(path),
                Some("--profiles") => profiles = Some(path),
                Some("--kdialog") => kdialog = Some(path),
                Some("--window") => window = path,
                Some("--network-file") => network = Some(path),
                Some("--container") => {
                    container = Some(Who::from_word(&value.to_string_lossy()));
                }
                Some("--userns") => {
                    userns = Some(
                        value
                            .to_str()
                            .and_then(crate::place::parse_key)
                            .ok_or("--userns is not a namespace's <dev>:<ino>")?,
                    );
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
            kdialog: kdialog.ok_or("--kdialog is required")?,
            window,
            container,
            userns,
            network,
        })
    }
}

/// The whole length of the frame at the front of `buf`, once its descriptor
/// is there; an error for a length the server would refuse too.
pub fn frame_len(buf: &[u8]) -> io::Result<Option<usize>> {
    if buf.len() < DESCRIPTOR {
        return Ok(None);
    }
    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if length == 0 || length > FRAME_MAX {
        return Err(io::Error::other(format!("a frame of {length} bytes")));
    }
    Ok(Some(DESCRIPTOR + length))
}

fn channel_of(frame: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(frame.get(4..8)?.try_into().ok()?))
}

/// The command and tag of a command packet; `None` for a stream's data.
pub fn command_of(frame: &[u8]) -> Option<(u32, u32)> {
    if channel_of(frame)? != COMMAND_CHANNEL {
        return None;
    }
    let p = frame.get(DESCRIPTOR..)?;
    if p.len() < 10 || p[0] != TAG_U32 || p[5] != TAG_U32 {
        return None;
    }
    Some((
        u32::from_be_bytes(p[1..5].try_into().ok()?),
        u32::from_be_bytes(p[6..10].try_into().ok()?),
    ))
}

/// A command's name, for the log.
pub fn command_name(command: u32) -> &'static str {
    COMMANDS
        .get(command as usize)
        .copied()
        .unwrap_or("an unknown command")
}

/// Which of a program's streams a command is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A sink input: sound the program plays.
    Playback,
    /// A source output: sound the program records.
    Record,
}

/// What the filter does with a command from the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Passed on, its property lists cut to `property_allowed`.
    Pass,
    /// Answered `ERROR`/`ACCESS` by the filter; the server never sees it.
    Refuse,
    /// The handshake: the first command, once, protocol 13 or newer.
    Auth,
    /// A new stream of the program's; its answer is watched.
    Create(Kind),
    /// The end of one of the program's streams, by its channel.
    Delete(Kind),
    /// Acts on a stream by its server-wide index (the first value): passed
    /// only for a stream this connection created.
    Own(Kind),
}

/// The allow-list. Commands that name a stream by its CHANNEL act only on the
/// connection's own streams: both servers look a channel up among the
/// client's streams alone. Commands that name a stream by its INDEX reach any
/// program's, so they are `Own`. Anything not here is refused — a command
/// added to the protocol later included.
pub fn rule(command: u32) -> Rule {
    use Kind::{Playback, Record};
    use Rule::{Auth, Create, Delete, Own, Pass, Refuse};
    match command {
        // Protocol version and cookie; nothing works before it.
        COMMAND_AUTH => Auth,
        // The program's name and properties (cut), shown in the mixer.
        COMMAND_SET_CLIENT_NAME | COMMAND_UPDATE_CLIENT_PROPLIST => Pass,
        // Play: a stream to the default output or to one the program names.
        COMMAND_CREATE_PLAYBACK_STREAM => Create(Playback),
        COMMAND_DELETE_PLAYBACK_STREAM => Delete(Playback),
        // Record: a microphone, never a monitor (`record_refused`).
        COMMAND_CREATE_RECORD_STREAM => Create(Record),
        COMMAND_DELETE_RECORD_STREAM => Delete(Record),
        // Pause, drop, play out, start now, refill: the own stream's control.
        COMMAND_CORK_PLAYBACK_STREAM
        | COMMAND_FLUSH_PLAYBACK_STREAM
        | COMMAND_DRAIN_PLAYBACK_STREAM
        | COMMAND_TRIGGER_PLAYBACK_STREAM
        | COMMAND_PREBUF_PLAYBACK_STREAM
        | COMMAND_CORK_RECORD_STREAM
        | COMMAND_FLUSH_RECORD_STREAM => Pass,
        // The own stream's timing, for audio/video sync.
        COMMAND_GET_PLAYBACK_LATENCY | COMMAND_GET_RECORD_LATENCY => Pass,
        // The own stream's name (a track title), properties (cut), buffers
        // and rate (a player that follows the file's rate).
        COMMAND_SET_PLAYBACK_STREAM_NAME
        | COMMAND_SET_RECORD_STREAM_NAME
        | COMMAND_UPDATE_PLAYBACK_STREAM_PROPLIST
        | COMMAND_UPDATE_RECORD_STREAM_PROPLIST
        | COMMAND_SET_PLAYBACK_STREAM_BUFFER_ATTR
        | COMMAND_SET_RECORD_STREAM_BUFFER_ATTR
        | COMMAND_UPDATE_PLAYBACK_STREAM_SAMPLE_RATE
        | COMMAND_UPDATE_RECORD_STREAM_SAMPLE_RATE => Pass,
        // The volume and mute of the own stream (a browser's, a player's
        // slider) — by index, so only one this connection made.
        COMMAND_SET_SINK_INPUT_VOLUME | COMMAND_SET_SINK_INPUT_MUTE => Own(Playback),
        COMMAND_SET_SOURCE_OUTPUT_VOLUME | COMMAND_SET_SOURCE_OUTPUT_MUTE => Own(Record),
        // Reading the own stream back (GStreamer, mpv read their volume so).
        // Another program's stream — its title, its binary — is not the
        // zone's to read, and the lists are refused for that.
        COMMAND_GET_SINK_INPUT_INFO => Own(Playback),
        COMMAND_GET_SOURCE_OUTPUT_INFO => Own(Record),
        // The devices, to offer outputs and microphones and follow the
        // default; a name to an index.
        COMMAND_GET_SERVER_INFO
        | COMMAND_GET_SINK_INFO
        | COMMAND_GET_SINK_INFO_LIST
        | COMMAND_GET_SOURCE_INFO
        | COMMAND_GET_SOURCE_INFO_LIST
        | COMMAND_GET_CARD_INFO
        | COMMAND_GET_CARD_INFO_LIST
        | COMMAND_LOOKUP_SINK
        | COMMAND_LOOKUP_SOURCE => Pass,
        // Change events (which object, not what), to follow a device.
        COMMAND_SUBSCRIBE => Pass,
        // The server's memory statistics (`pa_context_stat`).
        COMMAND_STAT => Pass,
        // The sample cache, for event sounds (libcanberra uploads a sound
        // once and plays it by name). Removing a sample is refused: the cache
        // is the server's, and the host's sounds are in it too.
        COMMAND_CREATE_UPLOAD_STREAM
        | COMMAND_DELETE_UPLOAD_STREAM
        | COMMAND_FINISH_UPLOAD_STREAM
        | COMMAND_PLAY_SAMPLE
        | COMMAND_GET_SAMPLE_INFO
        | COMMAND_GET_SAMPLE_INFO_LIST => Pass,
        // A memory pool for the audio data of a PulseAudio server (the ring
        // buffer that would carry commands is `ENABLE_SRBCHANNEL`, refused).
        COMMAND_REGISTER_MEMFD_SHMID => Pass,
        _ => Refuse,
    }
}

/// The keys a program's property lists keep: the ones PulseAudio defines to
/// describe a client or a stream (`proplist.h`), which no server acts on.
/// Every other key goes — PipeWire's own (`target.object`, `node.*`,
/// `stream.capture.sink`, `media.class`, `priority.*`), `device.*`,
/// `filter.*` (a PulseAudio server loads an echo canceller for it, with
/// arguments from the list) and `module-stream-restore.id` (the device the
/// server saved for another stream).
pub fn property_allowed(key: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 3] = [b"application.", b"window.", b"event."];
    const MEDIA: [&[u8]; 10] = [
        b"media.name",
        b"media.title",
        b"media.artist",
        b"media.copyright",
        b"media.software",
        b"media.language",
        b"media.filename",
        b"media.icon",
        b"media.icon_name",
        b"media.role",
    ];
    PREFIXES
        .iter()
        .any(|p| key.len() > p.len() && key.starts_with(p))
        || MEDIA.contains(&key)
}

/// One value of a packet, as much of it as the filter looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    U32(u32),
    /// A string, or the null string (`N`).
    Str(Option<Vec<u8>>),
    Bool(bool),
    /// A property list: each key and where its entry lies in the payload.
    Props(Vec<(Vec<u8>, Range<usize>)>),
    /// Any other value, by its tag.
    Other(u8),
}

/// A value and where it lies in the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub value: Value,
    pub span: Range<usize>,
}

struct Cursor<'a> {
    p: &'a [u8],
    at: usize,
    /// What is left of `MAX_VALUES`.
    left: usize,
}

impl Cursor<'_> {
    /// One more value of the packet's; `None` past `MAX_VALUES`.
    fn count(&mut self) -> Option<()> {
        self.left = self.left.checked_sub(1)?;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let bytes = self.p.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }
    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// A NUL-terminated string, without its NUL.
    fn string(&mut self) -> Option<Vec<u8>> {
        let len = self.p.get(self.at..)?.iter().position(|&b| b == 0)?;
        let s = self.take(len)?.to_vec();
        self.take(1)?;
        Some(s)
    }
    /// A property list after its `P`: as the server reads it (`read_props`),
    /// entries of a key, a length and that many bytes, until a null key.
    fn props(&mut self) -> Option<Vec<(Vec<u8>, Range<usize>)>> {
        let mut entries = Vec::new();
        loop {
            self.count()?;
            let start = self.at;
            match self.byte()? {
                TAG_STRING_NULL => return Some(entries),
                TAG_STRING => {}
                _ => return None,
            }
            let key = self.string()?;
            if self.byte()? != TAG_U32 {
                return None;
            }
            let length = self.u32()?;
            if self.byte()? != TAG_ARBITRARY {
                return None;
            }
            let size = self.u32()?;
            if length != size {
                return None;
            }
            self.take(size as usize)?;
            entries.push((key, start..self.at));
        }
    }
}

/// Every value of a command's payload, or `None` for one the filter cannot
/// read to its end, or that has more than `MAX_VALUES` — and does not pass on.
pub fn parse(payload: &[u8]) -> Option<Vec<Item>> {
    let mut c = Cursor {
        p: payload,
        at: 0,
        left: MAX_VALUES,
    };
    let mut items = Vec::new();
    while c.at < payload.len() {
        c.count()?;
        let start = c.at;
        let tag = c.byte()?;
        let value = match tag {
            TAG_U32 => Value::U32(c.u32()?),
            TAG_STRING => Value::Str(Some(c.string()?)),
            TAG_STRING_NULL => Value::Str(None),
            TAG_TRUE => Value::Bool(true),
            TAG_FALSE => Value::Bool(false),
            TAG_PROPLIST => Value::Props(c.props()?),
            TAG_U8 => c.take(1).map(|_| Value::Other(tag))?,
            TAG_VOLUME => c.take(4).map(|_| Value::Other(tag))?,
            TAG_SAMPLE_SPEC => c.take(6).map(|_| Value::Other(tag))?,
            TAG_U64 | TAG_S64 | TAG_USEC | TAG_TIMEVAL => c.take(8).map(|_| Value::Other(tag))?,
            TAG_ARBITRARY => {
                let n = c.u32()? as usize;
                c.take(n).map(|_| Value::Other(tag))?
            }
            TAG_CHANNEL_MAP => {
                let n = c.byte()? as usize;
                c.take(n).map(|_| Value::Other(tag))?
            }
            TAG_CVOLUME => {
                let n = c.byte()? as usize;
                c.take(4 * n).map(|_| Value::Other(tag))?
            }
            // An encoding and a property list of the format's own (rate,
            // channels), read by the server's format code, not a node's.
            TAG_FORMAT_INFO => {
                if c.byte()? != TAG_U8 {
                    return None;
                }
                c.take(1)?;
                if c.byte()? != TAG_PROPLIST {
                    return None;
                }
                c.props()?;
                Value::Other(tag)
            }
            _ => return None,
        };
        items.push(Item {
            value,
            span: start..c.at,
        });
    }
    Some(items)
}

fn u32_at(items: &[Item], i: usize) -> Option<u32> {
    match items.get(i)?.value {
        Value::U32(v) => Some(v),
        _ => None,
    }
}

fn str_at(items: &[Item], i: usize) -> Option<Option<&[u8]>> {
    match &items.get(i)?.value {
        Value::Str(s) => Some(s.as_deref()),
        _ => None,
    }
}

/// The value of `key` in a property list of `payload`, as text without its
/// NUL: an entry is `t` key NUL, `L` length, `x` length, the bytes (`props`).
fn property_text(
    payload: &[u8],
    entries: &[(Vec<u8>, Range<usize>)],
    key: &[u8],
) -> Option<String> {
    let (k, span) = entries.iter().find(|(k, _)| k == key)?;
    let start = span.start + 1 + k.len() + 1 + 5 + 5;
    let bytes = payload.get(start..span.end)?;
    let bytes = bytes.split(|b| *b == 0).next().unwrap_or_default();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// The program's name in the first property list among `values`: what it
/// calls itself, or its binary's name.
fn program_name(payload: &[u8], values: &[Item]) -> Option<String> {
    values.iter().find_map(|item| match &item.value {
        Value::Props(entries) => [&b"application.name"[..], b"application.process.binary"]
            .iter()
            .find_map(|key| property_text(payload, entries, key).filter(|n| !n.trim().is_empty())),
        _ => None,
    })
}

/// The frame with every key `property_allowed` does not keep cut out of its
/// top-level property lists, and the keys that went; the frame itself when
/// none did.
pub fn cut_properties(frame: &[u8], items: &[Item]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let payload = &frame[DESCRIPTOR..];
    let mut dropped = Vec::new();
    let mut out = Vec::with_capacity(payload.len());
    for item in items {
        let Value::Props(entries) = &item.value else {
            out.extend_from_slice(&payload[item.span.clone()]);
            continue;
        };
        out.push(TAG_PROPLIST);
        for (key, span) in entries {
            if property_allowed(key) {
                out.extend_from_slice(&payload[span.clone()]);
            } else {
                dropped.push(key.clone());
            }
        }
        out.push(TAG_STRING_NULL);
    }
    if dropped.is_empty() {
        return (frame.to_vec(), dropped);
    }
    let mut cut = Vec::with_capacity(DESCRIPTOR + out.len());
    cut.extend_from_slice(&(out.len() as u32).to_be_bytes());
    cut.extend_from_slice(&frame[4..DESCRIPTOR]);
    cut.extend_from_slice(&out);
    (cut, dropped)
}

/// Whether a source name is a number to the server: pipewire-pulse takes the
/// `atoi` of it as an index when it is not 0, and `find_device` any name
/// `strtoul` reads whole (`"0x10"`, `" +7"`). Both begin, after blanks and a
/// sign, with a digit — refusing every such name is refusing more than both.
fn looks_like_index(name: &[u8]) -> bool {
    // C's `isspace`: the vertical tab too, which `trim_ascii` keeps.
    let blanks = name
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    let rest = &name[blanks..];
    let rest = rest
        .strip_prefix(b"+")
        .or_else(|| rest.strip_prefix(b"-"))
        .unwrap_or(rest);
    rest.first().is_some_and(u8::is_ascii_digit)
}

/// A capture device's node, by the name the host's session manager gives it
/// (ALSA's and Bluetooth's inputs): what a record stream may be moved to
/// besides the source it had.
fn a_capture_device(name: &[u8]) -> bool {
    [&b"alsa_input."[..], b"bluez_input.", b"bluez_source."]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// A source name that is a monitor by name alone.
fn names_a_monitor(name: &[u8]) -> bool {
    name.ends_with(b".monitor") || name == b"@DEFAULT_MONITOR@"
}

/// Why a `CREATE_RECORD_STREAM` is refused before the server sees it, if it
/// is. `values` are the request's after its command and tag, protocol 13 or
/// newer: sample spec, channel map, source index, source name, maximum
/// length, corked, fragment size, seven flags, peak detection, latency
/// adjustment, properties, `direct_on_input` (pipewire-pulse
/// `do_create_record_stream`). What gets through is the default source or a
/// source by a name — and the server's own answer is checked after
/// (`record_source_refused`).
pub fn record_refused(values: &[Item]) -> Option<&'static str> {
    let layout = [
        TAG_SAMPLE_SPEC,
        TAG_CHANNEL_MAP,
        TAG_U32,
        TAG_STRING,
        TAG_U32,
        TAG_TRUE,
        TAG_U32,
    ];
    let kind_ok = |i: usize, tag: u8| match (values.get(i).map(|v| &v.value), tag) {
        (Some(Value::Other(t)), _) => *t == tag,
        (Some(Value::U32(_)), TAG_U32) => true,
        (Some(Value::Str(_)), TAG_STRING) => true,
        (Some(Value::Bool(_)), TAG_TRUE) => true,
        _ => false,
    };
    let unreadable = Some("a request the filter cannot read");
    if !layout.iter().enumerate().all(|(i, &t)| kind_ok(i, t))
        || !(7..16).all(|i| kind_ok(i, TAG_TRUE))
        || !matches!(values.get(16).map(|v| &v.value), Some(Value::Props(_)))
    {
        return unreadable;
    }
    let (Some(index), Some(name), Some(direct)) =
        (u32_at(values, 2), str_at(values, 3), u32_at(values, 17))
    else {
        return unreadable;
    };
    if direct != INVALID {
        return Some("another program's stream (direct_on_input)");
    }
    if index != INVALID {
        return Some("a source by its index");
    }
    match name {
        Some(n) if names_a_monitor(n) => Some("a monitor"),
        Some(n) if looks_like_index(n) => Some("a source by its index"),
        _ => None,
    }
}

/// Whether the source the server names for a record stream — in its reply to
/// `CREATE_RECORD_STREAM` or in `RECORD_STREAM_MOVED` — is one the zone may
/// not hear: a monitor, or none named at all.
pub fn record_source_refused(name: Option<&[u8]>) -> bool {
    name.is_none_or(names_a_monitor)
}

// --- A SILENT MICROPHONE ------------------------------------------------------
// The owner (docs/PERMISSIONS.md §11.15, 2026-09-29): the microphone, until
// it is allowed, is silent. A record stream the person is asked about — and
// one of a connection whose microphone they refused — is answered by the
// filter itself (a "ghost"): the program gets a stream that records silence
// at its rate, and nothing records on the host — the server has no stream of
// it, so nothing shows the microphone in use. Allowed, the filter makes the
// real stream and links it to the channel the program knows; the two ends
// may know a record stream by different channels from then on, and the
// filter translates them (`Session::record_up`, `record_down`).

/// Commands about a record stream by its channel, the first value.
const RECORD_CHANNEL_COMMANDS: [u32; 8] = [
    COMMAND_DELETE_RECORD_STREAM,
    COMMAND_SET_RECORD_STREAM_NAME,
    COMMAND_GET_RECORD_LATENCY,
    COMMAND_CORK_RECORD_STREAM,
    COMMAND_FLUSH_RECORD_STREAM,
    COMMAND_SET_RECORD_STREAM_BUFFER_ATTR,
    COMMAND_UPDATE_RECORD_STREAM_SAMPLE_RATE,
    COMMAND_UPDATE_RECORD_STREAM_PROPLIST,
];
/// The server's words about a record stream by its channel, the first value.
const RECORD_CHANNEL_EVENTS: [u32; 5] = [
    COMMAND_RECORD_STREAM_KILLED,
    COMMAND_RECORD_STREAM_SUSPENDED,
    COMMAND_RECORD_STREAM_MOVED,
    COMMAND_RECORD_STREAM_EVENT,
    COMMAND_RECORD_BUFFER_ATTR_CHANGED,
];
/// The filter's own requests to the server are tagged from here: libpulse
/// counts its tags up from 0.
const OWN_TAGS: u32 = 0xfff0_0000;
/// The source-output indices the filter makes up for its silent streams
/// start here: the servers' are small.
const GHOST_INDICES: u32 = 0x7ff0_0000;
/// Silent streams of one connection at once: a thread each.
const MAX_GHOSTS: usize = 8;
/// A silent stream's buffer, when the program left it to the server.
const GHOST_MAXLENGTH: u32 = 4 * 1024 * 1024;
/// A silent stream's fragment, when the program left it to the server: the
/// sound comes in pieces of this much, as from a server.
const GHOST_FRAGMENT_MS: u64 = 20;

/// A sample spec as the protocol carries it (`a`): format, channels, rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Spec {
    format: u8,
    channels: u8,
    rate: u32,
}

impl Spec {
    /// From a value's bytes: `a`, the format, the channels, the rate.
    fn of(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [TAG_SAMPLE_SPEC, format, channels, r0, r1, r2, r3] => Some(Self {
                format: *format,
                channels: *channels,
                rate: u32::from_be_bytes([*r0, *r1, *r2, *r3]),
            }),
            _ => None,
        }
    }

    /// Bytes of one frame (a sample of every channel); `None` for a format
    /// the protocol does not have, or no channel, or no rate.
    fn frame_bytes(&self) -> Option<u32> {
        let sample = match self.format {
            // u8, A-law, µ-law.
            0..=2 => 1,
            // s16 le/be.
            3 | 4 => 2,
            // float32, s32, le/be.
            5..=8 => 4,
            // s24 le/be.
            9 | 10 => 3,
            // s24-32 le/be.
            11 | 12 => 4,
            _ => return None,
        };
        (self.channels > 0 && self.rate > 0).then(|| sample * u32::from(self.channels))
    }

    /// The byte silence is made of: u8's middle, A-law's and µ-law's zero.
    fn silence(&self) -> u8 {
        match self.format {
            0 => 0x80,
            1 => 0xd5,
            2 => 0xff,
            _ => 0,
        }
    }

    /// Bytes of sound per second.
    fn bytes_per_second(&self) -> u64 {
        u64::from(self.frame_bytes().unwrap_or(1)) * u64::from(self.rate)
    }
}

/// Where a silent stream is on its way to the real one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Link {
    /// Silent: not allowed (yet).
    Silent,
    /// Allowed: the real stream asked for with this tag of the filter's,
    /// corked as it was then.
    Making { tag: u32, corked: bool },
    /// The real stream, by the server's channel and index.
    Linked { channel: u32, index: u32 },
}

/// A record stream the filter answered itself (a "ghost").
#[derive(Debug)]
struct Ghost {
    /// Its source output's index, as the program was told.
    index: u32,
    /// The program's request, its properties cut: the real stream's.
    request: Vec<u8>,
    spec: Spec,
    maxlength: u32,
    fragsize: u32,
    corked: bool,
    /// Bytes of silence sent: its read and write index both.
    sent: u64,
    link: Link,
}

/// What a request of the filter's own is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Own {
    /// A silent stream's real one, by the program's channel.
    Link(u32),
    /// Nothing: its answer is dropped.
    Discard,
}

/// A frame of the protocol: the command channel's, or a stream's data.
fn frame_of(channel: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(DESCRIPTOR + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&channel.to_be_bytes());
    frame.extend_from_slice(&[0u8; 12]);
    frame.extend_from_slice(payload);
    frame
}

fn put_u32(p: &mut Vec<u8>, value: u32) {
    p.push(TAG_U32);
    p.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(p: &mut Vec<u8>, tag: u8, value: u64) {
    p.push(tag);
    p.extend_from_slice(&value.to_be_bytes());
}

/// `REPLY` to the command tagged `tag`, with `values` after it.
fn reply_frame(tag: u32, values: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(10 + values.len());
    put_u32(&mut p, COMMAND_REPLY);
    put_u32(&mut p, tag);
    p.extend_from_slice(values);
    frame_of(COMMAND_CHANNEL, &p)
}

/// A command of the filter's own: `command`, its tag, `values` after them.
fn command_frame(command: u32, tag: u32, values: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(10 + values.len());
    put_u32(&mut p, command);
    put_u32(&mut p, tag);
    p.extend_from_slice(values);
    frame_of(COMMAND_CHANNEL, &p)
}

/// What becomes of a command's numbers of a record stream
/// (`Session::record_numbers`).
enum Numbers {
    /// None of them is the filter's: as it came.
    Same,
    /// Told the server's numbers: this frame instead.
    Rewritten(Vec<u8>),
    /// A silent stream's: answered by the filter.
    Answer(Up),
}

/// `ERROR` for the command tagged `tag`.
fn error_of(tag: u32, error: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(15);
    put_u32(&mut p, COMMAND_ERROR);
    put_u32(&mut p, tag);
    put_u32(&mut p, error);
    frame_of(COMMAND_CHANNEL, &p)
}

/// `bytes` of silence of `spec` on `channel`, as a server sends a record
/// stream's sound: inline, from where the last piece ended.
fn silence_frame(channel: u32, spec: Spec, bytes: usize) -> Vec<u8> {
    frame_of(channel, &vec![spec.silence(); bytes])
}

/// The u32 value `item` of `frame`'s payload set to `value`.
fn set_u32(frame: &mut [u8], item: &Item, value: u32) {
    let at = DESCRIPTOR + item.span.start + 1;
    frame[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// The boolean value `item` of `frame`'s payload set to `value`.
fn set_bool(frame: &mut [u8], item: &Item, value: bool) {
    frame[DESCRIPTOR + item.span.start] = if value { TAG_TRUE } else { TAG_FALSE };
}

/// Now, as `T` carries a time: the seconds and microseconds since the epoch.
fn now_timeval() -> [u8; 9] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 9];
    out[0] = TAG_TIMEVAL;
    out[1..5].copy_from_slice(&(now.as_secs() as u32).to_be_bytes());
    out[5..9].copy_from_slice(&now.subsec_micros().to_be_bytes());
    out
}

/// What becomes of a frame from the zone.
#[derive(Debug, PartialEq, Eq)]
enum Up {
    /// On to the server, perhaps with properties cut.
    Forward(Vec<u8>),
    /// Answered `ERROR`/`ACCESS` for this tag, and why.
    Refuse(u32, String),
    /// Answered by the filter itself: this frame to the program.
    Answer(Vec<u8>),
    /// A record stream answered by the filter itself, silent (a ghost): its
    /// reply to the program, its channel there, and the question about it —
    /// the program's name and whether "always" may be offered —, none when
    /// the person refused this connection the microphone. The zone's one
    /// open question is this one (`Policy::decide`).
    Ghost {
        channel: u32,
        reply: Vec<u8>,
        ask: Option<(String, bool)>,
    },
    /// The connection ends.
    Close(String),
}

/// What becomes of a frame from the server.
#[derive(Debug, PartialEq, Eq)]
enum Down {
    Forward,
    /// On to the program as this: a record stream's channel told as the
    /// program knows it.
    Rewritten(Vec<u8>),
    /// An answer to the filter's own request: not the program's; this, if
    /// anything, to the server.
    Own(Option<Vec<u8>>),
    /// Not for the program: data on a channel it has no checked record
    /// stream on.
    Drop,
    Close(String),
}

/// What the filter knows of one connection. Both directions share it: the
/// zone's side asks, the server's side answers.
#[derive(Debug, Default)]
struct Session {
    /// `AUTH` has passed.
    authed: bool,
    /// The tag of the program's last command (`tag_refused`).
    last_tag: Option<u32>,
    /// Streams asked for and not answered yet, by the request's tag.
    creating: HashMap<u32, Kind>,
    /// The connection's streams: by kind and channel, their server index.
    streams: HashMap<(Kind, u32), u32>,
    /// The source each record stream is linked to, by channel: the server's
    /// word, at its start and at every move let through.
    sources: HashMap<u32, Vec<u8>>,
    /// The generation of the microphone's setting last looked at
    /// ([`Session::microphone_taken_away`]).
    mic_seen: u64,
    /// A cut has been logged on this connection.
    told_cut: bool,
    /// The zone's microphone setting and its question
    /// (`crate::microphone`); by default one that never records.
    mic: Arc<Policy>,
    /// Whose program is on the other end (`crate::origin`), looked at when
    /// it connected: the microphone is decided by its container.
    who: Who,
    /// Its pid, the host's: where its launch is found for a question on
    /// its window (`crate::onwindow`).
    peer: Option<i32>,
    /// What the program calls itself (`SET_CLIENT_NAME`,
    /// `UPDATE_CLIENT_PROPLIST`): its word, for the question only.
    client_name: Option<String>,
    /// The person refused a record stream of this connection: its retries
    /// are silent without asking again.
    mic_denied: bool,
    /// The protocol version both ends speak: the program's (`AUTH`), then
    /// the lower of it and the server's (its reply).
    version: u32,
    /// The tag of `AUTH`, whose reply says the server's version.
    auth_tag: Option<u32>,
    /// Record streams the program knows by another channel than the
    /// server's: its channel → the server's, and back.
    record_up: HashMap<u32, u32>,
    record_down: HashMap<u32, u32>,
    /// The silent record streams, by the program's channel.
    ghosts: HashMap<u32, Ghost>,
    /// How many ghosts this connection has had: their made-up indices.
    ghosts_made: u32,
    /// The filter's own requests to the server, by their tags.
    own: HashMap<u32, Own>,
    own_made: u32,
}

impl Session {
    /// Why a command's tag is refused, if it is. The server answers a command
    /// by its tag, and the filter pairs a reply with the stream request it
    /// answers by that tag alone: a tag used twice would let the reply to
    /// another command stand for it — `CREATE_UPLOAD_STREAM` answers with a
    /// channel and the length the program asked for, which would read as a
    /// playback stream's channel and index, and the program would "own"
    /// another program's stream. libpulse counts its tags up from 0
    /// (`ctag++`), so every tag must be above the last one. The one exception
    /// is `REGISTER_MEMFD_SHMID`, which libpulse's stream layer sends with
    /// the tag `-1` and no reply.
    fn tag_refused(&mut self, command: u32, tag: u32) -> Option<&'static str> {
        if tag == INVALID {
            return (command != COMMAND_REGISTER_MEMFD_SHMID).then_some("the tag -1");
        }
        if self.last_tag.is_some_and(|last| tag <= last) {
            return Some("a tag not above the last one");
        }
        self.last_tag = Some(tag);
        None
    }

    fn up(&mut self, frame: &[u8]) -> Up {
        if channel_of(frame) != Some(COMMAND_CHANNEL) {
            // A stream's data: the server takes it only on the client's own
            // channels.
            return Up::Forward(frame.to_vec());
        }
        let Some((command, tag)) = command_of(frame) else {
            return Up::Close("a command the filter cannot read".to_owned());
        };
        let name = command_name(command);
        if let Some(why) = self.tag_refused(command, tag) {
            return Up::Refuse(tag, format!("{name}: {why}"));
        }
        // What is refused anyway is refused unread: the packet is read — the
        // costliest thing the filter does for a program — only for a command
        // it may pass, and only after AUTH, AUTH itself aside.
        let rule = rule(command);
        match rule {
            Rule::Refuse => return Up::Refuse(tag, name.to_owned()),
            Rule::Auth if self.authed => return Up::Refuse(tag, "a second AUTH".to_owned()),
            Rule::Auth => {}
            _ if !self.authed => return Up::Refuse(tag, format!("{name} before AUTH")),
            _ => {}
        }
        let Some(mut items) = parse(&frame[DESCRIPTOR..]) else {
            return Up::Refuse(tag, format!("{name} (unreadable)"));
        };
        // A record stream the program knows by other numbers than the
        // server's: a silent one's command is answered here, a linked or
        // moved one's goes on with the server's numbers.
        let rewritten;
        let frame = match self.record_numbers(command, tag, frame, &mut items) {
            Numbers::Answer(up) => return up,
            Numbers::Rewritten(f) => {
                rewritten = f;
                &rewritten[..]
            }
            Numbers::Same => frame,
        };
        let payload = &frame[DESCRIPTOR..];
        let values = &items[2..];
        // A record stream answered silent by the filter (`Up::Ghost`): the
        // question about it — its program, and whether "always" may be
        // offered —, none when the person refused the connection already.
        let mut silent: Option<Option<(String, bool)>> = None;
        match rule {
            Rule::Refuse => return Up::Refuse(tag, name.to_owned()),
            Rule::Auth => {
                // The server reads every later request by this version:
                // from 13 on, the flags above it are taken off (both servers).
                match u32_at(values, 0) {
                    Some(v) if v & PROTOCOL_VERSION_MASK >= PROTOCOL_MIN => {
                        self.version = v & PROTOCOL_VERSION_MASK;
                    }
                    _ => return Up::Refuse(tag, "AUTH below protocol 13".to_owned()),
                }
                self.authed = true;
                self.auth_tag = Some(tag);
                return Up::Forward(frame.to_vec());
            }
            Rule::Pass => {
                if matches!(
                    command,
                    COMMAND_SET_CLIENT_NAME | COMMAND_UPDATE_CLIENT_PROPLIST
                ) {
                    if let Some(program) = program_name(payload, values) {
                        self.client_name = Some(program);
                    }
                }
            }
            Rule::Create(kind) => {
                if self.creating.contains_key(&tag)
                    || self.creating.len() >= MAX_STREAMS
                    || self.streams.len() >= MAX_STREAMS
                {
                    return Up::Refuse(tag, format!("{name} (too many streams)"));
                }
                if kind == Kind::Record {
                    if let Some(why) = record_refused(values) {
                        return Up::Refuse(tag, format!("{name}: {why}"));
                    }
                    // Not a monitor: a microphone, by the setting of the
                    // program's container.
                    // `record_refused` has checked that values[16] are the
                    // stream's properties.
                    if self.mic_denied {
                        // Refused by the person once: silent, not asked again.
                        silent = Some(None);
                    } else {
                        let program = program_name(payload, &values[16..17])
                            .or_else(|| self.client_name.clone())
                            .unwrap_or_default();
                        match self.mic.decide(&program, &self.who) {
                            Verdict::Allow => {}
                            Verdict::Refuse(why) => {
                                return Up::Refuse(tag, format!("{name}: microphone: {why}"))
                            }
                            Verdict::Ask { remember } => silent = Some(Some((program, remember))),
                        }
                    }
                }
                // A silent stream is not the server's until it is allowed.
                if silent.is_none() {
                    self.creating.insert(tag, kind);
                }
            }
            Rule::Delete(kind) => {
                let Some(channel) = u32_at(values, 0) else {
                    return Up::Refuse(tag, format!("{name} (unreadable)"));
                };
                self.streams.remove(&(kind, channel));
                if kind == Kind::Record {
                    self.sources.remove(&channel);
                    // A stream the program knew by another channel: gone
                    // from the translation, and a linked ghost with it.
                    if let Some(client) = self.record_down.remove(&channel) {
                        self.record_up.remove(&client);
                        self.ghosts.remove(&client);
                    }
                }
            }
            Rule::Own(kind) => {
                let own = u32_at(values, 0).is_some_and(|index| {
                    self.streams
                        .iter()
                        .any(|((k, _), i)| *k == kind && *i == index)
                });
                if !own {
                    return Up::Refuse(tag, format!("{name} of a stream not its own"));
                }
            }
        }
        let (frame, dropped) = cut_properties(frame, &items);
        if !dropped.is_empty() && !self.told_cut {
            self.told_cut = true;
            let keys: Vec<String> = dropped
                .iter()
                .take(8)
                .map(|k| String::from_utf8_lossy(k).escape_debug().to_string())
                .collect();
            eprintln!(
                "pulse-filter: properties cut from {name}: {}",
                keys.join(", ")
            );
        }
        if let Some(ask) = silent {
            return self.ghost(tag, frame, ask);
        }
        Up::Forward(frame)
    }

    /// Whether the program knows a record stream by channel `c`: a silent
    /// one's, one it is told by another channel than the server's, or a
    /// stream of the server's told as it is.
    fn record_channel_taken(&self, c: u32) -> bool {
        self.ghosts.contains_key(&c)
            || self.record_down.values().any(|v| *v == c)
            || (self.streams.contains_key(&(Kind::Record, c)) && !self.record_down.contains_key(&c))
    }

    /// The lowest record channel the program knows no stream by: libpulse
    /// keeps its record streams in an array by channel.
    fn free_channel(&self) -> u32 {
        (0..u32::MAX)
            .find(|c| !self.record_channel_taken(*c))
            .unwrap_or(0)
    }

    /// A tag of the filter's own for a request to the server.
    fn own_tag(&mut self, what: Own) -> u32 {
        let tag = OWN_TAGS.wrapping_add(self.own_made);
        self.own_made = self.own_made.wrapping_add(1);
        self.own.insert(tag, what);
        tag
    }

    /// A command about a record stream (`RECORD_CHANNEL_COMMANDS`, or a
    /// source output's by its index) whose numbers the program knows
    /// otherwise than the server: a silent stream's is answered here, a
    /// linked or moved one's rewritten to the server's numbers — in the
    /// frame and in `items` both.
    fn record_numbers(
        &mut self,
        command: u32,
        tag: u32,
        frame: &[u8],
        items: &mut [Item],
    ) -> Numbers {
        let Some(Value::U32(first)) = items.get(2).map(|i| i.value.clone()) else {
            return Numbers::Same;
        };
        let rewrite = |items: &mut [Item], value: u32| {
            let mut f = frame.to_vec();
            set_u32(&mut f, &items[2], value);
            items[2].value = Value::U32(value);
            Numbers::Rewritten(f)
        };
        if RECORD_CHANNEL_COMMANDS.contains(&command) {
            let silent = self
                .ghosts
                .get(&first)
                .is_some_and(|g| !matches!(g.link, Link::Linked { .. }));
            if silent {
                return Numbers::Answer(self.ghost_command(command, tag, first, frame, items));
            }
            if let Some(&server) = self.record_up.get(&first) {
                return rewrite(items, server);
            }
        }
        if matches!(
            command,
            COMMAND_SET_SOURCE_OUTPUT_VOLUME
                | COMMAND_SET_SOURCE_OUTPUT_MUTE
                | COMMAND_GET_SOURCE_OUTPUT_INFO
        ) {
            if let Some(g) = self.ghosts.values().find(|g| g.index == first) {
                return match g.link {
                    Link::Linked { index, .. } => rewrite(items, index),
                    // A silent stream has no volume the server knows.
                    _ if command == COMMAND_GET_SOURCE_OUTPUT_INFO => {
                        Numbers::Answer(Up::Answer(error_of(tag, ERR_NOENTITY)))
                    }
                    _ => Numbers::Answer(Up::Answer(reply_frame(tag, &[]))),
                };
            }
        }
        Numbers::Same
    }

    /// A command about a silent stream, answered as a server would.
    fn ghost_command(
        &mut self,
        command: u32,
        tag: u32,
        channel: u32,
        frame: &[u8],
        items: &[Item],
    ) -> Up {
        let version = self.version;
        let payload = &frame[DESCRIPTOR..];
        let values = &items[2..];
        if command == COMMAND_DELETE_RECORD_STREAM {
            // Its real stream, if one is being made, is deleted when it is.
            self.ghosts.remove(&channel);
            return Up::Answer(reply_frame(tag, &[]));
        }
        let Some(g) = self.ghosts.get_mut(&channel) else {
            return Up::Answer(error_of(tag, ERR_NOENTITY));
        };
        let mut out = Vec::new();
        match command {
            COMMAND_CORK_RECORD_STREAM => {
                if let Some(Value::Bool(corked)) = values.get(1).map(|i| &i.value) {
                    g.corked = *corked;
                }
            }
            COMMAND_SET_RECORD_STREAM_BUFFER_ATTR => {
                let frame_bytes = g.spec.frame_bytes().unwrap_or(1);
                if let Some(m) = u32_at(values, 1).filter(|m| *m != INVALID && *m > 0) {
                    g.maxlength = m.min(GHOST_MAXLENGTH);
                }
                if let Some(f) = u32_at(values, 2).filter(|f| *f != INVALID && *f >= frame_bytes) {
                    g.fragsize = (f - f % frame_bytes).min(g.maxlength.max(frame_bytes));
                }
                put_u32(&mut out, g.maxlength);
                put_u32(&mut out, g.fragsize);
                if version >= 13 {
                    put_u64(&mut out, TAG_USEC, 0);
                }
            }
            COMMAND_UPDATE_RECORD_STREAM_SAMPLE_RATE => {
                if let Some(rate) = u32_at(values, 1).filter(|r| (1..=384_000).contains(r)) {
                    g.spec.rate = rate;
                }
            }
            COMMAND_GET_RECORD_LATENCY => {
                put_u64(&mut out, TAG_USEC, 0);
                put_u64(&mut out, TAG_USEC, 0);
                out.push(if g.corked { TAG_FALSE } else { TAG_TRUE });
                // The program's own time back, then now.
                match values.get(1).and_then(|i| payload.get(i.span.clone())) {
                    Some(time) if time.first() == Some(&TAG_TIMEVAL) => out.extend_from_slice(time),
                    _ => out.extend_from_slice(&now_timeval()),
                }
                out.extend_from_slice(&now_timeval());
                put_u64(&mut out, TAG_S64, g.sent);
                put_u64(&mut out, TAG_S64, g.sent);
            }
            // Flushed, named, its properties: nothing to keep of them.
            _ => {}
        }
        Up::Answer(reply_frame(tag, &out))
    }

    /// A record stream answered silent by the filter (`request`, its
    /// properties cut, tagged `tag`): its reply to the program, as the
    /// server's would be at this connection's version, and the question
    /// about it (`ask`). Refused where the zone's question was taken and
    /// the stream cannot be made: too many, a format without a silence.
    fn ghost(&mut self, tag: u32, request: Vec<u8>, ask: Option<(String, bool)>) -> Up {
        let refused = |s: &Self, why: &str| {
            if ask.is_some() {
                s.mic.abandon();
            }
            Up::Refuse(tag, format!("CREATE_RECORD_STREAM: {why}"))
        };
        if self.ghosts.len() >= MAX_GHOSTS {
            return refused(self, "too many silent record streams");
        }
        let Some(items) = parse(&request[DESCRIPTOR..]) else {
            return refused(self, "unreadable");
        };
        let payload = &request[DESCRIPTOR..];
        let values = &items[2..];
        let spec = values
            .first()
            .and_then(|i| Spec::of(payload.get(i.span.clone())?));
        let Some((spec, frame_bytes)) = spec.and_then(|s| Some((s, s.frame_bytes()?))) else {
            return refused(self, "a sample format the filter makes no silence of");
        };
        let maxlength = u32_at(values, 4)
            .filter(|m| *m != INVALID && *m > 0)
            .map_or(GHOST_MAXLENGTH, |m| m.min(GHOST_MAXLENGTH))
            .max(frame_bytes);
        let fragment =
            u32::try_from(spec.bytes_per_second() * GHOST_FRAGMENT_MS / 1000).unwrap_or(maxlength);
        let fragsize = u32_at(values, 6)
            .filter(|f| *f != INVALID && *f >= frame_bytes)
            .unwrap_or(fragment);
        let fragsize = (fragsize - fragsize % frame_bytes).clamp(frame_bytes, maxlength);
        let corked = matches!(values.get(5).map(|i| &i.value), Some(Value::Bool(true)));
        let channel = self.free_channel();
        let index = GHOST_INDICES.wrapping_add(self.ghosts_made);
        self.ghosts_made = self.ghosts_made.wrapping_add(1);
        let mut out = Vec::new();
        put_u32(&mut out, channel);
        put_u32(&mut out, index);
        if self.version >= 9 {
            put_u32(&mut out, maxlength);
            put_u32(&mut out, fragsize);
        }
        if self.version >= 12 {
            // The format and the map as the program asked for them; the
            // source it named, else the default one; not suspended.
            out.extend_from_slice(&payload[values[0].span.clone()]);
            out.extend_from_slice(&payload[values[1].span.clone()]);
            put_u32(&mut out, INVALID);
            out.push(TAG_STRING);
            out.extend_from_slice(
                str_at(values, 3)
                    .flatten()
                    .unwrap_or(&b"@DEFAULT_SOURCE@"[..]),
            );
            out.push(0);
            out.push(TAG_FALSE);
        }
        if self.version >= 13 {
            put_u64(&mut out, TAG_USEC, 0);
        }
        if self.version >= 22 {
            // PCM, and nothing more said of it.
            out.extend_from_slice(&[TAG_FORMAT_INFO, TAG_U8, 1, TAG_PROPLIST, TAG_STRING_NULL]);
        }
        self.ghosts.insert(
            channel,
            Ghost {
                index,
                request,
                spec,
                maxlength,
                fragsize,
                corked,
                sent: 0,
                link: Link::Silent,
            },
        );
        Up::Ghost {
            channel,
            reply: reply_frame(tag, &out),
            ask,
        }
    }

    /// The person allowed the silent stream on `channel`: the request for
    /// its real stream, tagged the filter's, as the program was told it —
    /// its buffer, its corking, its rate, the format fixed to what it asked
    /// for (not the source's) —, or `None` when it is gone or no longer
    /// silent.
    fn link(&mut self, channel: u32) -> Option<Vec<u8>> {
        let g = self.ghosts.get(&channel)?;
        if g.link != Link::Silent {
            return None;
        }
        let items = parse(&g.request[DESCRIPTOR..])?;
        if items.len() < 14 {
            return None;
        }
        let tag = self.own_tag(Own::Link(channel));
        let g = self.ghosts.get_mut(&channel)?;
        let mut frame = g.request.clone();
        set_u32(&mut frame, &items[1], tag);
        let rate = DESCRIPTOR + items[2].span.start + 3;
        frame[rate..rate + 4].copy_from_slice(&g.spec.rate.to_be_bytes());
        set_u32(&mut frame, &items[6], g.maxlength);
        set_bool(&mut frame, &items[7], g.corked);
        set_u32(&mut frame, &items[8], g.fragsize);
        for item in &items[11..14] {
            set_bool(&mut frame, item, false);
        }
        g.link = Link::Making {
            tag,
            corked: g.corked,
        };
        Some(frame)
    }

    /// The server's answer to a request of the filter's own; what to send
    /// the server after it, if anything.
    fn own_answer(&mut self, own: Own, command: u32, frame: &[u8]) -> Option<Vec<u8>> {
        let Own::Link(client) = own else {
            return None;
        };
        if command == COMMAND_ERROR {
            eprintln!("pulse-filter: the allowed record stream was not made — it stays silent");
            if let Some(g) = self.ghosts.get_mut(&client) {
                g.link = Link::Silent;
            }
            return None;
        }
        let items = parse(&frame[DESCRIPTOR..]);
        let values = items.as_deref().map_or(&[][..], |i| &i[2..]);
        let (Some(server), Some(index)) = (u32_at(values, 0), u32_at(values, 1)) else {
            return None;
        };
        let source = str_at(values, 7).flatten();
        let refused = record_source_refused(source);
        let corked_then = self.ghosts.get(&client).and_then(|g| match g.link {
            Link::Making { corked, .. } => Some(corked),
            _ => None,
        });
        let Some(corked_then) = corked_then.filter(|_| !refused) else {
            // Gone meanwhile, or linked to what the zone does not record:
            // the real stream goes, the silent one stays.
            if refused {
                eprintln!(
                    "pulse-filter: the allowed record stream was linked to what is not a \
                     microphone — deleted, it stays silent"
                );
                if let Some(g) = self.ghosts.get_mut(&client) {
                    g.link = Link::Silent;
                }
            }
            let tag = self.own_tag(Own::Discard);
            let mut p = Vec::new();
            put_u32(&mut p, server);
            return Some(command_frame(COMMAND_DELETE_RECORD_STREAM, tag, &p));
        };
        self.record_up.insert(client, server);
        self.record_down.insert(server, client);
        self.streams.insert((Kind::Record, server), index);
        self.sources
            .insert(server, source.unwrap_or_default().to_vec());
        let corked = {
            let g = self.ghosts.get_mut(&client)?;
            g.link = Link::Linked {
                channel: server,
                index,
            };
            g.corked
        };
        // Corked or uncorked since it was asked for: the real stream told.
        if corked == corked_then {
            return None;
        }
        let tag = self.own_tag(Own::Discard);
        let mut p = Vec::new();
        put_u32(&mut p, server);
        p.push(if corked { TAG_TRUE } else { TAG_FALSE });
        Some(command_frame(COMMAND_CORK_RECORD_STREAM, tag, &p))
    }

    /// Why this connection's recording ends now: its program's microphone
    /// was set to `no` since. Read again only when the setting's files have
    /// changed.
    fn microphone_taken_away(&mut self) -> Option<String> {
        let now = self.mic.generation();
        if self.mic.watched() && now == self.mic_seen {
            return None;
        }
        self.mic_seen = now;
        (self.mic.setting(&self.who).0 == crate::microphone::Setting::No).then(|| {
            "the microphone was taken away from this program — its recording ends".to_owned()
        })
    }

    fn down(&mut self, frame: &[u8]) -> Down {
        let Some(channel) = channel_of(frame) else {
            return Down::Close("a frame the filter cannot read".to_owned());
        };
        if channel != COMMAND_CHANNEL {
            // Sound the server sends is a record stream's; only one whose
            // source the server has named and the filter has let through —
            // and while its program may record (`microphone::Policy::watch`).
            return if self.streams.contains_key(&(Kind::Record, channel)) {
                match (self.microphone_taken_away(), self.record_down.get(&channel)) {
                    (Some(why), _) => Down::Close(why),
                    // On the channel the program knows it by.
                    (None, Some(&client)) => {
                        let mut f = frame.to_vec();
                        f[4..8].copy_from_slice(&client.to_be_bytes());
                        Down::Rewritten(f)
                    }
                    (None, None) => Down::Forward,
                }
            } else {
                Down::Drop
            };
        }
        let Some((command, tag)) = command_of(frame) else {
            return Down::Close("a command the filter cannot read".to_owned());
        };
        if matches!(command, COMMAND_REPLY | COMMAND_ERROR) {
            // An answer to the filter's own request: not the program's.
            if let Some(own) = self.own.remove(&tag) {
                return Down::Own(self.own_answer(own, command, frame));
            }
            // AUTH's: the server's version, the lower of the two spoken.
            if self.auth_tag == Some(tag) {
                self.auth_tag = None;
                let items = parse(&frame[DESCRIPTOR..]);
                if let Some(v) = items.as_deref().and_then(|i| u32_at(i, 2)) {
                    let v = v & PROTOCOL_VERSION_MASK;
                    if v > 0 && (self.version == 0 || v < self.version) {
                        self.version = v;
                    }
                }
            }
        }
        let verdict = self.down_command(command, tag, frame);
        // A record stream's word, on the channel the program knows it by.
        if verdict == Down::Forward && RECORD_CHANNEL_EVENTS.contains(&command) {
            let items = parse(&frame[DESCRIPTOR..]).unwrap_or_default();
            let server = u32_at(&items, 2);
            if let Some((server, client)) =
                server.and_then(|s| Some((s, *self.record_down.get(&s)?)))
            {
                let mut f = frame.to_vec();
                set_u32(&mut f, &items[2], client);
                if command == COMMAND_RECORD_STREAM_KILLED {
                    self.record_down.remove(&server);
                    self.record_up.remove(&client);
                    self.ghosts.remove(&client);
                }
                return Down::Rewritten(f);
            }
        }
        verdict
    }

    fn down_command(&mut self, command: u32, tag: u32, frame: &[u8]) -> Down {
        match command {
            COMMAND_ENABLE_SRBCHANNEL => Down::Close(
                "the sound server offers a shared ring buffer, which would carry commands \
                 past this filter"
                    .to_owned(),
            ),
            COMMAND_REPLY => {
                let Some(kind) = self.creating.remove(&tag) else {
                    return Down::Forward;
                };
                let items = parse(&frame[DESCRIPTOR..]);
                let values = items.as_deref().map_or(&[][..], |i| &i[2..]);
                let (Some(channel), Some(index)) = (u32_at(values, 0), u32_at(values, 1)) else {
                    return Down::Close("a stream's reply the filter cannot read".to_owned());
                };
                if kind == Kind::Record {
                    // Channel, index, maximum length, fragment size, sample
                    // spec, channel map, source index, source name.
                    let Some(source) = str_at(values, 7) else {
                        return Down::Close("a stream's reply the filter cannot read".to_owned());
                    };
                    if record_source_refused(source) {
                        return Down::Close(format!(
                            "the server linked a record stream to {} — the zone does not \
                             record what the host plays",
                            source.map_or("no source".into(), |s| String::from_utf8_lossy(s)
                                .escape_debug()
                                .to_string())
                        ));
                    }
                    self.sources
                        .insert(channel, source.unwrap_or_default().to_vec());
                    // A channel the program knows a silent stream by: this
                    // one is told another.
                    if self.record_channel_taken(channel) {
                        self.streams.insert((kind, channel), index);
                        let client = self.free_channel();
                        self.record_up.insert(client, channel);
                        self.record_down.insert(channel, client);
                        let items = items.unwrap_or_default();
                        let mut f = frame.to_vec();
                        set_u32(&mut f, &items[2], client);
                        return Down::Rewritten(f);
                    }
                }
                self.streams.insert((kind, channel), index);
                Down::Forward
            }
            COMMAND_ERROR => {
                self.creating.remove(&tag);
                Down::Forward
            }
            COMMAND_PLAYBACK_STREAM_KILLED | COMMAND_RECORD_STREAM_KILLED => {
                let kind = if command == COMMAND_PLAYBACK_STREAM_KILLED {
                    Kind::Playback
                } else {
                    Kind::Record
                };
                let items = parse(&frame[DESCRIPTOR..]);
                if let Some(channel) = items.as_deref().and_then(|i| u32_at(i, 2)) {
                    self.streams.remove(&(kind, channel));
                    if kind == Kind::Record {
                        self.sources.remove(&channel);
                    }
                }
                Down::Forward
            }
            COMMAND_RECORD_STREAM_MOVED => {
                // Channel, source index, source name. Where a record stream
                // may be moved: back to the source it had, or to a capture
                // device of the host's. pipewire-pulse names a monitor
                // `<sink>.monitor` in a move only for a plain sink: a stream
                // linked to another program's playback, or to a node that is
                // neither, comes with that node's bare name (review
                // 2026-09-27) — which no name can tell from a microphone's.
                let items = parse(&frame[DESCRIPTOR..]);
                let channel = items.as_deref().and_then(|i| u32_at(i, 2));
                let source = items.as_deref().and_then(|i| str_at(i, 4)).flatten();
                match (channel, source) {
                    (Some(channel), Some(name))
                        if !record_source_refused(Some(name))
                            && (self
                                .sources
                                .get(&channel)
                                .is_some_and(|had| had.as_slice() == name)
                                || a_capture_device(name)) =>
                    {
                        self.sources.insert(channel, name.to_vec());
                        Down::Forward
                    }
                    _ => Down::Close(
                        "the server moved a record stream to what is not a microphone — the \
                         zone does not record what the host plays"
                            .to_owned(),
                    ),
                }
            }
            _ => Down::Forward,
        }
    }
}

/// `ERROR` for the command tagged `tag`: access denied.
pub fn error_frame(tag: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(15);
    for value in [COMMAND_ERROR, tag, ERR_ACCESS] {
        payload.push(TAG_U32);
        payload.extend_from_slice(&value.to_be_bytes());
    }
    let mut frame = Vec::with_capacity(DESCRIPTOR + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&COMMAND_CHANNEL.to_be_bytes());
    frame.extend_from_slice(&[0u8; 12]);
    frame.extend_from_slice(&payload);
    frame
}

/// One side's writes, one frame at a time: the frames of the two directions
/// and the filter's own answers never interleave.
struct Out {
    sock: UnixStream,
    lock: Mutex<()>,
}

impl Out {
    fn send(&self, frame: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let first = frame.len().min(READ_CHUNK);
        sys::send_with_fds(self.sock.as_raw_fd(), &frame[..first], fds)?;
        let mut rest = &frame[first..];
        while !rest.is_empty() {
            let n = rest.len().min(READ_CHUNK);
            sys::send_with_fds(self.sock.as_raw_fd(), &rest[..n], &[])?;
            rest = &rest[n..];
        }
        Ok(())
    }
}

/// Whole frames from one side, each with the descriptors that came with it.
struct Frames<'a> {
    from: &'a UnixStream,
    buf: Vec<u8>,
    pending: Vec<u8>,
    /// Where in the stream each batch of descriptors arrived.
    marks: VecDeque<(u64, Vec<OwnedFd>)>,
    read: u64,
    sent: u64,
}

impl<'a> Frames<'a> {
    fn new(from: &'a UnixStream) -> Self {
        Self {
            from,
            buf: vec![0u8; READ_CHUNK],
            pending: Vec::new(),
            marks: VecDeque::new(),
            read: 0,
            sent: 0,
        }
    }

    fn next(&mut self) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
        loop {
            if let Some(len) = frame_len(&self.pending)? {
                if self.pending.len() >= len {
                    let frame: Vec<u8> = self.pending.drain(..len).collect();
                    let start = self.sent;
                    self.sent += len as u64;
                    let mut carried: Vec<OwnedFd> = Vec::new();
                    while let Some((at, _)) = self.marks.front() {
                        if *at > start {
                            break;
                        }
                        if *at < start {
                            return Err(io::Error::other("descriptors in the middle of a frame"));
                        }
                        carried = self.marks.pop_front().map(|(_, f)| f).unwrap_or_default();
                    }
                    return Ok(Some((frame, carried)));
                }
            }
            let (n, fds, truncated) =
                sys::recv_into_with_fds(self.from.as_raw_fd(), &mut self.buf, MAX_FDS_PER_READ)?;
            if truncated {
                return Err(io::Error::other("descriptors were cut off"));
            }
            if n == 0 {
                return Ok(None);
            }
            if !fds.is_empty() {
                self.marks.push_back((self.read, fds));
            }
            self.read += n as u64;
            self.pending.extend_from_slice(&self.buf[..n]);
        }
    }
}

fn lock(session: &Mutex<Session>) -> std::sync::MutexGuard<'_, Session> {
    session.lock().unwrap_or_else(|e| e.into_inner())
}

/// The zone's frames to the server; what is refused is answered to the zone.
fn pump_up(
    client: &UnixStream,
    to_server: &Arc<Out>,
    to_client: &Arc<Out>,
    session: &Arc<Mutex<Session>>,
) -> io::Result<()> {
    let mut frames = Frames::new(client);
    while let Some((frame, carried)) = frames.next()? {
        // Decided under the lock, sent without it: a full socket must not
        // hold the other direction up.
        let verdict = lock(session).up(&frame);
        match verdict {
            Up::Forward(frame) => {
                let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                to_server.send(&frame, &raw)?;
            }
            Up::Refuse(tag, what) => {
                eprintln!("pulse-filter: {what} refused");
                to_client.send(&error_frame(tag), &[])?;
            }
            Up::Answer(frame) => to_client.send(&frame, &[])?,
            Up::Ghost {
                channel,
                reply,
                ask,
            } => {
                to_client.send(&reply, &[])?;
                silence(channel, to_client, session);
                if let Some((program, remember)) = ask {
                    self::ask(channel, program, remember, to_server, session);
                }
            }
            Up::Close(why) => return Err(io::Error::other(why)),
        }
    }
    Ok(())
}

/// A silent stream's sound, on a thread of its own: a fragment of silence
/// at a time, at the stream's rate, while it is not corked — until it is
/// linked to its real stream, gone, or the program is.
fn silence(channel: u32, to_client: &Arc<Out>, session: &Arc<Mutex<Session>>) {
    let (to_client, session) = (Arc::clone(to_client), Arc::clone(session));
    let started = thread::Builder::new().spawn(move || loop {
        let (frame, wait) = {
            let mut s = lock(&session);
            let Some(g) = s.ghosts.get_mut(&channel) else {
                return;
            };
            if matches!(g.link, Link::Linked { .. }) {
                return;
            }
            let per_second = g.spec.bytes_per_second().max(1);
            let wait =
                std::time::Duration::from_micros(u64::from(g.fragsize) * 1_000_000 / per_second);
            if g.corked {
                (None, wait)
            } else {
                g.sent += u64::from(g.fragsize);
                let fragment = g.fragsize as usize;
                (Some(silence_frame(channel, g.spec, fragment)), wait)
            }
        };
        if let Some(frame) = frame {
            if to_client.send(&frame, &[]).is_err() {
                return;
            }
        }
        thread::sleep(wait.max(std::time::Duration::from_millis(1)));
    });
    if let Err(e) = started {
        eprintln!("pulse-filter: no thread for a silent record stream ({e}) — it stays mute");
    }
}

/// Ask about a silent record stream on a thread of its own — the
/// connection's other commands go on meanwhile, the program hears silence —
/// and, allowed, have its real stream made.
fn ask(
    channel: u32,
    program: String,
    remember: bool,
    to_server: &Arc<Out>,
    session: &Arc<Mutex<Session>>,
) {
    let (mic, who, peer) = {
        let s = lock(session);
        (Arc::clone(&s.mic), s.who.clone(), s.peer)
    };
    let spawned = {
        let (to_server, session, mic) =
            (Arc::clone(to_server), Arc::clone(session), Arc::clone(&mic));
        thread::Builder::new().spawn(move || {
            // The connection's state by the answer, while the zone's question
            // is still open: a request of this connection that comes in
            // meanwhile is refused as "a question is open", and one after it
            // finds the deny standing — none gets a question of its own.
            let launch = peer
                .and_then(|p| crate::onwindow::launch_above(&crate::onwindow::runtime_dir(), p));
            let made = mic.ask(&program, &who, remember, launch, |allowed| {
                let mut s = lock(&session);
                if allowed {
                    s.link(channel)
                } else {
                    s.mic_denied = true;
                    None
                }
            });
            // The connection may be gone by now: then this fails, and there
            // is nobody to tell.
            if let Some(frame) = made {
                let _ = to_server.send(&frame, &[]);
            }
        })
    };
    if let Err(e) = spawned {
        mic.abandon();
        eprintln!("pulse-filter: a record stream stays silent: cannot ask ({e})");
    }
}

/// The server's frames to the zone.
fn pump_down(
    server: &UnixStream,
    to_client: &Out,
    to_server: &Out,
    session: &Mutex<Session>,
) -> io::Result<()> {
    let mut frames = Frames::new(server);
    while let Some((frame, carried)) = frames.next()? {
        let verdict = lock(session).down(&frame);
        match verdict {
            Down::Forward => {
                let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                to_client.send(&frame, &raw)?;
            }
            Down::Rewritten(frame) => {
                let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                to_client.send(&frame, &raw)?;
            }
            Down::Own(then) => {
                if let Some(frame) = then {
                    to_server.send(&frame, &[])?;
                }
            }
            Down::Drop => {}
            Down::Close(why) => {
                return Err(io::Error::other(format!(
                    "{why} — the connection is closed"
                )))
            }
        }
    }
    Ok(())
}

/// Whose program the peer of `client` is (`crate::origin`), looked at
/// while it is certainly the process that connected. Unknown when it cannot
/// be looked at.
/// Whose program `client` is, and its pid (this process's pid namespace's:
/// the host's) — where its launch is found for a question on its window
/// (`crate::onwindow::launch_above`).
fn who_is(client: &UnixStream, args: &Args) -> (Who, Option<i32>) {
    let Some(peer) = crate::origin::Peer::of(client.as_raw_fd()) else {
        return (Who::Unknown, None);
    };
    (who_of(&peer, args), Some(peer.pid))
}

fn who_of(peer: &crate::origin::Peer, args: &Args) -> Who {
    // An instance's filter: its clients are the instance's container — when
    // they are in its user namespace, as they must be to reach the socket.
    if let Some(who) = &args.container {
        let inside = args
            .userns
            .is_none_or(|key| crate::place::chain_of(peer.pid).contains(&key) && peer.alive());
        return if inside { who.clone() } else { Who::Unknown };
    }
    // A zone's own filter: the zone's own programs, in its own mount
    // namespace — no container's since stage 5 (`crate::origin`).
    let Some(state) = args.zone_dir.parent() else {
        return Who::Unknown;
    };
    crate::origin::of_peer(state, &args.zone, peer)
}

fn serve(
    client: UnixStream,
    upstream: &PathBuf,
    mic: Arc<Policy>,
    (who, peer): (Who, Option<i32>),
) -> io::Result<()> {
    let server = UnixStream::connect(upstream)?;
    let session = Arc::new(Mutex::new(Session {
        mic,
        who,
        peer,
        ..Session::default()
    }));
    let to_client = Arc::new(Out {
        sock: client.try_clone()?,
        lock: Mutex::new(()),
    });
    let to_server = Arc::new(Out {
        sock: server.try_clone()?,
        lock: Mutex::new(()),
    });
    let down = {
        let (to_client, to_server) = (Arc::clone(&to_client), Arc::clone(&to_server));
        let session = Arc::clone(&session);
        let server = server.try_clone()?;
        // A thread that cannot be made ends this connection, not the filter.
        thread::Builder::new().spawn(move || {
            if let Err(e) = pump_down(&server, &to_client, &to_server, &session) {
                report(&e);
            }
            let _ = to_client.sock.shutdown(std::net::Shutdown::Both);
            let _ = server.shutdown(std::net::Shutdown::Both);
        })?
    };
    let result = pump_up(&client, &to_server, &to_client, &session);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = server.shutdown(std::net::Shutdown::Both);
    let _ = down.join();
    // The silent streams' threads end at their next fragment.
    lock(&session).ghosts.clear();
    result
}

/// A connection's end, unless it is only the other side going away.
fn report(e: &io::Error) {
    if !matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    ) {
        eprintln!("pulse-filter: {e}");
    }
}

/// Serve until the zone's unit that started us goes.
pub fn run(args: &Args) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    // Nobody of the same uid may read this process through /proc/<pid>/:
    // its `root` is the host's file system, `pulse/native` unfiltered and
    // the zone's microphone setting in it, and its `fd` hold both. The zone
    // starts it in the host's user namespace (`zone::Helpers`), which a
    // zone's programs cannot read anyway; not dumpable, it stays out of reach
    // wherever it is started from (`bus_filter::run` does the same). What it
    // starts — the question's window, or kdialog — is dumpable again after exec, and is safe only by
    // where this process lives.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let _ = fs::remove_file(&args.listen);
    let listener = match UnixListener::bind(&args.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "pulse-filter: cannot listen on {}: {e}",
                args.listen.display()
            );
            return 1;
        }
    };
    let _ = fs::set_permissions(&args.listen, fs::Permissions::from_mode(0o600));
    // The zone is this filter's, fixed here — an instance's, the network it
    // is in now (`--network-file`: a live switch moves it); the setting is
    // read for every record stream.
    let mic = Arc::new(
        Policy::new(
            &args.zone,
            args.zone_dir.clone(),
            args.config.clone(),
            args.profiles.clone(),
            args.kdialog.clone(),
            args.window.clone(),
        )
        .following(args.network.clone()),
    );
    mic.watch();
    if !mic.has_display() {
        eprintln!(
            "pulse-filter: zone {}: no graphical session (WAYLAND_DISPLAY, DISPLAY) — a microphone \
             set to \"ask\" is refused, there is nobody to ask",
            mic.zone()
        );
    }
    let connections = Arc::new(AtomicU32::new(0));
    let shared = Arc::new(args.clone());
    for client in listener.incoming() {
        let Ok(client) = client else {
            continue;
        };
        if connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            eprintln!("pulse-filter: too many connections — refused");
            continue;
        }
        connections.fetch_add(1, Ordering::SeqCst);
        let args = Arc::clone(&shared);
        let connections = Arc::clone(&connections);
        let mic = Arc::clone(&mic);
        let counted = Arc::clone(&connections);
        let started = thread::Builder::new().spawn(move || {
            // On the connection's own thread: the registry is read for it.
            let who = who_is(&client, &args);
            if let Err(e) = serve(client, &args.upstream, mic, who) {
                report(&e);
            }
            connections.fetch_sub(1, Ordering::SeqCst);
        });
        // No thread for it: this connection is refused, the filter goes on.
        if let Err(e) = started {
            eprintln!("pulse-filter: no thread for a connection ({e}) — refused");
            counted.fetch_sub(1, Ordering::SeqCst);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::microphone::Setting;

    /// A packet's values, written as the client library writes them.
    #[derive(Clone)]
    enum V<'a> {
        L(u32),
        S(Option<&'a str>),
        B(bool),
        P(&'a [(&'a str, &'a str)]),
        Spec,
        Map,
        CVol,
        Usec,
    }

    fn payload(values: &[V]) -> Vec<u8> {
        let mut p = Vec::new();
        for v in values {
            match v {
                V::L(n) => {
                    p.push(TAG_U32);
                    p.extend_from_slice(&n.to_be_bytes());
                }
                V::S(None) => p.push(TAG_STRING_NULL),
                V::S(Some(s)) => {
                    p.push(TAG_STRING);
                    p.extend_from_slice(s.as_bytes());
                    p.push(0);
                }
                V::B(b) => p.push(if *b { TAG_TRUE } else { TAG_FALSE }),
                V::P(entries) => {
                    p.push(TAG_PROPLIST);
                    for (k, val) in entries.iter() {
                        p.push(TAG_STRING);
                        p.extend_from_slice(k.as_bytes());
                        p.push(0);
                        let len = (val.len() + 1) as u32;
                        p.push(TAG_U32);
                        p.extend_from_slice(&len.to_be_bytes());
                        p.push(TAG_ARBITRARY);
                        p.extend_from_slice(&len.to_be_bytes());
                        p.extend_from_slice(val.as_bytes());
                        p.push(0);
                    }
                    p.push(TAG_STRING_NULL);
                }
                V::Spec => p.extend_from_slice(&[TAG_SAMPLE_SPEC, 3, 2, 0, 0, 0xbb, 0x80]),
                V::Map => p.extend_from_slice(&[TAG_CHANNEL_MAP, 2, 1, 2]),
                V::CVol => {
                    p.extend_from_slice(&[TAG_CVOLUME, 1]);
                    p.extend_from_slice(&0x10000u32.to_be_bytes());
                }
                V::Usec => {
                    p.push(TAG_USEC);
                    p.extend_from_slice(&[0; 8]);
                }
            }
        }
        p
    }

    fn framed(channel: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&channel.to_be_bytes());
        frame.extend_from_slice(&[0u8; 12]);
        frame.extend_from_slice(payload);
        frame
    }

    fn packet(cmd: u32, tag: u32, values: &[V]) -> Vec<u8> {
        let mut all = vec![V::L(cmd), V::L(tag)];
        all.extend_from_slice(values);
        framed(COMMAND_CHANNEL, &payload(&all))
    }

    fn command(cmd: u32, tag: u32) -> Vec<u8> {
        packet(cmd, tag, &[V::S(Some("module-tunnel-sink"))])
    }

    fn auth(tag: u32) -> Vec<u8> {
        let mut values = payload(&[V::L(COMMAND_AUTH), V::L(tag), V::L(0x8000_0000 | 35)]);
        values.push(TAG_ARBITRARY);
        values.extend_from_slice(&256u32.to_be_bytes());
        values.extend_from_slice(&[0u8; 256]);
        framed(COMMAND_CHANNEL, &values)
    }

    /// `CREATE_RECORD_STREAM` as libpulse sends it (protocol 35).
    fn record(
        tag: u32,
        index: u32,
        name: Option<&str>,
        props: &[(&str, &str)],
        direct: u32,
    ) -> Vec<u8> {
        let mut v = vec![
            V::Spec,
            V::Map,
            V::L(index),
            V::S(name),
            V::L(INVALID),
            V::B(false),
            V::L(INVALID),
        ];
        v.extend(std::iter::repeat_n(V::B(false), 7));
        v.extend([V::B(false), V::B(true), V::P(props), V::L(direct)]);
        v.extend([V::B(false), V::B(false), V::B(false)]);
        let mut p = payload(&[V::L(COMMAND_CREATE_RECORD_STREAM), V::L(tag)]);
        p.extend(payload(&v));
        p.extend_from_slice(&[TAG_U8, 0]);
        p.extend(payload(&[
            V::CVol,
            V::B(false),
            V::B(false),
            V::B(false),
            V::B(false),
            V::B(false),
        ]));
        framed(COMMAND_CHANNEL, &p)
    }

    /// The server's reply to a `CREATE_RECORD_STREAM`, linked to `source`.
    fn record_reply(tag: u32, channel: u32, index: u32, source: Option<&str>) -> Vec<u8> {
        packet(
            COMMAND_REPLY,
            tag,
            &[
                V::L(channel),
                V::L(index),
                V::L(4096),
                V::L(1024),
                V::Spec,
                V::Map,
                V::L(3),
                V::S(source),
                V::B(false),
                V::Usec,
            ],
        )
    }

    /// After AUTH, in a zone whose microphone is let.
    fn authed() -> Session {
        with_mic(Setting::Yes, false)
    }

    /// After AUTH, with this microphone setting and a display or none.
    fn with_mic(setting: Setting, display: bool) -> Session {
        let mut s = Session {
            mic: Arc::new(Policy::fixed(setting, display)),
            who: Who::Main,
            ..Session::default()
        };
        assert!(matches!(s.up(&auth(0)), Up::Forward(_)));
        s
    }

    fn refused(verdict: Up) -> String {
        match verdict {
            Up::Refuse(_, why) => why,
            other => panic!("not refused: {other:?}"),
        }
    }

    #[test]
    fn a_frame_is_read_the_way_the_server_reads_it() {
        let f = command(COMMAND_LOAD_MODULE, 7);
        assert_eq!(frame_len(&f[..10]).unwrap(), None);
        assert_eq!(frame_len(&f).unwrap(), Some(f.len()));
        assert_eq!(command_of(&f), Some((COMMAND_LOAD_MODULE, 7)));
        // A stream's data is not a command.
        let mut data = f.clone();
        data[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(command_of(&data), None);
        // A length the server refuses is an error, not a wait.
        let mut huge = f.clone();
        huge[0..4].copy_from_slice(&(FRAME_MAX as u32 + 1).to_be_bytes());
        assert!(frame_len(&huge).is_err());
        let mut zero = f;
        zero[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(frame_len(&zero).is_err());
    }

    #[test]
    fn the_command_numbers_are_the_servers() {
        // commands.h: the table's order is the protocol.
        for (n, name) in [
            (3, "CREATE_PLAYBACK_STREAM"),
            (5, "CREATE_RECORD_STREAM"),
            (8, "AUTH"),
            (37, "SET_SINK_INPUT_VOLUME"),
            (44, "SET_DEFAULT_SINK"),
            (48, "KILL_CLIENT"),
            (51, "LOAD_MODULE"),
            (67, "MOVE_SINK_INPUT"),
            (69, "SET_SINK_INPUT_MUTE"),
            (79, "RECORD_STREAM_MOVED"),
            (87, "EXTENSION"),
            (90, "SET_CARD_PROFILE"),
            (98, "SET_SOURCE_OUTPUT_VOLUME"),
            (101, "ENABLE_SRBCHANNEL"),
            (103, "REGISTER_MEMFD_SHMID"),
            (104, "SEND_OBJECT_MESSAGE"),
        ] {
            assert_eq!(command_name(n), name);
        }
        assert_eq!(command_name(105), "an unknown command");
    }

    /// The allow-list, whole: a command added to it is added here on purpose.
    #[test]
    fn only_the_commands_of_an_ordinary_program_pass() {
        let allowed: Vec<&str> = (0..=u32::from(u8::MAX))
            .filter(|&c| rule(c) != Rule::Refuse)
            .map(command_name)
            .collect();
        assert_eq!(
            allowed,
            [
                "CREATE_PLAYBACK_STREAM",
                "DELETE_PLAYBACK_STREAM",
                "CREATE_RECORD_STREAM",
                "DELETE_RECORD_STREAM",
                "AUTH",
                "SET_CLIENT_NAME",
                "LOOKUP_SINK",
                "LOOKUP_SOURCE",
                "DRAIN_PLAYBACK_STREAM",
                "STAT",
                "GET_PLAYBACK_LATENCY",
                "CREATE_UPLOAD_STREAM",
                "DELETE_UPLOAD_STREAM",
                "FINISH_UPLOAD_STREAM",
                "PLAY_SAMPLE",
                "GET_SERVER_INFO",
                "GET_SINK_INFO",
                "GET_SINK_INFO_LIST",
                "GET_SOURCE_INFO",
                "GET_SOURCE_INFO_LIST",
                "GET_SINK_INPUT_INFO",
                "GET_SOURCE_OUTPUT_INFO",
                "GET_SAMPLE_INFO",
                "GET_SAMPLE_INFO_LIST",
                "SUBSCRIBE",
                "SET_SINK_INPUT_VOLUME",
                "CORK_PLAYBACK_STREAM",
                "FLUSH_PLAYBACK_STREAM",
                "TRIGGER_PLAYBACK_STREAM",
                "SET_PLAYBACK_STREAM_NAME",
                "SET_RECORD_STREAM_NAME",
                "GET_RECORD_LATENCY",
                "CORK_RECORD_STREAM",
                "FLUSH_RECORD_STREAM",
                "PREBUF_PLAYBACK_STREAM",
                "SET_SINK_INPUT_MUTE",
                "SET_PLAYBACK_STREAM_BUFFER_ATTR",
                "SET_RECORD_STREAM_BUFFER_ATTR",
                "UPDATE_PLAYBACK_STREAM_SAMPLE_RATE",
                "UPDATE_RECORD_STREAM_SAMPLE_RATE",
                "UPDATE_RECORD_STREAM_PROPLIST",
                "UPDATE_PLAYBACK_STREAM_PROPLIST",
                "UPDATE_CLIENT_PROPLIST",
                "GET_CARD_INFO",
                "GET_CARD_INFO_LIST",
                "SET_SOURCE_OUTPUT_VOLUME",
                "SET_SOURCE_OUTPUT_MUTE",
                "REGISTER_MEMFD_SHMID",
            ]
        );
        // What changes the server rather than uses it, by name.
        for name in [
            "EXIT",
            "LOAD_MODULE",
            "UNLOAD_MODULE",
            "KILL_CLIENT",
            "KILL_SINK_INPUT",
            "KILL_SOURCE_OUTPUT",
            "SET_DEFAULT_SINK",
            "SET_DEFAULT_SOURCE",
            "MOVE_SINK_INPUT",
            "MOVE_SOURCE_OUTPUT",
            "SET_SINK_VOLUME",
            "SET_SOURCE_VOLUME",
            "SET_SINK_MUTE",
            "SET_SOURCE_MUTE",
            "SUSPEND_SINK",
            "SUSPEND_SOURCE",
            "SET_SINK_PORT",
            "SET_SOURCE_PORT",
            "SET_CARD_PROFILE",
            "SET_PORT_LATENCY_OFFSET",
            "EXTENSION",
            "ENABLE_SRBCHANNEL",
            "DISABLE_SRBCHANNEL",
            "SEND_OBJECT_MESSAGE",
            "REMOVE_SAMPLE",
            "REMOVE_CLIENT_PROPLIST",
            "GET_CLIENT_INFO_LIST",
            "GET_SINK_INPUT_INFO_LIST",
            "GET_MODULE_INFO_LIST",
            "REPLY",
        ] {
            let n = COMMANDS.iter().position(|c| *c == name).unwrap() as u32;
            assert_eq!(rule(n), Rule::Refuse, "{name}");
        }
    }

    #[test]
    fn nothing_passes_before_auth_and_auth_passes_once() {
        let mut s = Session::default();
        assert!(refused(s.up(&command(COMMAND_GET_SERVER_INFO, 1))).contains("before AUTH"));
        // A version before property lists: the filter would misread the rest.
        let mut old = auth(2);
        old[DESCRIPTOR + 11..DESCRIPTOR + 15].copy_from_slice(&12u32.to_be_bytes());
        assert!(refused(s.up(&old)).contains("protocol 13"));
        assert!(matches!(s.up(&auth(3)), Up::Forward(_)));
        assert!(refused(s.up(&auth(4))).contains("second AUTH"));
        assert!(matches!(
            s.up(&packet(COMMAND_GET_SERVER_INFO, 5, &[])),
            Up::Forward(_)
        ));
        // What does not change the server passes as it came.
        let lookup = packet(COMMAND_LOOKUP_SINK, 6, &[V::S(Some("x"))]);
        assert_eq!(s.up(&lookup), Up::Forward(lookup));
        // A command the filter does not know, or cannot read, is refused.
        assert!(refused(s.up(&command(200, 7))).contains("unknown"));
        let mut broken = packet(COMMAND_GET_SERVER_INFO, 8, &[V::L(1)]);
        broken.push(b'?');
        let length = (broken.len() - DESCRIPTOR) as u32;
        broken[0..4].copy_from_slice(&length.to_be_bytes());
        assert!(refused(s.up(&broken)).contains("unreadable"));
        // A command packet that is not one at all ends the connection.
        let junk = framed(COMMAND_CHANNEL, b"hello, server");
        assert!(matches!(s.up(&junk), Up::Close(_)));
    }

    /// One-byte values fill a frame with ~48 times their size in the filter's
    /// memory: a packet with more than `MAX_VALUES` is refused unread, and
    /// one that would be refused anyway is not read at all.
    #[test]
    fn a_packet_of_countless_values_is_refused_not_read() {
        let flood = |cmd, tag, n| {
            let mut p = payload(&[V::L(cmd), V::L(tag)]);
            p.resize(p.len() + n, TAG_TRUE);
            framed(COMMAND_CHANNEL, &p)
        };
        // As much as fits: 2 values of its own, and the rest.
        let mut s = authed();
        let fits = flood(COMMAND_SET_CLIENT_NAME, 1, MAX_VALUES - 2);
        assert!(matches!(s.up(&fits), Up::Forward(_)));
        let over = flood(COMMAND_SET_CLIENT_NAME, 2, MAX_VALUES - 1);
        assert!(refused(s.up(&over)).contains("unreadable"));
        // The largest frame the server takes: refused, and at no more cost.
        let huge = flood(COMMAND_SET_CLIENT_NAME, 3, FRAME_MAX - 10);
        assert_eq!(frame_len(&huge).unwrap(), Some(huge.len()));
        assert!(parse(&huge[DESCRIPTOR..]).is_none());
        assert!(refused(s.up(&huge)).contains("unreadable"));
        // The entries of a property list count too.
        let mut many = payload(&[V::L(COMMAND_SET_CLIENT_NAME), V::L(4)]);
        many.push(TAG_PROPLIST);
        for _ in 0..MAX_VALUES {
            many.extend_from_slice(&payload(&[V::S(Some("media.name")), V::L(0)]));
            many.push(TAG_ARBITRARY);
            many.extend_from_slice(&0u32.to_be_bytes());
        }
        many.push(TAG_STRING_NULL);
        let many = framed(COMMAND_CHANNEL, &many);
        assert!(refused(s.up(&many)).contains("unreadable"));
        // A command refused anyway, or one before AUTH, is refused unread:
        // by its name, not as unreadable.
        let module = flood(COMMAND_LOAD_MODULE, 5, FRAME_MAX - 10);
        assert_eq!(refused(s.up(&module)), "LOAD_MODULE");
        let mut fresh = Session::default();
        let early = flood(COMMAND_GET_SERVER_INFO, 1, FRAME_MAX - 10);
        assert!(refused(fresh.up(&early)).contains("before AUTH"));
    }

    #[test]
    fn module_loading_is_refused_and_answered_as_the_server_would() {
        let mut s = authed();
        for (tag, cmd) in [
            COMMAND_LOAD_MODULE,
            COMMAND_UNLOAD_MODULE,
            COMMAND_KILL_CLIENT,
        ]
        .into_iter()
        .enumerate()
        {
            let tag = tag as u32 + 1;
            let why = refused(s.up(&command(cmd, tag)));
            assert_eq!(why, command_name(cmd));
        }
        let e = error_frame(9);
        assert_eq!(frame_len(&e).unwrap(), Some(e.len()));
        assert_eq!(command_of(&e), Some((COMMAND_ERROR, 9)));
        assert_eq!(&e[e.len() - 4..], &ERR_ACCESS.to_be_bytes());
    }

    #[test]
    fn only_the_descriptive_properties_reach_the_server() {
        for key in [
            "application.name",
            "application.process.binary",
            "window.x11.display",
            "event.id",
            "media.name",
            "media.role",
            "media.icon_name",
        ] {
            assert!(property_allowed(key.as_bytes()), "{key}");
        }
        for key in [
            "target.object",
            "node.target",
            "stream.capture.sink",
            "media.class",
            "media.category",
            "priority.session",
            "node.passive",
            "device.description",
            "filter.want",
            "filter.apply.echo-cancel.parameters",
            "module-stream-restore.id",
            "application.",
            "",
        ] {
            assert!(!property_allowed(key.as_bytes()), "{key}");
        }
        let mut s = authed();
        let props: &[(&str, &str)] = &[
            ("application.name", "Browser"),
            ("target.object", "alsa_output.pci.analog-stereo"),
            ("media.class", "Audio/Sink"),
            ("media.name", "call"),
        ];
        let name = packet(COMMAND_SET_CLIENT_NAME, 1, &[V::P(props)]);
        let Up::Forward(cut) = s.up(&name) else {
            panic!("SET_CLIENT_NAME refused");
        };
        assert_eq!(frame_len(&cut).unwrap(), Some(cut.len()));
        let items = parse(&cut[DESCRIPTOR..]).unwrap();
        let Value::Props(entries) = &items[2].value else {
            panic!("no property list");
        };
        let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(keys, [&b"application.name"[..], b"media.name"]);
        assert_eq!(
            cut,
            packet(
                COMMAND_SET_CLIENT_NAME,
                1,
                &[V::P(&[
                    ("application.name", "Browser"),
                    ("media.name", "call")
                ])]
            )
        );
        // A list that loses nothing is passed as it came.
        let clean = packet(
            COMMAND_UPDATE_CLIENT_PROPLIST,
            2,
            &[V::L(1), V::P(&props[..1])],
        );
        assert_eq!(s.up(&clean), Up::Forward(clean));
    }

    #[test]
    fn recording_a_monitor_is_refused_before_the_server_sees_it() {
        let mut s = authed();
        let none: &[(&str, &str)] = &[];
        for (tag, (index, name, direct, why)) in [
            (
                INVALID,
                Some("alsa_output.pci.analog-stereo.monitor"),
                INVALID,
                "a monitor",
            ),
            (INVALID, Some("@DEFAULT_MONITOR@"), INVALID, "a monitor"),
            (7, None, INVALID, "by its index"),
            (0, None, INVALID, "by its index"),
            (INVALID, Some("57"), INVALID, "by its index"),
            (INVALID, Some("0x10"), INVALID, "by its index"),
            (INVALID, Some(" +3"), INVALID, "by its index"),
            (INVALID, Some("\u{b}57"), INVALID, "by its index"),
            (INVALID, Some("12abc"), INVALID, "by its index"),
            (INVALID, None, 42, "direct_on_input"),
        ]
        .into_iter()
        .enumerate()
        {
            let tag = 100 + tag as u32;
            let why_got = refused(s.up(&record(tag, index, name, none, direct)));
            assert!(why_got.contains(why), "{name:?} {index}: {why_got}");
        }
        assert!(s.creating.is_empty());
        // The default source and a microphone by its name go on — to the
        // server's word (below).
        for (tag, name) in [
            (200, None),
            (201, Some("alsa_input.usb-Mic.mono")),
            (202, Some("@DEFAULT_SOURCE@")),
        ] {
            assert!(matches!(
                s.up(&record(tag, INVALID, name, none, INVALID)),
                Up::Forward(_)
            ));
        }
        assert_eq!(s.creating.len(), 3);
        // A target in the properties is cut, not obeyed.
        let sneaky: &[(&str, &str)] = &[
            ("target.object", "alsa_output.pci.analog-stereo"),
            ("stream.capture.sink", "true"),
        ];
        let Up::Forward(cut) = s.up(&record(203, INVALID, None, sneaky, INVALID)) else {
            panic!("refused");
        };
        assert!(!cut.windows(13).any(|w| w == b"target.object"));
        assert!(!cut.windows(19).any(|w| w == b"stream.capture.sink"));
        assert_eq!(cut, record(203, INVALID, None, none, INVALID));
    }

    /// A tag used twice would pair the reply to one command with another.
    #[test]
    fn every_tag_is_new() {
        let mut s = authed();
        let play = |tag| {
            packet(
                COMMAND_CREATE_PLAYBACK_STREAM,
                tag,
                &[V::Spec, V::Map, V::L(INVALID), V::S(None), V::L(INVALID)],
            )
        };
        assert!(matches!(s.up(&play(5)), Up::Forward(_)));
        // An upload stream under the same tag, asking for a "length" that is
        // another program's stream index: its reply (channel, length) would
        // read as the playback stream's (channel, index).
        let upload = packet(
            COMMAND_CREATE_UPLOAD_STREAM,
            5,
            &[V::S(Some("bell")), V::Spec, V::Map, V::L(70), V::P(&[])],
        );
        assert!(refused(s.up(&upload)).contains("tag not above"));
        // Or the upload first, then the stream: refused all the same.
        assert!(matches!(
            s.up(&packet(COMMAND_CREATE_UPLOAD_STREAM, 6, &[])),
            Up::Forward(_)
        ));
        assert!(refused(s.up(&play(6))).contains("tag not above"));
        assert!(refused(s.up(&play(4))).contains("tag not above"));
        // -1 is the tag of a memory pool's registration alone, which has no
        // reply.
        let pool = packet(COMMAND_REGISTER_MEMFD_SHMID, INVALID, &[V::L(1)]);
        assert!(matches!(s.up(&pool), Up::Forward(_)));
        assert!(refused(s.up(&play(INVALID))).contains("-1"));
        assert!(matches!(s.up(&play(7)), Up::Forward(_)));
    }

    /// A microphone taken away ends the recording going on, not only the
    /// next one: the setting is read again when its files have changed.
    #[test]
    fn a_microphone_taken_away_ends_the_recording() {
        let base = std::env::temp_dir().join(format!("vz-mic-revoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let zone_dir = base.join("state/nl");
        let config = base.join("config");
        std::fs::create_dir_all(&zone_dir).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(crate::permissions::FILE), "microphone = yes\n").unwrap();
        let mic = Arc::new(Policy::new(
            "nl",
            zone_dir.clone(),
            config.clone(),
            base.join("profiles"),
            PathBuf::from("/nonexistent/kdialog"),
            PathBuf::new(),
        ));
        mic.watch();
        let mut s = Session {
            mic: Arc::clone(&mic),
            who: Who::Main,
            ..Session::default()
        };
        assert!(matches!(s.up(&auth(0)), Up::Forward(_)));
        let none: &[(&str, &str)] = &[];
        assert!(matches!(
            s.up(&record(1, INVALID, None, none, INVALID)),
            Up::Forward(_)
        ));
        assert_eq!(
            s.down(&record_reply(1, 0, 70, Some("alsa_input.usb-Mic.mono"))),
            Down::Forward
        );
        let data = framed(0, b"a voice");
        assert_eq!(s.down(&data), Down::Forward);
        // Taken away: the next packet of sound ends it, once the change is
        // seen — by its event, not by a clock.
        let before = mic.generation();
        std::fs::write(config.join(crate::permissions::FILE), "microphone = no\n").unwrap();
        // The test's own patience with the watcher thread, not the filter's.
        let mut ended = false;
        for _ in 0..1000 {
            if mic.generation() != before {
                ended = matches!(s.down(&data), Down::Close(_));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(ended, "the recording went on");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_servers_word_on_the_source_decides() {
        let mut s = authed();
        let none: &[(&str, &str)] = &[];
        for tag in [1, 2, 3] {
            assert!(matches!(
                s.up(&record(tag, INVALID, None, none, INVALID)),
                Up::Forward(_)
            ));
        }
        // No sound before the reply, and none on a channel never answered.
        let data = framed(0, b"what the host plays");
        assert_eq!(s.down(&data), Down::Drop);
        // A microphone: its data flows.
        assert_eq!(
            s.down(&record_reply(1, 0, 70, Some("alsa_input.usb-Mic.mono"))),
            Down::Forward
        );
        assert_eq!(s.down(&data), Down::Forward);
        // The default source was a monitor, or the server fell back to one,
        // or named nothing: the connection ends before the reply is read.
        assert!(matches!(
            s.down(&record_reply(
                2,
                1,
                71,
                Some("alsa_output.pci.analog-stereo.monitor")
            )),
            Down::Close(_)
        ));
        assert!(matches!(
            s.down(&record_reply(3, 2, 72, None)),
            Down::Close(_)
        ));
        assert_eq!(s.down(&framed(1, b"x")), Down::Drop);
        // A move to a monitor later ends it too; to a microphone it is news.
        let moved = |name| {
            packet(
                COMMAND_RECORD_STREAM_MOVED,
                INVALID,
                &[V::L(0), V::L(5), V::S(name), V::B(false)],
            )
        };
        assert_eq!(
            s.down(&moved(Some("alsa_input.pci.analog-stereo"))),
            Down::Forward
        );
        assert_eq!(
            s.down(&moved(Some("alsa_input.usb-Mic.mono"))),
            Down::Forward
        );
        assert!(matches!(s.down(&moved(Some("x.monitor"))), Down::Close(_)));
        // Another program's playback, named bare by pipewire-pulse: no
        // microphone, whatever its name says.
        assert!(matches!(s.down(&moved(Some("Firefox"))), Down::Close(_)));
        assert!(matches!(s.down(&moved(None)), Down::Close(_)));
        // A shared ring buffer would carry commands past the filter.
        assert!(matches!(
            s.down(&command(COMMAND_ENABLE_SRBCHANNEL, 0)),
            Down::Close(_)
        ));
    }

    #[test]
    fn a_program_sets_the_volume_of_its_own_streams_only() {
        let mut s = authed();
        let mut tag = 0;
        let mut next = || {
            tag += 1;
            tag
        };
        let set = |cmd, tag, index| packet(cmd, tag, &[V::L(index), V::CVol]);
        let play = |tag| {
            packet(
                COMMAND_CREATE_PLAYBACK_STREAM,
                tag,
                &[V::Spec, V::Map, V::L(INVALID), V::S(None), V::L(INVALID)],
            )
        };
        let reply = |tag| packet(COMMAND_REPLY, tag, &[V::L(0), V::L(70), V::L(0)]);
        let volume = COMMAND_SET_SINK_INPUT_VOLUME;
        // Before its stream exists, index 70 is another program's.
        assert!(refused(s.up(&set(volume, next(), 70))).contains("not its own"));
        let t = next();
        assert!(matches!(s.up(&play(t)), Up::Forward(_)));
        assert_eq!(s.down(&reply(t)), Down::Forward);
        assert!(matches!(s.up(&set(volume, next(), 70)), Up::Forward(_)));
        let mute = packet(COMMAND_SET_SINK_INPUT_MUTE, next(), &[V::L(70), V::B(true)]);
        assert!(matches!(s.up(&mute), Up::Forward(_)));
        let info = packet(COMMAND_GET_SINK_INPUT_INFO, next(), &[V::L(70)]);
        assert!(matches!(s.up(&info), Up::Forward(_)));
        // Another program's, and a record stream's by a playback index: no.
        assert!(refused(s.up(&set(volume, next(), 71))).contains("not its own"));
        let record_volume = set(COMMAND_SET_SOURCE_OUTPUT_VOLUME, next(), 70);
        assert!(refused(s.up(&record_volume)).contains("not its own"));
        // Deleted, or killed by the server: the index is no longer its own.
        let delete = packet(COMMAND_DELETE_PLAYBACK_STREAM, next(), &[V::L(0)]);
        assert!(matches!(s.up(&delete), Up::Forward(_)));
        assert!(refused(s.up(&set(volume, next(), 70))).contains("not its own"));
        let t = next();
        assert!(matches!(s.up(&play(t)), Up::Forward(_)));
        assert_eq!(s.down(&reply(t)), Down::Forward);
        let killed = packet(COMMAND_PLAYBACK_STREAM_KILLED, INVALID, &[V::L(0)]);
        assert_eq!(s.down(&killed), Down::Forward);
        assert!(refused(s.up(&set(volume, next(), 70))).contains("not its own"));
        // A refused create frees its tag.
        let t = next();
        assert!(matches!(s.up(&play(t)), Up::Forward(_)));
        assert_eq!(s.down(&error_frame(t)), Down::Forward);
        assert!(s.creating.is_empty());
    }

    /// A real conversation through the filter: a harmless command passes, a
    /// module load and a monitor's recording are answered by the filter and
    /// never reach the server, and a server that links a record stream to a
    /// monitor loses the program's connection before its reply.
    #[test]
    fn only_harmless_commands_reach_the_server() {
        use std::io::{Read, Write};
        let dir = std::env::temp_dir().join(format!("vz-pulse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let upstream = dir.join("server");
        let server = UnixListener::bind(&upstream).unwrap();
        let (client, filter_side) = UnixStream::pair().unwrap();
        let path = upstream.clone();
        let mic = Arc::new(Policy::fixed(Setting::Yes, false));
        thread::spawn(move || {
            let _ = serve(filter_side, &path, mic, (Who::Main, None));
        });
        let (mut seen, _) = server.accept().unwrap();
        let mut c = client;
        let none: &[(&str, &str)] = &[];
        c.write_all(&auth(0)).unwrap();
        c.write_all(&command(COMMAND_LOAD_MODULE, 1)).unwrap();
        c.write_all(&record(2, INVALID, Some("sink.monitor"), none, INVALID))
            .unwrap();
        c.write_all(&packet(COMMAND_GET_SERVER_INFO, 3, &[]))
            .unwrap();
        c.write_all(&record(4, INVALID, None, none, INVALID))
            .unwrap();
        // The client hears ACCESS for the module and the monitor…
        for tag in [1, 2] {
            let mut answer = vec![0u8; DESCRIPTOR + 15];
            c.read_exact(&mut answer).unwrap();
            assert_eq!(command_of(&answer), Some((COMMAND_ERROR, tag)));
        }
        // …and the server sees AUTH, the question and the default source.
        let mut frames = Frames::new(&seen);
        let mut got = Vec::new();
        for _ in 0..3 {
            let (f, _) = frames.next().unwrap().unwrap();
            got.push(command_of(&f).unwrap());
        }
        assert_eq!(
            got,
            [
                (COMMAND_AUTH, 0),
                (COMMAND_GET_SERVER_INFO, 3),
                (COMMAND_CREATE_RECORD_STREAM, 4)
            ]
        );
        // The server links it to a monitor and sends its sound: the program
        // gets neither the reply nor the sound — the connection ends.
        seen.write_all(&record_reply(4, 0, 9, Some("sink.monitor")))
            .unwrap();
        let _ = seen.write_all(&framed(0, b"what the host plays"));
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest);
        assert!(rest.is_empty(), "{} bytes reached the program", rest.len());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The microphone by the zone's setting: no refuses, yes passes, ask
    /// holds the request — and a monitor stays refused whatever it says.
    #[test]
    fn a_microphone_goes_by_the_zones_setting() {
        let none: &[(&str, &str)] = &[];
        let mut s = with_mic(Setting::No, true);
        let why = refused(s.up(&record(1, INVALID, None, none, INVALID)));
        assert!(why.contains("microphone"), "{why}");
        assert!(s.creating.is_empty());
        // A monitor is refused as one, before the setting is looked at.
        let mut s = with_mic(Setting::Yes, true);
        let why = refused(s.up(&record(1, INVALID, Some("x.monitor"), none, INVALID)));
        assert!(why.contains("a monitor"), "{why}");
        assert!(matches!(
            s.up(&record(2, INVALID, None, none, INVALID)),
            Up::Forward(_)
        ));
        assert_eq!(s.creating.len(), 1);
        // Ask, with nobody to ask: refused.
        let mut s = with_mic(Setting::Ask, false);
        let why = refused(s.up(&record(1, INVALID, None, none, INVALID)));
        assert!(why.contains("графической"), "{why}");
        // Ask: answered silent by the filter — not the server's — under the
        // program's own name, the stream's over the client's.
        let mut s = with_mic(Setting::Ask, true);
        let client = packet(
            COMMAND_SET_CLIENT_NAME,
            1,
            &[V::P(&[("application.name", "Client")])],
        );
        assert!(matches!(s.up(&client), Up::Forward(_)));
        let sneaky: &[(&str, &str)] = &[("target.object", "x")];
        match s.up(&record(2, INVALID, None, sneaky, INVALID)) {
            Up::Ghost {
                channel,
                reply,
                ask,
            } => {
                assert_eq!(channel, 0);
                assert_eq!(command_of(&reply), Some((COMMAND_REPLY, 2)));
                assert_eq!(ask, Some(("Client".to_owned(), true)));
                // Kept with its properties cut, as it would have gone on.
                assert_eq!(
                    s.ghosts[&0].request,
                    record(2, INVALID, None, none, INVALID)
                );
            }
            other => panic!("not silent: {other:?}"),
        }
        assert!(s.creating.is_empty());
        // One question at a time for the zone.
        let why = refused(s.up(&record(3, INVALID, None, none, INVALID)));
        assert!(why.contains("уже открыт"), "{why}");
        s.mic.abandon();
        let named: &[(&str, &str)] = &[("application.name", "Stream")];
        assert!(matches!(
            s.up(&record(4, INVALID, None, named, INVALID)),
            Up::Ghost { channel: 1, ask: Some((program, _)), .. } if program == "Stream"
        ));
        s.mic.abandon();
        // Refused by the person once: silent, not asked again.
        s.mic_denied = true;
        assert!(matches!(
            s.up(&record(5, INVALID, None, none, INVALID)),
            Up::Ghost {
                channel: 2,
                ask: None,
                ..
            }
        ));
    }

    /// A silent record stream (the owner, docs/PERMISSIONS.md §11.15): the
    /// filter's reply is the server's at the connection's version — its
    /// buffer, the format asked for, a source that is no monitor —, its
    /// commands are answered by the filter, and nothing of it reaches the
    /// server; its sound is silence of its format.
    #[test]
    fn a_silent_stream_is_answered_by_the_filter() {
        let mut s = with_mic(Setting::Ask, true);
        let none: &[(&str, &str)] = &[];
        let Up::Ghost { channel, reply, .. } = s.up(&record(2, INVALID, None, none, INVALID))
        else {
            panic!("not silent");
        };
        s.mic.abandon();
        let items = parse(&reply[DESCRIPTOR..]).unwrap();
        let values = &items[2..];
        // 20 ms of s16 stereo at 48 kHz.
        assert_eq!(u32_at(values, 0), Some(channel));
        assert_eq!(u32_at(values, 1), Some(GHOST_INDICES));
        assert_eq!(u32_at(values, 2), Some(GHOST_MAXLENGTH));
        assert_eq!(u32_at(values, 3), Some(3840));
        assert_eq!(str_at(values, 7), Some(Some(&b"@DEFAULT_SOURCE@"[..])));
        assert!(!record_source_refused(str_at(values, 7).unwrap()));
        assert_eq!(values.len(), 11, "protocol 35: latency and format too");
        // Its commands: the filter's to answer.
        let answer = |up: Up, tag: u32| match up {
            Up::Answer(frame) => {
                assert_eq!(command_of(&frame), Some((COMMAND_REPLY, tag)));
                parse(&frame[DESCRIPTOR..]).unwrap()
            }
            other => panic!("not answered: {other:?}"),
        };
        answer(
            s.up(&packet(
                COMMAND_CORK_RECORD_STREAM,
                3,
                &[V::L(channel), V::B(true)],
            )),
            3,
        );
        assert!(s.ghosts[&channel].corked);
        let attr = answer(
            s.up(&packet(
                COMMAND_SET_RECORD_STREAM_BUFFER_ATTR,
                4,
                &[
                    V::L(channel),
                    V::L(8192),
                    V::L(1001),
                    V::B(true),
                    V::B(false),
                ],
            )),
            4,
        );
        assert_eq!(
            (u32_at(&attr, 2), u32_at(&attr, 3)),
            (Some(8192), Some(1000))
        );
        let mut latency = payload(&[V::L(COMMAND_GET_RECORD_LATENCY), V::L(5), V::L(channel)]);
        latency.extend_from_slice(&[TAG_TIMEVAL, 0, 0, 0, 7, 0, 0, 0, 9]);
        let lat = answer(s.up(&framed(COMMAND_CHANNEL, &latency)), 5);
        assert_eq!(lat.len(), 2 + 7);
        assert_eq!(lat[4].value, Value::Bool(false), "corked: not running");
        let volume = packet(
            COMMAND_SET_SOURCE_OUTPUT_VOLUME,
            6,
            &[V::L(GHOST_INDICES), V::CVol],
        );
        answer(s.up(&volume), 6);
        answer(
            s.up(&packet(COMMAND_DELETE_RECORD_STREAM, 7, &[V::L(channel)])),
            7,
        );
        assert!(s.ghosts.is_empty());
        // Silence of each format.
        let spec = |format| Spec {
            format,
            channels: 1,
            rate: 8000,
        };
        assert_eq!(silence_frame(3, spec(0), 2)[DESCRIPTOR..], [0x80, 0x80]);
        assert_eq!(silence_frame(3, spec(2), 1)[DESCRIPTOR..], [0xff]);
        assert_eq!(silence_frame(3, spec(3), 2)[DESCRIPTOR..], [0, 0]);
        assert_eq!(channel_of(&silence_frame(3, spec(3), 2)), Some(3));
        assert_eq!(spec(13).frame_bytes(), None);
    }

    /// Allowed, a silent stream's real one is made by the filter's own
    /// request — the format as the program was told it, its corking — and
    /// linked: the server's answer is not the program's, the sound and the
    /// words of the server's channel come on the program's, and its
    /// commands go to the server's channel and index. A real stream on a
    /// channel a silent one has is told another.
    #[test]
    fn an_allowed_silent_stream_is_linked_to_the_real_one() {
        let mut s = with_mic(Setting::Ask, true);
        let none: &[(&str, &str)] = &[];
        let Up::Ghost { channel, .. } = s.up(&record(2, INVALID, None, none, INVALID)) else {
            panic!("not silent");
        };
        s.mic.abandon();
        assert_eq!(channel, 0);
        answer_ok(s.up(&packet(
            COMMAND_CORK_RECORD_STREAM,
            3,
            &[V::L(channel), V::B(true)],
        )));
        let made = s.link(channel).expect("its real stream");
        let (command, tag) = command_of(&made).unwrap();
        assert_eq!(command, COMMAND_CREATE_RECORD_STREAM);
        assert!(tag >= OWN_TAGS);
        let items = parse(&made[DESCRIPTOR..]).unwrap();
        assert_eq!(items[7].value, Value::Bool(true), "corked");
        assert!(items[11..14].iter().all(|i| i.value == Value::Bool(false)));
        assert_eq!(u32_at(&items, 8), Some(3840));
        assert!(s.link(channel).is_none(), "made once");
        // Uncorked meanwhile: told to the real stream after its reply.
        answer_ok(s.up(&packet(
            COMMAND_CORK_RECORD_STREAM,
            4,
            &[V::L(channel), V::B(false)],
        )));
        let reply = record_reply(tag, 5, 77, Some("alsa_input.usb-Mic.mono"));
        let Down::Own(Some(cork)) = s.down(&reply) else {
            panic!("the reply was the program's");
        };
        assert_eq!(
            command_of(&cork).map(|c| c.0),
            Some(COMMAND_CORK_RECORD_STREAM)
        );
        assert!(matches!(
            s.down(&error_of(command_of(&cork).unwrap().1, 1)),
            Down::Own(None)
        ));
        // The server's sound and words on the program's channel.
        let Down::Rewritten(data) = s.down(&framed(5, b"sound")) else {
            panic!("not the program's channel");
        };
        assert_eq!(channel_of(&data), Some(0));
        let suspended = packet(
            COMMAND_RECORD_STREAM_SUSPENDED,
            INVALID,
            &[V::L(5), V::B(true)],
        );
        let Down::Rewritten(word) = s.down(&suspended) else {
            panic!("not the program's channel");
        };
        assert_eq!(
            parse(&word[DESCRIPTOR..]).and_then(|i| u32_at(&i, 2)),
            Some(0)
        );
        // Its commands to the server's channel and index.
        let Up::Forward(cork) = s.up(&packet(
            COMMAND_CORK_RECORD_STREAM,
            6,
            &[V::L(0), V::B(true)],
        )) else {
            panic!("not the server's");
        };
        assert_eq!(
            parse(&cork[DESCRIPTOR..]).and_then(|i| u32_at(&i, 2)),
            Some(5)
        );
        let Up::Forward(volume) = s.up(&packet(
            COMMAND_SET_SOURCE_OUTPUT_VOLUME,
            7,
            &[V::L(GHOST_INDICES), V::CVol],
        )) else {
            panic!("not the server's");
        };
        assert_eq!(
            parse(&volume[DESCRIPTOR..]).and_then(|i| u32_at(&i, 2)),
            Some(77)
        );
        // Another silent stream takes channel 1; a real one the server puts
        // on channel 1 is told channel 2.
        s.mic_denied = true;
        let Up::Ghost {
            channel: second, ..
        } = s.up(&record(8, INVALID, None, none, INVALID))
        else {
            panic!("not silent");
        };
        assert_eq!(second, 1);
        s.creating.insert(9, Kind::Record);
        let Down::Rewritten(told) = s.down(&record_reply(
            9,
            1,
            78,
            Some("alsa_input.pci.analog-stereo"),
        )) else {
            panic!("told the channel of a silent stream");
        };
        assert_eq!(
            parse(&told[DESCRIPTOR..]).and_then(|i| u32_at(&i, 2)),
            Some(2)
        );
        let Down::Rewritten(data) = s.down(&framed(1, b"sound")) else {
            panic!("not the program's channel");
        };
        assert_eq!(channel_of(&data), Some(2));
        // Deleted by the program: gone from the translation.
        let Up::Forward(delete) = s.up(&packet(COMMAND_DELETE_RECORD_STREAM, 10, &[V::L(0)]))
        else {
            panic!("not the server's");
        };
        assert_eq!(
            parse(&delete[DESCRIPTOR..]).and_then(|i| u32_at(&i, 2)),
            Some(5)
        );
        assert!(!s.ghosts.contains_key(&0) && !s.record_down.contains_key(&5));
        assert_eq!(s.down(&framed(5, b"x")), Down::Drop);
    }

    /// A silent stream the program deleted while its real one was being
    /// made: the real one is deleted as soon as it is; one the server
    /// linked to a monitor, too — and the silent one stays silent.
    #[test]
    fn a_real_stream_nobody_wants_is_deleted() {
        let mut s = with_mic(Setting::Ask, true);
        let none: &[(&str, &str)] = &[];
        let Up::Ghost { channel, .. } = s.up(&record(2, INVALID, None, none, INVALID)) else {
            panic!("not silent");
        };
        s.mic.abandon();
        let made = s.link(channel).unwrap();
        let tag = command_of(&made).unwrap().1;
        answer_ok(s.up(&packet(COMMAND_DELETE_RECORD_STREAM, 3, &[V::L(channel)])));
        let Down::Own(Some(delete)) = s.down(&record_reply(tag, 4, 70, Some("alsa_input.x")))
        else {
            panic!("not deleted");
        };
        assert_eq!(
            command_of(&delete).map(|c| c.0),
            Some(COMMAND_DELETE_RECORD_STREAM)
        );
        assert!(s.record_down.is_empty());
        // Linked to a monitor: deleted, silent again.
        s.mic_denied = true;
        let Up::Ghost { channel, .. } = s.up(&record(5, INVALID, None, none, INVALID)) else {
            panic!("not silent");
        };
        let made = s.link(channel).unwrap();
        let tag = command_of(&made).unwrap().1;
        let Down::Own(Some(_)) = s.down(&record_reply(tag, 6, 71, Some("x.monitor"))) else {
            panic!("not deleted");
        };
        assert_eq!(s.ghosts[&channel].link, Link::Silent);
        assert_eq!(s.down(&framed(6, b"x")), Down::Drop);
    }

    fn answer_ok(up: Up) {
        match up {
            Up::Answer(frame) => assert_eq!(command_of(&frame).map(|c| c.0), Some(COMMAND_REPLY)),
            other => panic!("not answered: {other:?}"),
        }
    }

    /// "Ask" for real: the record stream is answered at once, silent, while
    /// the person is asked and the connection's other commands reach the
    /// server; allowed once, its real stream is made — that stream only;
    /// refused, it stays silent and the connection is not asked again.
    #[test]
    fn a_record_stream_is_silent_until_the_answer_and_the_rest_goes_on() {
        use std::io::Write;
        use std::time::{Duration, Instant};
        let dir = std::env::temp_dir().join(format!("vz-pulse-ask-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state/nl")).unwrap();
        fs::create_dir_all(dir.join("config")).unwrap();
        // A kdialog that writes down its question and answers what `go` says.
        let kdialog = dir.join("kdialog");
        let (asked, go) = (dir.join("asked"), dir.join("go"));
        crate::dialog::test_program(
            &kdialog,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {asked}.tmp && mv {asked}.tmp {asked}\n\
                 while [ ! -e {go} ]; do sleep 0.05; done\nexit $(cat {go})\n",
                asked = asked.display(),
                go = go.display()
            ),
        );
        let answer = |code: &str| {
            fs::write(dir.join("go.tmp"), code).unwrap();
            fs::rename(dir.join("go.tmp"), &go).unwrap();
        };
        let wait_asked = || {
            let started = Instant::now();
            while !asked.exists() {
                assert!(started.elapsed() < Duration::from_secs(10), "never asked");
                thread::sleep(Duration::from_millis(20));
            }
            fs::read_to_string(&asked).unwrap()
        };
        let mic = Arc::new(Policy::for_test(
            dir.join("state/nl"),
            dir.join("config"),
            dir.join("profiles"),
            kdialog.clone(),
            true,
            Duration::from_secs(20),
        ));
        let upstream = dir.join("server");
        let server = UnixListener::bind(&upstream).unwrap();
        let (client, filter_side) = UnixStream::pair().unwrap();
        let path = upstream.clone();
        thread::spawn(move || {
            let _ = serve(filter_side, &path, mic, (Who::Main, None));
        });
        let (seen, _) = server.accept().unwrap();
        seen.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut c = client;
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let none: &[(&str, &str)] = &[];
        c.write_all(&auth(0)).unwrap();
        c.write_all(&packet(
            COMMAND_SET_CLIENT_NAME,
            1,
            &[V::P(&[("application.name", "<b>Evil</b>\nЗона: host")])],
        ))
        .unwrap();
        c.write_all(&record(2, INVALID, None, none, INVALID))
            .unwrap();
        c.write_all(&packet(COMMAND_GET_SERVER_INFO, 3, &[]))
            .unwrap();
        // The server gets the rest of the connection's commands, not the
        // silent stream.
        let mut frames = Frames::new(&seen);
        let mut next = || command_of(&frames.next().unwrap().unwrap().0).unwrap();
        assert_eq!(next(), (COMMAND_AUTH, 0));
        assert_eq!(next(), (COMMAND_SET_CLIENT_NAME, 1));
        assert_eq!(next(), (COMMAND_GET_SERVER_INFO, 3));
        // The program: its stream's reply at once, then silence on it.
        let reader = c.try_clone().unwrap();
        let mut heard = Frames::new(&reader);
        let mut replied = || loop {
            let (frame, _) = heard.next().unwrap().unwrap();
            if channel_of(&frame) == Some(COMMAND_CHANNEL) {
                break command_of(&frame).unwrap();
            }
            assert!(frame[DESCRIPTOR..].iter().all(|b| *b == 0), "not silence");
        };
        assert_eq!(replied(), (COMMAND_REPLY, 2));
        // The question: the filter's zone, the program's own word, cleaned.
        let question = wait_asked();
        assert!(
            question.contains("настоящего дома (сеть «nl»)"),
            "{question}"
        );
        assert!(question.contains("«‹b›Evil‹/b› Зона: host»"), "{question}");
        assert!(question.contains("Всегда — настоящему дому"), "{question}");
        // Once: its real stream is made now, by the filter's own request;
        // nothing is remembered.
        answer("0");
        let (made, tag) = next();
        assert_eq!(made, COMMAND_CREATE_RECORD_STREAM);
        assert!(tag >= OWN_TAGS, "the program's tag: {tag}");
        assert!(!dir.join("state/nl/microphone").exists());
        // A stream asked for while the last question is still closing is
        // refused as "a question is open": asked for again, with the next
        // tag, until it is not.
        let mut tag = 4;
        let mut asked_for = |c: &mut UnixStream, replied: &mut dyn FnMut() -> (u32, u32)| loop {
            c.write_all(&record(tag, INVALID, None, none, INVALID))
                .unwrap();
            let (command, answered) = replied();
            assert_eq!(answered, tag);
            tag += 1;
            if command == COMMAND_REPLY {
                return answered;
            }
            assert_eq!(command, COMMAND_ERROR);
            thread::sleep(Duration::from_millis(20));
        };
        // The next stream is asked about again, and refused: silent.
        fs::remove_file(&asked).unwrap();
        fs::remove_file(&go).unwrap();
        asked_for(&mut c, &mut replied);
        wait_asked();
        answer("2");
        // Refused once: this connection is not asked again — silent too.
        fs::remove_file(&asked).unwrap();
        let last = asked_for(&mut c, &mut replied);
        assert!(!asked.exists(), "asked again after a refusal");
        // Neither refused stream reached the server.
        c.write_all(&packet(COMMAND_GET_SERVER_INFO, last + 1, &[]))
            .unwrap();
        assert_eq!(next(), (COMMAND_GET_SERVER_INFO, last + 1));
        let _ = fs::remove_dir_all(&dir);
    }
}
