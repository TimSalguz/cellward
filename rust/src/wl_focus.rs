//! Who may give a program's window the keyboard focus: the Wayland proxy's
//! word on `xdg_activation_v1` (the owner, 2026-09-27;
//! `docs/WINDOW-FRAME.md` §8, «Фокус»; `docs/THREAT-MODEL.md` W17).
//!
//! **How a program asks.** `xdg_activation_v1.get_activation_token` makes a
//! token object; on it the program may name the input event it acts on
//! (`set_serial`: the serial of an event the compositor sent it, and the
//! seat), itself (`set_app_id`) and its surface (`set_surface`); it
//! `commit`s, and the compositor answers `done` with the token, a string.
//! `xdg_activation_v1.activate(token, surface)` then asks for the focus —
//! for a window of its own, or, the token handed over, for another
//! program's. What is honoured is the compositor's to say: niri takes a
//! token whose serial is no older than the keyboard's or the pointer's last
//! entering, for ten seconds; wlroots one whose serial it gave that client,
//! made while its surface had the keyboard or the pointer. Both forget a
//! token once it is used.
//!
//! **What went wrong** (the owner, 2026-09-27). Qt makes a new token for
//! every `requestActivate()`, each from the last serial it has: Telegram,
//! opening an image in a window of its own, asks again and again, and the
//! compositor honours every one — the focus is taken several times over,
//! all from one click. The same is a way to take keys: the person types a
//! password into the browser, a program in a zone takes the focus, and the
//! keys that follow are its.
//!
//! **The policy** is a container's (`cellward container set <c> focus`,
//! `programs.cellward.containers.<c>.focus`; `input` without one), given to
//! the proxy with the launch (`wl-sandbox --focus`). The proxy sees every
//! request of the launch's programs, so it holds on any compositor:
//!
//! * `input` — one input event of the person, one change of the focus. The
//!   first `activate` for what its token was made from goes up, the rest are
//!   dropped: no error, the request does nothing, as one a compositor
//!   declines. What a token was made from is its serial when the program set
//!   one — the serial alone, not with the seat: compositors count serials
//!   for the whole display (libwayland's, which wlroots and KWin use;
//!   smithay's, niri's), so a serial names one event on whichever seat, and
//!   a program that binds the seat twice gets no second change out of one
//!   click. A token made without a serial, and one the program did not make
//!   through the launch's connections (a launcher's `XDG_ACTIVATION_TOKEN`, a
//!   notification's), counts by its string: once each. The launch's
//!   connections share one count ([`Activations`]): a program does not get
//!   a second change by asking on a second connection. No clock: a serial
//!   is used up by its change of the focus, not by time.
//! * `notify` — no `activate` goes up. The supervisor is asked (a byte on
//!   its channel, `crate::wl_proxy`) to tell the person: «<программа> просит
//!   внимания», with «Перейти», which focuses a window of the launch through
//!   the compositor's IPC (`crate::focus::attention`). One notification of a
//!   launch at a time: requests while it is up do nothing.
//! * `ask` — the same, with a question in its place, guarded against keys
//!   typed on (`crate::window::question`).
//! * `allow` — everything goes up, as without the proxy.
//!
//! **What it does not decide.** A NEW window taking the focus as it opens is
//! the compositor's own rule (niri: the window rule `open-focused`). Only
//! tokens the compositor made and the program's own requests are looked at:
//! nothing more is trusted to the program than before, and the proxy's
//! seccomp filter is as it was. A setting changed applies to programs
//! started after it, as the frame's colour does.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::rc::Rc;

use wl_proxy::object::{Object, ObjectRcUtils};
use wl_proxy::protocols::wayland::wl_seat::WlSeat;
use wl_proxy::protocols::wayland::wl_surface::WlSurface;
use wl_proxy::protocols::xdg_activation_v1::xdg_activation_token_v1::{
    XdgActivationTokenV1, XdgActivationTokenV1Handler,
};
use wl_proxy::protocols::xdg_activation_v1::xdg_activation_v1::{
    XdgActivationV1, XdgActivationV1Handler,
};

use crate::container::{Source, Sourced};
use crate::tools::Tools;

/// The key of a container's settings it is written under, and the word of
/// `cellward container set`.
pub const KEY: &str = "focus";

/// What becomes of a program's asking for the focus
/// (`xdg_activation_v1.activate`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FocusPolicy {
    /// One input event of the person, one change of the focus.
    #[default]
    Input,
    /// None goes up; the person is told, and goes there with a click.
    Notify,
    /// None goes up; the person is asked.
    Ask,
    /// Every one goes up, as without the proxy.
    Allow,
}

impl FocusPolicy {
    /// As the settings, Nix and `wl-sandbox --focus` write it.
    pub fn parse(word: &str) -> Option<Self> {
        match word.trim() {
            "input" => Some(Self::Input),
            "notify" => Some(Self::Notify),
            "ask" => Some(Self::Ask),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Notify => "notify",
            Self::Ask => "ask",
            Self::Allow => "allow",
        }
    }

    /// Whether a request held back is told to the person: `notify`, `ask`.
    pub fn tells(self) -> bool {
        matches!(self, Self::Notify | Self::Ask)
    }
}

/// A container's policy and where it is from: Nix's word, then its local
/// one (`crate::container::own_value_in`), then `input`. A word that is no
/// policy is none. A file that is there and cannot be read — what it says
/// is not known — is `notify`, where it is: nothing passes, and nothing
/// comes up by itself.
pub fn of_container(config: &Path, name: &str) -> Sourced<FocusPolicy> {
    let default = Sourced {
        value: FocusPolicy::Input,
        source: Source::Default,
    };
    match crate::container::own_value_in(config, name, KEY) {
        Ok(Some((word, source))) => FocusPolicy::parse(&word)
            .map(|value| Sourced { value, source })
            .unwrap_or(default),
        Ok(None) => default,
        Err(source) => Sourced {
            value: FocusPolicy::Notify,
            source,
        },
    }
}

/// The policy of a launch: its container's, `input` for a launch without
/// one (the main home, a throwaway container).
pub fn of_launch(tools: &Tools, container: Option<&str>) -> FocusPolicy {
    container
        .and_then(|name| crate::container::load(tools, name))
        .map_or(FocusPolicy::Input, |c| c.focus.value)
}

// --- `input`: what has had its change of the focus ---------------------------

/// Tokens made on the launch's connections remembered at once: a program
/// makes one per request, and a well-behaved one uses it at once.
const MAX_MADE: usize = 1024;
/// Serials remembered one by one; an older one forgotten raises the floor.
const MAX_SERIALS: usize = 64;
/// Token strings that have had their change, remembered at once.
const MAX_TOKENS: usize = 1024;

/// What `input` has let through, for the whole launch.
///
/// Bounded, and never so that forgetting lets through what would not have
/// passed with more memory — with one exception said below:
///
/// * a serial used up and forgotten raises a FLOOR: no serial as old as it
///   passes again. Serials count up, and a program acts on its latest; an
///   older one it had not used yet is stale by then — the person has acted
///   since. A program that sets a serial far ahead only closes its own
///   launch;
/// * a token of the launch's forgotten is taken for used up: an `activate`
///   with it later would otherwise count as a token from outside, and pass
///   once more;
/// * a token string used up and forgotten may pass once again, after
///   [`MAX_TOKENS`] others. Where it came from outside, niri and wlroots
///   have forgotten it themselves once it was used; the one way it counts
///   is a program making more than [`MAX_MADE`] tokens, and asking with as
///   many strings, within the few seconds a compositor keeps a token (niri:
///   ten) — a second change of the focus from one click. `notify` and `ask`
///   pass none.
#[derive(Debug, Default)]
pub(crate) struct Activations {
    /// Tokens the compositor made for the launch's connections, with the
    /// serial each was made from (`None`: without one).
    made: HashMap<String, Option<u32>>,
    made_order: VecDeque<String>,
    /// Serials that have had their change, the oldest first.
    serials: VecDeque<u32>,
    /// The newest serial forgotten from [`Self::serials`].
    floor: Option<u32>,
    /// Token strings that have had theirs, and the order they came in.
    tokens: HashSet<String>,
    tokens_order: VecDeque<String>,
}

impl Activations {
    /// The compositor made `token` for one of the launch's connections
    /// (`done`), from `serial` when the program set one. A string the
    /// compositor made twice keeps what it was first made from.
    pub(crate) fn made(&mut self, token: &str, serial: Option<u32>) {
        if self.made.contains_key(token) {
            return;
        }
        if self.made.len() >= MAX_MADE {
            if let Some(old) = self.made_order.pop_front() {
                self.made.remove(&old);
                self.spend_token(old);
            }
        }
        self.made.insert(token.to_owned(), serial);
        self.made_order.push_back(token.to_owned());
    }

    /// Whether an `activate` with `token` goes up: the first for what the
    /// token was made from does, and uses it up.
    pub(crate) fn pass(&mut self, token: &str) -> bool {
        match self.made.get(token).copied().flatten() {
            Some(serial) => self.spend_serial(serial),
            None => self.spend_token(token.to_owned()),
        }
    }

    fn spend_serial(&mut self, serial: u32) -> bool {
        if self.serials.contains(&serial) || self.floor.is_some_and(|floor| !newer(serial, floor)) {
            return false;
        }
        if self.serials.len() >= MAX_SERIALS {
            if let Some(old) = self.serials.pop_front() {
                self.floor = Some(match self.floor {
                    Some(floor) if newer(floor, old) => floor,
                    _ => old,
                });
            }
        }
        self.serials.push_back(serial);
        true
    }

    fn spend_token(&mut self, token: String) -> bool {
        if self.tokens.contains(&token) {
            return false;
        }
        if self.tokens.len() >= MAX_TOKENS {
            if let Some(old) = self.tokens_order.pop_front() {
                self.tokens.remove(&old);
            }
        }
        self.tokens.insert(token.clone());
        self.tokens_order.push_back(token);
        true
    }
}

/// Whether serial `a` came after `b`. Serials count up and wrap: the one
/// less than half the circle ahead is the newer — libwayland's and
/// smithay's reading.
fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

// --- the proxy's side ------------------------------------------------------

/// The launch's policy, shared by its connections: what `input` has let
/// through, and whether a request was held back that the person is to be
/// told of.
pub(crate) struct Focus {
    policy: FocusPolicy,
    seen: RefCell<Activations>,
    wanted: Cell<bool>,
}

impl Focus {
    pub(crate) fn new(policy: FocusPolicy) -> Rc<Self> {
        Rc::new(Self {
            policy,
            seen: RefCell::new(Activations::default()),
            wanted: Cell::new(false),
        })
    }

    /// A global the program has bound: `xdg_activation_v1` is watched,
    /// unless everything passes. The frame never watches it
    /// (`crate::wl_frame`), so the handler is this one's.
    pub(crate) fn watch(self: &Rc<Self>, id: &Rc<dyn Object>) {
        if self.policy == FocusPolicy::Allow {
            return;
        }
        if let Some(activation) = id.try_downcast::<XdgActivationV1>() {
            activation.set_handler(Activation {
                focus: self.clone(),
            });
        }
    }

    /// Whether a request was held back since the last look (`notify`,
    /// `ask`): the proxy's loop asks after every round, and sends the
    /// supervisor one byte for any number of them.
    pub(crate) fn take_wanted(&self) -> bool {
        self.wanted.replace(false)
    }
}

/// A program's `xdg_activation_v1`.
struct Activation {
    focus: Rc<Focus>,
}

impl XdgActivationV1Handler for Activation {
    fn handle_get_activation_token(
        &mut self,
        slf: &Rc<XdgActivationV1>,
        id: &Rc<XdgActivationTokenV1>,
    ) {
        // Only `input` counts by what a token was made from.
        if self.focus.policy == FocusPolicy::Input {
            id.set_handler(Token {
                focus: self.focus.clone(),
                serial: None,
            });
        }
        slf.send_get_activation_token(id);
    }

    fn handle_activate(&mut self, slf: &Rc<XdgActivationV1>, token: &str, surface: &Rc<WlSurface>) {
        let pass = match self.focus.policy {
            FocusPolicy::Allow => true,
            FocusPolicy::Input => self.focus.seen.borrow_mut().pass(token),
            FocusPolicy::Notify | FocusPolicy::Ask => {
                self.focus.wanted.set(true);
                false
            }
        };
        if pass {
            slf.send_activate(token, surface);
        }
    }
}

/// A token object of the program's, under `input`: the serial it was made
/// from, and the string the compositor made of it.
struct Token {
    focus: Rc<Focus>,
    serial: Option<u32>,
}

impl XdgActivationTokenV1Handler for Token {
    fn handle_set_serial(
        &mut self,
        slf: &Rc<XdgActivationTokenV1>,
        serial: u32,
        seat: &Rc<WlSeat>,
    ) {
        // The last one before the commit is the one the compositor keeps.
        self.serial = Some(serial);
        slf.send_set_serial(serial, seat);
    }

    fn handle_done(&mut self, slf: &Rc<XdgActivationTokenV1>, token: &str) {
        self.focus.seen.borrow_mut().made(token, self.serial);
        slf.send_done(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_is_one_of_four_words() {
        for policy in [
            FocusPolicy::Input,
            FocusPolicy::Notify,
            FocusPolicy::Ask,
            FocusPolicy::Allow,
        ] {
            assert_eq!(FocusPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(FocusPolicy::parse(" notify\n"), Some(FocusPolicy::Notify));
        assert_eq!(FocusPolicy::default(), FocusPolicy::Input);
        // `default` is the CLI's word for "none of its own", not a policy.
        for bad in ["", "default", "Input", "yes", "deny", "focus"] {
            assert_eq!(FocusPolicy::parse(bad), None, "{bad:?}");
        }
        assert!(FocusPolicy::Notify.tells() && FocusPolicy::Ask.tells());
        assert!(!FocusPolicy::Input.tells() && !FocusPolicy::Allow.tells());
    }

    /// One click, one change: the same serial twice is one `activate`, a
    /// new serial another; a token from outside passes once, and one made
    /// without a serial counts by its string.
    #[test]
    fn one_input_event_is_one_change_of_the_focus() {
        let mut seen = Activations::default();
        seen.made("t1", Some(5));
        seen.made("t2", Some(5));
        seen.made("t3", Some(6));
        seen.made("t4", None);
        assert!(seen.pass("t1"), "the first of its click");
        assert!(!seen.pass("t2"), "a second token of the same click");
        assert!(!seen.pass("t1"), "the same token again");
        assert!(seen.pass("t3"), "a new click");
        assert!(seen.pass("from-a-launcher"), "a token from outside, once");
        assert!(!seen.pass("from-a-launcher"), "and not twice");
        assert!(seen.pass("t4"), "made without a serial: once by its string");
        assert!(!seen.pass("t4"));
        // A string the compositor made again keeps its first serial.
        seen.made("t3", Some(99));
        assert!(!seen.pass("t3"));
    }

    /// Serials used up and forgotten raise a floor: none as old passes
    /// again; the newer ones do. Across the wrap, too.
    #[test]
    fn a_forgotten_serial_is_still_used_up() {
        let mut seen = Activations::default();
        let first = u32::MAX - 10;
        let serials: Vec<u32> = (0..MAX_SERIALS as u32 + 20)
            .map(|i| first.wrapping_add(i))
            .collect();
        for (i, &serial) in serials.iter().enumerate() {
            let token = format!("s{i}");
            seen.made(&token, Some(serial));
            assert!(seen.pass(&token), "{serial}");
        }
        assert!(seen.serials.len() <= MAX_SERIALS);
        // The oldest are forgotten, and still refused — through the wrap.
        seen.made("again", Some(first));
        assert!(!seen.pass("again"));
        seen.made("older", Some(first - 1));
        assert!(!seen.pass("older"), "older than the floor");
        let next = serials.last().unwrap().wrapping_add(1);
        seen.made("next", Some(next));
        assert!(seen.pass("next"), "a newer click");
        assert!(newer(0, u32::MAX) && !newer(u32::MAX, 0) && !newer(7, 7));
    }

    /// A token of the launch forgotten is used up, not taken for one from
    /// outside.
    #[test]
    fn a_forgotten_token_of_the_launch_is_used_up() {
        let mut seen = Activations::default();
        seen.made("old", Some(1));
        for i in 0..MAX_MADE {
            seen.made(&format!("t{i}"), Some(1000 + i as u32));
        }
        assert!(seen.made.len() <= MAX_MADE && !seen.made.contains_key("old"));
        assert!(!seen.pass("old"));
    }

    /// Nix's word over the local one over `input`; a word that is no policy
    /// is none.
    #[test]
    fn nix_over_local_over_the_default() {
        let base = std::env::temp_dir().join(format!("vz-focus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let config = base.join("config");
        std::fs::create_dir_all(config.join("containers/work")).unwrap();
        std::fs::create_dir_all(config.join("declared/containers")).unwrap();
        let local = config.join("containers/work/container.conf");
        let at = |value, source| Sourced { value, source };
        assert_eq!(
            of_container(&config, "work"),
            at(FocusPolicy::Input, Source::Default)
        );
        std::fs::write(&local, "home = private\nfocus = notify\n").unwrap();
        assert_eq!(
            of_container(&config, "work"),
            at(FocusPolicy::Notify, Source::Local)
        );
        std::fs::write(&local, "focus = sometimes\n").unwrap();
        assert_eq!(
            of_container(&config, "work"),
            at(FocusPolicy::Input, Source::Default)
        );
        std::fs::write(&local, "focus = allow\n").unwrap();
        crate::declared::declare(
            &config.join("declared/containers/work.conf"),
            "home = private\nfocus = ask\n",
        );
        assert_eq!(
            of_container(&config, "work"),
            at(FocusPolicy::Ask, Source::Nix)
        );
        // Declared without a word of its own: the local one.
        crate::declared::declare(
            &config.join("declared/containers/work.conf"),
            "home = private\n",
        );
        assert_eq!(
            of_container(&config, "work"),
            at(FocusPolicy::Allow, Source::Local)
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
