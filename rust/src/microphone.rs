//! The microphone by permission (owner, 2026-09-25): a program in a zone
//! records only as the zone's setting says — `yes`, `no`, or `ask`, the
//! default: the first time a program of the zone records, the person on the
//! host is asked, as a phone asks — allow once, allow always, deny.
//!
//! **Where it is decided.** In the sound filter (`crate::pulse_filter`), one
//! process per zone on the host, when a program asks for a record stream: the
//! setting is read then, so a change applies at once, without restarting the
//! zone. For `ask` the filter holds that one request — the connection's other
//! commands go on — until the answer, and then passes it or answers it
//! `ERROR`/`ACCESS`. The zone in the question is the filter's own, the one it
//! was started for; nothing a program says names it. The program's name in
//! the question is its own word (its properties) and is shown as that,
//! cleaned (`shown_program`).
//!
//! **Where the setting lives** is out of the zone's own file system, so that a
//! program cannot answer its own question: the zone's marker in its state
//! directory (`~/.local/state/vpn-zones/<zone>/microphone`, hidden from zones
//! — LEAK-MODEL §17), and `declared/microphone` below `~/.config/vpn-zones`
//! (Nix, `programs.vpn-zones.microphone`; read-only in zones). The filter
//! that reads and writes them runs in the host's user namespace
//! (`zone::Helpers`), and so does the kdialog it asks with: a program of the
//! zone cannot reach the host's file system through their `/proc/<pid>/root`.
//! What this does NOT hold: a zone that is not hermetic keeps the host's
//! `systemd --user`, and through it runs anything on the host — a recorder,
//! or a write to the marker; and the raw `pipewire-0` records past the sound
//! filter in every zone (LEAK-MODEL §17, ROADMAP §17). The switch is the
//! PulseAudio path's.
//!
//! **Which wins**: Nix over the zone's marker, the marker over the default
//! (`ask`). A value that is none of the three, or a file that is there but
//! cannot be read, is `no`: nothing opens the microphone by accident. "Allow
//! always" writes `yes` into the marker — offered only where the marker
//! decides, i.e. not when Nix set the zone's value.
//!
//! **Nobody to ask** — no `WAYLAND_DISPLAY` or `DISPLAY` in the filter's
//! environment, or no answer within [`TIMEOUT`] — is a refusal, said on the
//! filter's stderr (the zone's unit journal) and in `vpn-zone journal`. One
//! question at a time per zone: a request while one is open is refused, not
//! queued — a stream of questions is how a "yes" is got by accident (the
//! broker's rule). A person's "deny" stands for that connection: the
//! program's retries on it are refused without asking again; and for
//! [`AFTER_DENY`] no program of the zone is asked at all, so that one that
//! reconnects after every refusal cannot keep a dialog waiting for a stray
//! Enter. "Always" is the ZONE's: the button and the text say so, since the
//! program's name in the question is only its own word.
//!
//! Monitors (what the host plays) are not a microphone, and never recordable
//! whatever this says (`pulse_filter::record_refused`, the server's word).

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cli::DECLARED_DIR;
use crate::container::Source;

/// The zone's marker, in its state directory: `yes`, `no` or `ask`.
pub const MARKER: &str = "microphone";
/// The values Nix declared, below `declared/`: `<zone> <value>` per line.
pub const DECLARED: &str = "microphone";
/// How long a question waits for its answer. Under libpulse's own wait for a
/// reply (`DEFAULT_TIMEOUT`, 30 s): past that the program has failed the
/// stream and stopped waiting, and a late "yes" would open the microphone
/// for a request nobody waits on — the server capturing, the sound going to
/// a socket whose program has moved on.
pub const TIMEOUT: Duration = Duration::from_secs(25);
/// After a refusal of the person's — or a question nobody answered — the
/// zone is not asked again for this long: its requests are refused without
/// a dialog.
pub const AFTER_DENY: Duration = Duration::from_secs(180);
/// At most one line in `vpn-zone journal` per this long for refusals nobody
/// was asked about: a program asking in a loop must not wash the journal's
/// history out (it rotates at a megabyte). stderr gets every one.
const QUIET: Duration = Duration::from_secs(10);

/// A zone's microphone setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    Yes,
    No,
    Ask,
}

impl Setting {
    /// One of the three words; anything else is `None`.
    pub fn parse(word: &str) -> Option<Self> {
        match word.trim() {
            "yes" => Some(Self::Yes),
            "no" => Some(Self::No),
            "ask" => Some(Self::Ask),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Ask => "ask",
        }
    }
}

/// The zone's setting and where it comes from.
pub fn setting(zone_dir: &Path, config: &Path, zone: &str) -> (Setting, Source) {
    match std::fs::read_to_string(config.join(DECLARED_DIR).join(DECLARED)) {
        Ok(text) => {
            let declared = text.lines().find_map(|line| {
                let (name, value) = line.trim().split_once(char::is_whitespace)?;
                (name == zone).then(|| Setting::parse(value).unwrap_or(Setting::No))
            });
            if let Some(value) = declared {
                return (value, Source::Nix);
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        // Nix may have said "no" for this zone in a file that cannot be read.
        Err(_) => return (Setting::No, Source::Nix),
    }
    match std::fs::read_to_string(zone_dir.join(MARKER)) {
        Ok(text) if text.trim().is_empty() => (Setting::Ask, Source::Default),
        Ok(text) => (Setting::parse(&text).unwrap_or(Setting::No), Source::Local),
        Err(e) if e.kind() == ErrorKind::NotFound => (Setting::Ask, Source::Default),
        Err(_) => (Setting::No, Source::Local),
    }
}

/// What becomes of a record stream, by the setting alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Refuse(String),
    /// The person is asked; `remember` — "allow always" may be offered.
    Ask {
        remember: bool,
    },
}

/// The verdict for a setting from `source`, with or without a graphical
/// session to ask on.
pub fn verdict(setting: Setting, source: Source, display: bool) -> Verdict {
    match setting {
        Setting::Yes => Verdict::Allow,
        Setting::No => Verdict::Refuse(match source {
            Source::Nix => "микрофон зоне запрещён (задано в Nix)".to_owned(),
            _ => "микрофон зоне запрещён".to_owned(),
        }),
        Setting::Ask if !display => {
            Verdict::Refuse("спросить некого (нет графической сессии)".to_owned())
        }
        Setting::Ask => Verdict::Ask {
            remember: source != Source::Nix,
        },
    }
}

/// The person's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// This one stream.
    Once,
    /// This stream, and `yes` in the zone's marker.
    Always,
    /// Refused, and why.
    Deny(String),
}

/// The answer from kdialog's exit code: `choices` is whether "always" was
/// among the buttons (yes, no, cancel = once, always, deny) or not (yes, no
/// = once, deny). No code — not started, killed, the deadline — and a code
/// no button gives are a refusal.
pub fn answer_of(code: Option<i32>, remember: bool) -> Answer {
    match (code, remember) {
        (Some(0), _) => Answer::Once,
        (Some(1), true) => Answer::Always,
        (Some(1), false) | (Some(2), true) => Answer::Deny("человек отказал".to_owned()),
        (None, _) => Answer::Deny(format!(
            "нет ответа за {} с (или диалог не открылся)",
            TIMEOUT.as_secs()
        )),
        (Some(_), _) => Answer::Deny("диалог закрылся без ответа".to_owned()),
    }
}

/// How much of a program's name a question shows.
const SHOWN_NAME: usize = 80;

/// A program's name as it may be shown in a question: its own word, so no
/// control characters, markup or reordering marks (`broker::shown_word`),
/// not endless, and never empty.
pub fn shown_program(name: &str) -> String {
    let clean = crate::broker::shown_word(name);
    let clean = clean.trim();
    if clean.is_empty() {
        return "без имени".to_owned();
    }
    if clean.chars().count() > SHOWN_NAME {
        let head: String = clean.chars().take(SHOWN_NAME).collect();
        return format!("{head}…");
    }
    clean.to_owned()
}

/// The question's text. The zone is the filter's; the program is named as
/// it names itself, and said to be that. `remember`: "always" is offered —
/// and said to be the whole zone's, not the named program's.
pub fn question(zone: &str, program: &str, remember: bool) -> String {
    let always = if remember {
        format!(
            "«{}» — это любой программе зоны «{zone}», без вопросов, пока это не \
             отменить (vpn-zone microphone {zone} ask).\n\n",
            always_label(zone)
        )
    } else {
        String::new()
    };
    format!(
        "Программа из зоны «{zone}» хочет записывать звук с микрофона.\n\n\
         Она называет себя: «{}» — это её собственные слова.\n\n{always}Разрешить?",
        shown_program(program)
    )
}

/// The "always" button: whose it is, in its own words.
pub fn always_label(zone: &str) -> String {
    format!("Всегда — всей зоне «{zone}»")
}

/// What the filter of one zone knows to decide by. One per filter process,
/// i.e. per zone: its question lock is the zone's.
#[derive(Debug)]
pub struct Policy {
    zone: String,
    /// Where the setting is read: the zone's directory and the config
    /// directory. `None` for a fixed setting (tests).
    files: Option<(PathBuf, PathBuf)>,
    fixed: Setting,
    kdialog: PathBuf,
    /// A graphical session to ask on, from the filter's environment.
    display: bool,
    timeout: Duration,
    /// Where `vpn-zone journal` lives; `None` to write none.
    journal: Option<PathBuf>,
    /// A question is open for this zone.
    asking: AtomicBool,
    /// No question before then: the person refused, or did not answer.
    quiet_until: Mutex<Option<Instant>>,
    after_deny: Duration,
    /// The last journal line for a refusal nobody was asked about.
    last_told: Mutex<Option<Instant>>,
}

impl Default for Policy {
    /// No zone behind it: never records.
    fn default() -> Self {
        Self::fixed(Setting::No, false)
    }
}

impl Policy {
    /// The filter of the zone `zone`, its state in `zone_dir`.
    pub fn new(zone: &str, zone_dir: PathBuf, config: PathBuf, kdialog: PathBuf) -> Self {
        let journal = zone_dir.parent().map(Path::to_path_buf);
        Self {
            zone: zone.to_owned(),
            files: Some((zone_dir, config)),
            fixed: Setting::No,
            kdialog,
            display: crate::launch::has_display(),
            timeout: TIMEOUT,
            journal,
            asking: AtomicBool::new(false),
            quiet_until: Mutex::new(None),
            after_deny: AFTER_DENY,
            last_told: Mutex::new(None),
        }
    }

    /// A setting that does not come from files.
    pub fn fixed(setting: Setting, display: bool) -> Self {
        Self {
            zone: String::new(),
            files: None,
            fixed: setting,
            kdialog: PathBuf::from("/nonexistent/kdialog"),
            display,
            timeout: TIMEOUT,
            journal: None,
            asking: AtomicBool::new(false),
            quiet_until: Mutex::new(None),
            after_deny: AFTER_DENY,
            last_told: Mutex::new(None),
        }
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn has_display(&self) -> bool {
        self.display
    }

    /// The setting now, and where it comes from.
    pub fn setting(&self) -> (Setting, Source) {
        match &self.files {
            Some((dir, config)) => setting(dir, config, &self.zone),
            None => (self.fixed, Source::Default),
        }
    }

    /// What becomes of a record stream of `program`, now. A question it
    /// calls for is this zone's one open question: [`Policy::ask`] must
    /// follow, which closes it.
    pub fn decide(&self, program: &str) -> Verdict {
        let (setting, source) = self.setting();
        let verdict = verdict(setting, source, self.display);
        match &verdict {
            Verdict::Refuse(why) if setting == Setting::Ask => {
                self.tell(program, false, why, false)
            }
            Verdict::Ask { .. } if self.quiet() => {
                let why = format!(
                    "человек недавно отказал — зону не спрашивают {} мин",
                    self.after_deny.as_secs().div_ceil(60)
                );
                self.tell(program, false, &why, false);
                return Verdict::Refuse(why);
            }
            // The zone's one question: taken here, closed by `ask`.
            Verdict::Ask { .. }
                if self
                    .asking
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err() =>
            {
                let why = "уже открыт вопрос о микрофоне этой зоны".to_owned();
                self.tell(program, false, &why, false);
                return Verdict::Refuse(why);
            }
            _ => {}
        }
        verdict
    }

    /// Within the quiet after a refusal.
    fn quiet(&self) -> bool {
        let until = self.quiet_until.lock().unwrap_or_else(|e| e.into_inner());
        until.is_some_and(|t| Instant::now() < t)
    }

    /// Ask the person, and settle it: "always" is written, every answer
    /// told. `then` gets whether the stream may go on, and its result is
    /// returned; it runs BEFORE the zone's question is open again, so that
    /// what the answer means for the connection (a deny standing for it) is
    /// in place before the next request of that connection can ask. Closes
    /// the open question.
    pub fn ask<R>(&self, program: &str, remember: bool, then: impl FnOnce(bool) -> R) -> R {
        struct Close<'a>(&'a AtomicBool);
        impl Drop for Close<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _close = Close(&self.asking);
        let text = question(&self.zone, program, remember);
        let title = format!("Микрофон — зона «{}»", self.zone);
        let always = always_label(&self.zone);
        let code = if remember {
            crate::dialog::choose_within(
                &self.kdialog,
                [
                    "--title",
                    title.as_str(),
                    "--yes-label",
                    "Разрешить один раз",
                    "--no-label",
                    always.as_str(),
                    "--cancel-label",
                    "Отказать",
                    "--warningyesnocancel",
                    text.as_str(),
                ],
                self.timeout,
            )
        } else {
            crate::dialog::choose_within(
                &self.kdialog,
                [
                    "--title",
                    title.as_str(),
                    "--yes-label",
                    "Разрешить один раз",
                    "--no-label",
                    "Отказать",
                    "--warningyesno",
                    text.as_str(),
                ],
                self.timeout,
            )
        };
        let allowed = self.settle(program, &answer_of(code, remember));
        then(allowed)
    }

    /// Close the open question without asking (it could not be asked).
    pub fn abandon(&self) {
        self.asking.store(false, Ordering::SeqCst);
    }

    /// What an answer does: "always" writes `yes` — and if that cannot be
    /// written, this stream still goes on, as "once" (the person said yes).
    fn settle(&self, program: &str, answer: &Answer) -> bool {
        match answer {
            Answer::Once => {
                self.tell(program, true, "человек разрешил один раз", true);
                true
            }
            Answer::Always => {
                match self.remember() {
                    Ok(()) => self.tell(program, true, "человек разрешил всегда", true),
                    Err(e) => self.tell(
                        program,
                        true,
                        &format!("человек разрешил всегда, но это не записано ({e}) — один раз"),
                        true,
                    ),
                }
                true
            }
            Answer::Deny(why) => {
                *self.quiet_until.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now() + self.after_deny);
                self.tell(program, false, why, true);
                false
            }
        }
    }

    /// `yes` in the zone's marker.
    fn remember(&self) -> std::io::Result<()> {
        match &self.files {
            Some((dir, _)) => std::fs::write(dir.join(MARKER), "yes"),
            None => Ok(()),
        }
    }

    /// A decision about the microphone on stderr and in `vpn-zone journal`:
    /// whether it was allowed, and why. `asked`: the person was — those
    /// lines come at a person's pace; the others at most one per [`QUIET`].
    fn tell(&self, program: &str, allowed: bool, why: &str, asked: bool) {
        let program = shown_program(program);
        let decision = if allowed { "allowed" } else { "refused" };
        eprintln!(
            "pulse-filter: zone {}: microphone for «{program}» {decision}: {why}",
            self.zone
        );
        let Some(state) = &self.journal else {
            return;
        };
        if !asked {
            let mut last = self.last_told.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_some_and(|t| t.elapsed() < QUIET) {
                return;
            }
            *last = Some(Instant::now());
        }
        if let Err(e) = crate::journal::append(
            state,
            "microphone",
            &[
                ("zone", self.zone.as_str()),
                ("program", program.as_str()),
                ("decision", decision),
                ("why", why),
            ],
        ) {
            eprintln!("pulse-filter: journal: {e}");
        }
    }
}

#[cfg(test)]
impl Policy {
    /// A zone's policy in `dir` with a kdialog, a display and a deadline of
    /// the test's choosing.
    pub(crate) fn for_test(
        zone_dir: PathBuf,
        config: PathBuf,
        kdialog: PathBuf,
        display: bool,
        timeout: Duration,
    ) -> Self {
        Self {
            display,
            timeout,
            ..Self::new("nl", zone_dir, config, kdialog)
        }
    }

    /// The quiet after a refusal, shortened (or none).
    pub(crate) fn with_after_deny(mut self, after_deny: Duration) -> Self {
        self.after_deny = after_deny;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Dirs {
        base: PathBuf,
    }

    impl Dirs {
        fn new(tag: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("vpn-zone-mic-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("state/nl")).unwrap();
            std::fs::create_dir_all(base.join("config/declared")).unwrap();
            Self { base }
        }
        fn zone(&self) -> PathBuf {
            self.base.join("state/nl")
        }
        fn config(&self) -> PathBuf {
            self.base.join("config")
        }
        fn write(&self, path: &str, text: &str) {
            std::fs::write(self.base.join(path), text).unwrap();
        }
        fn setting(&self) -> (Setting, Source) {
            setting(&self.zone(), &self.config(), "nl")
        }
        /// A kdialog that answers with `script` (a shell body).
        fn kdialog(&self, name: &str, script: &str) -> PathBuf {
            let path = self.base.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }
        fn policy(&self, kdialog: PathBuf, display: bool, timeout: Duration) -> Policy {
            Policy::for_test(self.zone(), self.config(), kdialog, display, timeout)
        }
        fn journal(&self) -> String {
            std::fs::read_to_string(self.base.join("state").join(crate::journal::FILE))
                .unwrap_or_default()
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// Ask by default; the zone's marker over it; Nix over both; anything
    /// that is not one of the three words is no.
    #[test]
    fn nix_wins_over_the_marker_and_the_marker_over_ask() {
        let d = Dirs::new("precedence");
        assert_eq!(d.setting(), (Setting::Ask, Source::Default));
        d.write("state/nl/microphone", "");
        assert_eq!(d.setting(), (Setting::Ask, Source::Default));
        d.write("state/nl/microphone", "yes\n");
        assert_eq!(d.setting(), (Setting::Yes, Source::Local));
        d.write("state/nl/microphone", "no");
        assert_eq!(d.setting(), (Setting::No, Source::Local));
        d.write("state/nl/microphone", "ask");
        assert_eq!(d.setting(), (Setting::Ask, Source::Local));
        d.write("state/nl/microphone", "on");
        assert_eq!(d.setting(), (Setting::No, Source::Local));
        // Another zone's line is not this zone's.
        d.write("config/declared/microphone", "de yes\nnlx yes\n");
        assert_eq!(d.setting(), (Setting::No, Source::Local));
        d.write("state/nl/microphone", "yes");
        d.write("config/declared/microphone", "de yes\nnl no\n");
        assert_eq!(d.setting(), (Setting::No, Source::Nix));
        d.write("config/declared/microphone", "nl ask\n");
        assert_eq!(d.setting(), (Setting::Ask, Source::Nix));
        d.write("config/declared/microphone", "nl maybe\n");
        assert_eq!(d.setting(), (Setting::No, Source::Nix));
        // A declared file that is there and cannot be read: no.
        std::fs::remove_file(d.config().join("declared/microphone")).unwrap();
        std::fs::create_dir(d.config().join("declared/microphone")).unwrap();
        assert_eq!(d.setting(), (Setting::No, Source::Nix));
    }

    #[test]
    fn ask_without_a_display_is_a_refusal_and_always_only_where_the_marker_decides() {
        assert_eq!(verdict(Setting::Yes, Source::Local, false), Verdict::Allow);
        assert!(matches!(
            verdict(Setting::No, Source::Default, true),
            Verdict::Refuse(_)
        ));
        let Verdict::Refuse(why) = verdict(Setting::Ask, Source::Default, false) else {
            panic!("asked with nobody to ask");
        };
        assert!(why.contains("графической"), "{why}");
        assert_eq!(
            verdict(Setting::Ask, Source::Local, true),
            Verdict::Ask { remember: true }
        );
        assert_eq!(
            verdict(Setting::Ask, Source::Nix, true),
            Verdict::Ask { remember: false }
        );
    }

    #[test]
    fn the_buttons_mean_once_always_deny() {
        assert_eq!(answer_of(Some(0), true), Answer::Once);
        assert_eq!(answer_of(Some(1), true), Answer::Always);
        assert!(matches!(answer_of(Some(2), true), Answer::Deny(_)));
        assert_eq!(answer_of(Some(0), false), Answer::Once);
        assert!(matches!(answer_of(Some(1), false), Answer::Deny(_)));
        // No "always" where it was not offered, whatever the code.
        assert!(matches!(answer_of(Some(2), false), Answer::Deny(_)));
        assert!(matches!(answer_of(None, true), Answer::Deny(_)));
        assert!(matches!(answer_of(Some(255), true), Answer::Deny(_)));
    }

    /// The program's name is its own word: shown clean, bounded, never empty.
    #[test]
    fn a_programs_name_is_shown_clean() {
        assert_eq!(shown_program("Firefox"), "Firefox");
        assert_eq!(
            shown_program("<b>Системный</b>\nмикрофон\u{202E}"),
            "‹b›Системный‹/b› микрофон"
        );
        assert_eq!(shown_program(" \u{200B}"), "без имени");
        let long = shown_program(&"a".repeat(500));
        assert_eq!(long.chars().count(), SHOWN_NAME + 1);
        let q = question("nl", "zoom\n\nЗона: host", true);
        assert!(q.contains("зоны «nl»"), "{q}");
        assert!(
            q.contains("«zoom  Зона: host» — это её собственные слова"),
            "{q}"
        );
        // "Always" is the zone's, and the text says so where it is offered.
        assert!(
            q.contains("«Всегда — всей зоне «nl»» — это любой программе зоны «nl»"),
            "{q}"
        );
        let q = question("nl", "zoom", false);
        assert!(!q.contains("Всегда"), "{q}");
    }

    #[test]
    fn once_always_and_deny_as_the_person_answers() {
        let d = Dirs::new("answers");
        let marker = d.zone().join(MARKER);
        // Once: this stream, nothing written.
        let p = d.policy(d.kdialog("once", "exit 0"), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(p.ask("app", true, |a| a));
        assert!(!marker.exists());
        // Deny.
        let p = d.policy(d.kdialog("deny", "exit 2"), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(!p.ask("app", true, |a| a));
        assert!(!marker.exists());
        // Always: yes in the marker, and the next stream is not asked about.
        let p = d.policy(d.kdialog("always", "exit 1"), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(p.ask("app", true, |a| a));
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "yes");
        assert_eq!(p.decide("app"), Verdict::Allow);
        // Nix says ask: "always" is not offered, and its button is a no.
        std::fs::remove_file(&marker).unwrap();
        d.write("config/declared/microphone", "nl ask\n");
        let p = d.policy(d.kdialog("two", "exit 1"), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: false });
        assert!(!p.ask("app", false, |a| a));
        assert!(!marker.exists());
        let journal = d.journal();
        assert_eq!(journal.matches("\"event\":\"microphone\"").count(), 4);
        assert!(journal.contains("\"decision\":\"refused\",\"why\":\"человек отказал\""));
    }

    /// No answer in time: refused, and the dialog is gone.
    #[test]
    fn no_answer_in_time_is_a_refusal() {
        let d = Dirs::new("timeout");
        let pidfile = d.base.join("kdialog.pid");
        let kdialog = d.kdialog(
            "slow",
            &format!("echo $$ > {}; exec sleep 30", pidfile.display()),
        );
        let p = d.policy(kdialog, true, Duration::from_secs(1));
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        let started = Instant::now();
        assert!(!p.ask("app", true, |a| a));
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 only checks that the process exists.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the dialog outlived its deadline"
        );
        let said = format!("нет ответа за {} с", TIMEOUT.as_secs());
        assert!(d.journal().contains(&said), "{}", d.journal());
        // Under libpulse's own wait for the reply (30 s): an answer the
        // program no longer waits for must not open the microphone.
        assert!(TIMEOUT < Duration::from_secs(30));
        // Nobody answered: the zone is not asked again for a while either.
        assert!(matches!(p.decide("app"), Verdict::Refuse(why) if why.contains("недавно")));
        // A kdialog that cannot be started is no answer either.
        let p = d.policy(d.base.join("missing"), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(!p.ask("app", true, |a| a));
    }

    /// After a refusal the zone is not asked for a while: a program that
    /// reconnects after every "no" cannot keep a dialog up for a stray Enter.
    #[test]
    fn a_refusal_quiets_the_zone_for_a_while() {
        let d = Dirs::new("quiet");
        let asked = d.base.join("asked");
        let kdialog = d.kdialog("deny", &format!("touch {}; exit 2", asked.display()));
        let p = d.policy(kdialog.clone(), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(!p.ask("app", true, |a| a));
        std::fs::remove_file(&asked).unwrap();
        let Verdict::Refuse(why) = p.decide("app") else {
            panic!("asked again right after a refusal");
        };
        assert!(why.contains("недавно отказал"), "{why}");
        assert!(!asked.exists());
        // The switch itself still decides: yes lets it through at once.
        d.write("state/nl/microphone", "yes");
        assert_eq!(p.decide("app"), Verdict::Allow);
        std::fs::remove_file(d.zone().join(MARKER)).unwrap();
        // Once the quiet is over, the zone is asked again.
        let p = d
            .policy(kdialog, true, TIMEOUT)
            .with_after_deny(Duration::ZERO);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(!p.ask("app", true, |a| a));
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        p.abandon();
    }

    /// What an answer means for the connection is settled while the zone's
    /// question is still open: a request in between is refused as "a
    /// question is open", never asked about anew.
    #[test]
    fn the_answer_is_settled_before_the_question_closes() {
        let d = Dirs::new("settle");
        let p = d.policy(d.kdialog("once", "exit 0"), true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        let meanwhile = p.ask("app", true, |allowed| {
            assert!(allowed);
            p.decide("app")
        });
        assert!(
            matches!(&meanwhile, Verdict::Refuse(why) if why.contains("уже открыт")),
            "{meanwhile:?}"
        );
    }

    /// No display: refused without a dialog, said in the journal; one
    /// question at a time.
    #[test]
    fn nobody_to_ask_and_one_question_at_a_time() {
        let d = Dirs::new("nodisplay");
        let asked = d.base.join("asked");
        let kdialog = d.kdialog("mark", &format!("touch {}; exit 0", asked.display()));
        let p = d.policy(kdialog.clone(), false, TIMEOUT);
        assert!(matches!(p.decide("app"), Verdict::Refuse(why) if why.contains("графической")));
        assert!(!asked.exists());
        assert!(
            d.journal().contains("нет графической сессии"),
            "{}",
            d.journal()
        );
        // A second refusal right after is on stderr only.
        assert!(matches!(p.decide("app"), Verdict::Refuse(_)));
        assert_eq!(d.journal().matches("\"event\":\"microphone\"").count(), 1);

        let p = d.policy(kdialog, true, TIMEOUT);
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(matches!(p.decide("other"), Verdict::Refuse(why) if why.contains("уже открыт")));
        assert!(p.ask("app", true, |a| a));
        assert!(asked.exists());
        // Answered: the next one may ask again.
        assert_eq!(p.decide("app"), Verdict::Ask { remember: true });
        assert!(p.ask("app", true, |a| a));
    }
}
