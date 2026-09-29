//! Data containers ("profiles"): an overlayfs layer over the whole home, put
//! in place for one program run (`crate::home_layer`).
//!
//! This is `vpn-zone run --profile` seen from the inside. The bash side has
//! already entered the zone's user+net namespace (`nsenter --preserve-credentials
//! --keep-caps`) and a mount namespace of its own (`unshare --mount`, a slave
//! of the zone's: what the zone binds into its runtime directory later still
//! comes in); everything that happens here happens in that namespace and is
//! invisible to the rest of the system. Three steps:
//!
//!  1. stack the profile over the home: the lower layer is the real home
//!     (read-only in effect), the upper layer lives in the profile directory.
//!     The program sees the home, but everything it writes lands in the
//!     profile — only what is granted (`--share`) reaches the real home;
//!  2. drop the capabilities that were needed for step 1;
//!  3. start the program — and, for a throwaway container, outlive it and take
//!     the directory away afterwards.
//!
//! **Why mount(2) and not `mount(8)`.** The util-linux tool, started by a
//! non-root user, tries to drop privileges and dies with "drop permissions
//! failed" — even when the mount would be allowed (CAP_SYS_ADMIN came from
//! `nsenter --keep-caps`). The raw syscall makes no such check.
//! (`docs/GOTCHAS.md` §1)
//!
//! **Why the ambient capability set is cleared.** The capabilities are needed
//! for mounting and for nothing else. The ambient set survives `execve`, so
//! without an explicit clear Chrome would inherit CAP_SYS_ADMIN inside the
//! namespace. It cannot reach the host from there, but there is no reason to
//! hand it over either. (`docs/GOTCHAS.md` §1)
//!
//! **In a container's instance with a pid namespace of its own** (stage 3
//! of the container design, 2026-09-27, `crate::init`) this process does
//! not become the program: it stays, as the launch's subreaper
//! ([`supervise`]). Pid 1 of the namespace is every orphan's there, and a
//! daemon the program leaves behind would otherwise go to the instance's
//! pid 1 — out of the launch's tree, where its supervisor (`wl-sandbox`)
//! passes a close on and finds a window's launch (J7 of the design). Kept
//! here instead, it stays in the launch's subtree: the kernel hands this
//! process itself, once its waiter is gone, to the supervisor, the
//! subreaper one level up. The main program's status goes back to the
//! waiter at once ([`ENV_STATUS_FD`]): `cellward run` returns when the
//! program does, not when its daemons do.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// The directories a profile's layer used to cover one by one ("slots"),
/// before it covered the whole home: moved into the whole-home layer at the
/// first launch (`home_layer::migrate_slots`). Documents, `~/.bashrc` and the
/// rest of the home were written through then — the hole the whole-home layer
/// closes (owner, 2026-09-26; `docs/PERMISSIONS.md` §11.3).
pub const SUBDIRS: [&str; 5] = [".config", ".local/share", ".cache", ".mozilla", ".pki"];

/// `PR_CAP_AMBIENT` / `PR_CAP_AMBIENT_CLEAR_ALL` from `linux/prctl.h`.
///
/// Spelled out rather than taken from `libc`: the numbers are kernel ABI and
/// will never change, and this way the binary that has to clear the ambient set
/// cannot fail to build because some libc release moved the constant.
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;

/// The program could not be started at all — the code a shell uses for it.
pub const EXIT_NOT_STARTED: u8 = 127;

/// The pid namespace the launch was made to enter (`pid:[…]`, stage 3):
/// set by `container-enter`, it must be the one this process is in.
pub const ENV_EXPECT_PIDNS: &str = "VPN_ZONE_EXPECT_PIDNS";

/// The descriptor of the pipe the main program's status goes back through
/// to the launch's waiter (`crate::enter`), as a number: [`status_word`]
/// once the main program has ended.
pub const ENV_STATUS_FD: &str = "VPN_ZONE_STATUS_FD";

/// The signals passed on to every child of the launch's subreaper — the
/// program and the orphans it adopted —, as `wl-sandbox` passes them on
/// (`wl_proxy::pass_on`): what a launch is ended or told something with.
pub const FORWARDED: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

/// What goes into the status pipe: `S` and the main program's exit code, as
/// a shell reports it ([`exit_code_of`]).
pub fn status_word(code: u8) -> [u8; 2] {
    [b'S', code]
}

/// The launch's subreaper's one question: which end is the main program's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subreaper {
    main: libc::pid_t,
    code: Option<u8>,
}

impl Subreaper {
    pub fn new(main: libc::pid_t) -> Self {
        Self { main, code: None }
    }

    /// A child reaped, with its code: the main program's status — once, to
    /// be said to the waiter — or nothing (an orphan it adopted).
    pub fn reaped(&mut self, pid: libc::pid_t, code: u8) -> Option<u8> {
        if pid != self.main || self.code.is_some() {
            return None;
        }
        self.code = Some(code);
        self.code
    }

    /// What to end with when nothing is left: the main program's status.
    pub fn code(&self) -> u8 {
        self.code.unwrap_or(1)
    }
}

/// Whom a signal is passed on to: every child of `me` — the program and the
/// orphans it adopted — in a table of `(pid, parent)`.
pub fn forward_targets(me: libc::pid_t, table: &[(i32, i32)]) -> Vec<i32> {
    table
        .iter()
        .filter(|&&(pid, parent)| parent == me && pid != me)
        .map(|&(pid, _)| pid)
        .collect()
}

/// Every process below `me` in a table of `(pid, parent)`, children first:
/// whom a TERM is passed on to. Since stage 4 of the container design
/// (`crate::epoch`) a launch's program is not in its launcher's cgroup but in
/// its instance's epoch, and a stop of the launcher's scope or service — which
/// TERMed every process in it — reaches the program only through this
/// process: a shell that dies of the TERM before it passed it on would
/// leave its children running (red once in CI, `pw-record` under `sh -c`).
pub fn descendants(me: libc::pid_t, table: &[(i32, i32)]) -> Vec<i32> {
    let mut out: Vec<i32> = Vec::new();
    let mut at = 0;
    let mut parents = vec![me];
    while at < parents.len() {
        let parent = parents[at];
        at += 1;
        for &(pid, of) in table {
            if of == parent && pid != me && !out.contains(&pid) {
                out.push(pid);
                parents.push(pid);
            }
        }
    }
    out
}

/// What `profile-run` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Where the upper layers live. **Empty means the "main" profile**: no
    /// layers are stacked at all and the program works with the real `~/`.
    /// Being able to say "through the VPN, but without a container" is the
    /// point of that case.
    pub profile_dir: PathBuf,
    /// The zone this run belongs to. Accepted and not used: the "who runs
    /// where" registry is kept by `vpn-zone` itself (it is shared by profiles
    /// and by the main environment), and duplicating it here would only give
    /// the two copies a chance to disagree. Part of the CLI contract, so it
    /// stays in the signature.
    pub zone: OsString,
    /// Throwaway container: the directory is removed once the last program
    /// living in it is gone.
    pub ephemeral: bool,
    /// Directory of the launch registry for this container, or empty. Used
    /// only to answer "is anybody else still in here?".
    pub regdir: PathBuf,
    /// `--registered <pid>:<start>`: the launch's own record in that
    /// registry — the launcher's pid and its start time — which is not
    /// "anybody else" ([`others_alive`]). Without it, this process itself.
    pub registered: Option<Registered>,
    /// `--cwd`: the directory the program is to start in — the caller's.
    ///
    /// Needed because `nsenter`, joining another mount namespace, does
    /// `chdir("/")`: the old working directory belongs to the old namespace. A
    /// terminal started into a zone opened in `/` (measured). `nsenter --wd`
    /// cannot do it for a container: the overlay is mounted over `$HOME` HERE,
    /// after `nsenter`, and a chdir made before that would pin the program to
    /// the directory UNDER the layer. So the chdir is made here, after the
    /// mounts. (`docs/GOTCHAS.md` §1)
    pub cwd: Option<PathBuf>,
    /// `--trust DIR`: the container's directory of trusted certificates. Its
    /// presence lays the trust layer down (`crate::trust`).
    pub trust: Option<PathBuf>,
    /// `--nss-home DIR`: the home the program will SEE when that is not
    /// `$HOME` — a named sandbox's home as it lies on disk. Its NSS databases
    /// are the container's by construction.
    pub nss_home: Option<PathBuf>,
    /// `--certutil PATH`, from the manifest.
    pub certutil: Option<PathBuf>,
    /// `--bwrap PATH`, from the manifest: the box certutil works in.
    pub bwrap: Option<PathBuf>,
    /// `--own-x11`: a `/tmp/.X11-unix` of this launch's own, for the X
    /// server `x11-run` starts in it.
    pub own_x11: bool,
    /// `--storage PATH`: the container's storage directory, which the zone
    /// covers — given back at `PATH` from the zone's keep
    /// (`home_layer::KEPT_STORAGE`), in this launch's mount namespace only,
    /// before anything else.
    pub storage: Option<PathBuf>,
    /// `--camera`: the host's cameras let this launch — bound into this
    /// mount namespace's `/dev` from the zone's devtmpfs ([`give_capture`]).
    pub camera: bool,
    /// `--device <path>=<major>:<minor>:<vendor>:<product>`, repeated: a
    /// device its container is given (`crate::devices`), bound into this
    /// mount namespace once it is checked again here ([`give_devices`]).
    pub devices: Vec<crate::devices::Pass>,
    /// `--all-devices`: every device of the host ([`give_all_devices`]).
    pub all_devices: bool,
    /// `--share PATH`, repeated: a path of the real home granted to the
    /// container (`container grant`) — written through the layer, into the
    /// real home. Checked again here, as written and as resolved.
    pub share: Vec<PathBuf>,
    /// `--trust-extra DIR`, repeated: certificate directories declared in Nix,
    /// besides the container's own.
    pub trust_extra: Vec<PathBuf>,
    /// The program and its arguments.
    pub cmd: Vec<OsString>,
}

/// Everything that can be wrong with the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgError {
    /// No `--` separator, so where the command starts is anybody's guess.
    NoSeparator,
    /// Fewer positional arguments than the four this takes.
    MissingArguments,
    /// `--` was there, but nothing followed it.
    EmptyCommand,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeparator => write!(f, "no `--` before the command"),
            Self::MissingArguments => {
                write!(f, "need <profiledir> <zone> <ephemeral 0|1> <regdir>")
            }
            Self::EmptyCommand => write!(f, "nothing to run after `--`"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `[--cwd DIR] [--trust DIR] [--nss-home DIR] [--certutil PATH]
    /// <profiledir> <zone> <ephemeral 0|1> <regdir> -- cmd...`.
    ///
    /// The flags are optional, in any order, and only before the positionals,
    /// so that every older command line still parses the way it did. An empty
    /// value is no value.
    ///
    /// `OsString` and not `String` all the way through: an argument can be a
    /// file name handed over by the launcher through a `%U` field code, and
    /// those are bytes, not necessarily UTF-8. Refusing to start a program
    /// because its argument is not valid Unicode would be a regression against
    /// every other launcher on the system.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or(ArgError::NoSeparator)?;
        let mut positional = &argv[..split];
        let (mut cwd, mut trust, mut nss_home, mut certutil, mut bwrap) =
            (None, None, None, None, None);
        let mut trust_extra = Vec::new();
        let mut share = Vec::new();
        let mut storage = None;
        let mut camera = false;
        let mut own_x11 = false;
        let mut devices = Vec::new();
        let mut all_devices = false;
        let mut registered = None;
        while let Some(flag) = positional.first() {
            if flag == "--registered" {
                // One that does not read is none: this process counts as the
                // launch's own record then, as it did before the flag.
                registered = positional
                    .get(1)
                    .and_then(|v| v.to_str())
                    .and_then(Registered::parse);
                positional = positional.get(2..).unwrap_or(&[]);
                continue;
            }
            if flag == "--device" {
                // One that does not read is not given: nothing more.
                if let Some(pass) = positional
                    .get(1)
                    .and_then(|v| v.to_str())
                    .and_then(crate::devices::Pass::parse)
                {
                    devices.push(pass);
                }
                positional = positional.get(2..).unwrap_or(&[]);
                continue;
            }
            if flag == "--camera" {
                camera = true;
                positional = &positional[1..];
                continue;
            }
            if flag == "--all-devices" {
                all_devices = true;
                positional = &positional[1..];
                continue;
            }
            if flag == "--own-x11" {
                own_x11 = true;
                positional = &positional[1..];
                continue;
            }
            if flag == "--storage" {
                storage = positional
                    .get(1)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from);
                positional = positional.get(2..).unwrap_or(&[]);
                continue;
            }
            if flag == "--trust-extra" || flag == "--share" {
                if let Some(value) = positional.get(1).filter(|v| !v.is_empty()) {
                    if flag == "--share" {
                        share.push(PathBuf::from(value));
                    } else {
                        trust_extra.push(PathBuf::from(value));
                    }
                }
                positional = positional.get(2..).unwrap_or(&[]);
                continue;
            }
            let slot = match flag.as_bytes() {
                b"--cwd" => &mut cwd,
                b"--trust" => &mut trust,
                b"--nss-home" => &mut nss_home,
                b"--certutil" => &mut certutil,
                b"--bwrap" => &mut bwrap,
                _ => break,
            };
            *slot = positional
                .get(1)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from);
            positional = positional.get(2..).unwrap_or(&[]);
        }
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err(ArgError::EmptyCommand);
        }
        if positional.len() < 2 {
            return Err(ArgError::MissingArguments);
        }
        Ok(Self {
            profile_dir: PathBuf::from(positional[0].clone()),
            zone: positional[1].clone(),
            // Anything other than "1" means "keep the container", which is the
            // safe way round: a typo must not delete somebody's data.
            ephemeral: positional.get(2).is_some_and(|e| e == "1"),
            regdir: PathBuf::from(positional.get(3).cloned().unwrap_or_default()),
            registered,
            cwd,
            trust,
            nss_home,
            certutil,
            bwrap,
            own_x11,
            storage,
            camera,
            devices,
            all_devices,
            share,
            trust_extra,
            cmd,
        })
    }
}

/// Directory name of the upper/work pair for one XDG subdirectory:
/// `.local/share` → `.local_share`, so that the whole thing stays one level
/// deep inside the profile.
pub fn slot_name(sub: &str) -> String {
    sub.replace('/', "_")
}

/// `$HOME`, or the passwd entry if the environment does not say — the same
/// order Python's `os.path.expanduser("~")` used.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Some(PathBuf::from(home));
    }
    // SAFETY: getpwuid returns a pointer into a static buffer; it is read
    // before anything else can call into the passwd machinery again.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return None;
        }
        let bytes = CStr::from_ptr((*pw).pw_dir).to_bytes().to_vec();
        Some(PathBuf::from(OsString::from_vec(bytes)))
    }
}

/// Give the container's storage directory back at `path` (below one of the
/// storage directories the zone covers, `home_layer::STORAGE`), from the
/// zone's keep. Outside a zone there is no keep, and nothing covered: the
/// path is the real one already.
fn give_storage_back(path: &Path) -> Result<(), String> {
    let home = home_dir().ok_or("no $HOME")?;
    let kept = crate::home_layer::kept_storage_of(&home, path)
        .ok_or_else(|| format!("{} is no container's storage", path.display()))?;
    if !home.join(crate::home_layer::KEPT_STORAGE).is_dir() {
        return Ok(());
    }
    if !fs::symlink_metadata(&kept).is_ok_and(|m| m.is_dir()) {
        // A zone brought up by a build that kept no such storage (the
        // throwaway containers', before 2026-09-27): it shows every launch
        // the whole root, and this one is not started into it.
        return Err(format!(
            "the zone keeps no {} — it was brought up by an older cellward: restart the zone",
            kept.display()
        ));
    }
    if fs::symlink_metadata(path).is_err() {
        // Two launches of one container at once both find it missing and
        // both make it (the VM check of 2026-09-28 saw the second one not
        // started): made by the other one is as good — a directory, not
        // whatever else might be there.
        if let Err(e) = fs::create_dir(path) {
            let made = e.kind() == std::io::ErrorKind::AlreadyExists
                && fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
            if !made {
                return Err(format!("cannot make {}: {e}", path.display()));
            }
        }
    }
    crate::sys::mount(kept.as_os_str(), path, "", libc::MS_BIND | libc::MS_REC, "")
        .map_err(|e| format!("cannot give {} back: {e}", path.display()))
}

/// Put the whole home under the profile's layer (`crate::home_layer`): the
/// old slots moved into it first, then the overlay, then back over it what
/// was mounted below the home (the zone's covers keep their flags, anything
/// else is read-only unless granted), the granted paths, and the other
/// containers' storage covered. Returns the directories that are the
/// container's own — the home, for the trust layer's NSS databases.
///
/// Every step but a grant is fatal, and the program is not started: a layer
/// container that ran with the real home, or with the zone's covers gone
/// under its layer (the project's state, every zone's key in it), would be a
/// hole nobody sees. A grant that cannot be given back leaves that path in
/// the layer, and says so.
fn mount_profile(profile_dir: &Path, shares: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    use crate::home_layer::{give_back, keeps_flags, layer_dirs, relative_share, STORAGE};
    let home = home_dir().ok_or("no $HOME")?;
    crate::home_layer::migrate_slots(profile_dir);
    let (upper, work) = layer_dirs(profile_dir);
    for dir in [&upper, &work] {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("cannot prepare {}: {e}", dir.display()))?;
    }
    let options = crate::home_layer::overlay_options(&home, &upper, &work).ok_or_else(|| {
        format!(
            "the home's path {} has a comma, a colon or a backslash — overlayfs cannot be told it",
            home.display()
        )
    })?;
    // The mounts below the home by the home's real path: mountinfo names
    // mount points resolved, and a home reached through a link (`/home` →
    // `/var/home`) would find none of them — the zone's covers gone under
    // the layer (review 2026-09-27). Fatal if it cannot be resolved.
    let real_home =
        fs::canonicalize(&home).map_err(|e| format!("cannot resolve {}: {e}", home.display()))?;
    let below = crate::home_layer::submounts(
        &fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| format!("cannot read the mounts below the home: {e}"))?,
        &real_home,
    );
    // The grants, checked again: the file is the host's, but a link along a
    // path may have changed since it was written. As written and as
    // resolved, and relative to the home they resolve in.
    let mut granted: Vec<PathBuf> = Vec::new();
    for share in shares {
        let resolved = fs::canonicalize(share).unwrap_or_else(|_| share.clone());
        let why = crate::container::forbidden_path(&home, share)
            .or_else(|| crate::container::forbidden_path(&real_home, &resolved));
        match (why, relative_share(&real_home, &resolved)) {
            (Some(why), _) => eprintln!("profile: {} is not given: {why}", share.display()),
            (None, Some(rel)) => granted.push(rel),
            // Outside the home: not under the layer, the real one anyway.
            (None, None) => {}
        }
    }
    let real =
        crate::sys::open_dir(&home).map_err(|e| format!("cannot open {}: {e}", home.display()))?;
    crate::sys::mount(
        OsStr::new("overlay"),
        &home,
        "overlay",
        libc::MS_NOSUID | libc::MS_NODEV,
        &options,
    )
    .map_err(|e| format!("overlayfs refused the home: {e}"))?;
    for rel in &below {
        // Not there to give back: the layer would show what lies under the
        // mount instead — under a zone's cover, the project's state. And a
        // path given nothing would make the layer itself read-only below.
        if !give_back(&real, &home, rel)? {
            return Err(format!(
                "{} was mounted below the home and cannot be given back over the layer",
                rel.display()
            ));
        }
        if !keeps_flags(rel, &granted) {
            crate::sys::read_only_tree(&home.join(rel))
                .map_err(|e| format!("cannot make {} read-only: {e}", rel.display()))?;
        }
    }
    for rel in &granted {
        if let Err(e) = give_back(&real, &home, rel) {
            eprintln!("profile: {} stays in the layer: {e}", rel.display());
        }
    }
    for storage in STORAGE {
        let dir = home.join(storage);
        if !dir.is_dir() {
            continue;
        }
        crate::sys::mount(
            OsStr::new("tmpfs"),
            &dir,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0700,size=16k",
        )
        .map_err(|e| format!("cannot cover {}: {e}", dir.display()))?;
    }
    Ok(vec![home])
}

/// Where to try to start the program, in order: the caller's directory, the
/// home directory, and `/`, which always exists.
///
/// A fallback and not a failure, because the caller's directory may well not
/// exist in here: the zone's mount tree is a private copy taken when the zone
/// came up, and a drive mounted since (or a directory removed since) is simply
/// not there. A program that does not start because of where it was started
/// FROM would be a worse bug than the one this fixes.
pub fn start_dirs(cwd: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [cwd, home]
        .into_iter()
        .flatten()
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect();
    dirs.push(PathBuf::from("/"));
    dirs
}

/// `chdir` into the first of [`start_dirs`] that works.
fn enter_start_dir(cwd: Option<&Path>) {
    let home = home_dir();
    for dir in start_dirs(cwd, home.as_deref()) {
        if std::env::set_current_dir(&dir).is_ok() {
            if cwd.is_some_and(|wanted| wanted != dir) {
                eprintln!(
                    "profile: {} is not reachable here — starting in {}",
                    cwd.unwrap_or(Path::new("")).display(),
                    dir.display()
                );
            }
            return;
        }
    }
}

/// The supplementary groups: the primary one alone.
fn own_group_only() -> io::Result<()> {
    // SAFETY: getgid(2) takes no arguments and cannot fail.
    let gid = unsafe { libc::getgid() };
    // SAFETY: a list of one gid and its length.
    if unsafe { libc::setgroups(1, &gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Drop the ambient capability set before handing control to the program —
/// and the inheritable one: `nsenter --keep-caps` fills both, and a binary
/// with inheritable file capabilities would get them back in the zone.
///
/// Errors are ignored deliberately: on a kernel without ambient capabilities
/// (< 4.3) `prctl` answers EINVAL, and there is nothing to clear there anyway.
fn clear_ambient_capabilities() {
    // SAFETY: prctl with these two constants takes no pointers.
    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    }
    clear_inheritable_capabilities();
}

/// `capget`/`capset`'s header and one of its two data words
/// (`_LINUX_CAPABILITY_VERSION_3`).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The effective set made the permitted one again.
fn raise_effective_capabilities() {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget/capset with a version 3 header and two data words, as
    // the kernel's ABI has them.
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) != 0 {
            return;
        }
        for word in &mut data {
            word.effective = word.permitted;
        }
        libc::syscall(libc::SYS_capset, &mut header, data.as_ptr());
    }
}

/// The inheritable set emptied; the effective and permitted ones left as
/// they are (a throwaway container is cleaned up after its program).
fn clear_inheritable_capabilities() {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget/capset with a version 3 header and two data words, as
    // the kernel's ABI has them.
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) != 0 {
            return;
        }
        for word in &mut data {
            word.inheritable = 0;
        }
        libc::syscall(libc::SYS_capset, &mut header, data.as_ptr());
    }
}

/// Is there a live process with this pid? The real liveness test, the one
/// [`others_alive`] is given in production.
pub fn proc_is_alive(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).is_dir()
}

/// A launch's own record in the registry: the pid `vpn-zone run` wrote
/// there — its own, which survives its `exec` — and when that process
/// started (`crate::sys::start_time`). The two together name the one
/// process; the pid alone names whoever has the number now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    pub pid: i32,
    pub start: u64,
}

impl Registered {
    /// `<pid>:<start>`, as `profile-run --registered` takes it. Anything
    /// else is none.
    pub fn parse(text: &str) -> Option<Self> {
        let (pid, start) = text.split_once(':')?;
        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !all_digits(pid) || !all_digits(start) {
            return None;
        }
        let pid = pid.parse::<i32>().ok().filter(|p| *p > 0)?;
        Some(Self {
            pid,
            start: start.parse().ok()?,
        })
    }

    /// The flag's value: what [`Registered::parse`] reads back.
    pub fn arg(&self) -> String {
        format!("{}:{}", self.pid, self.start)
    }

    /// This process, as the registry would have it when its pid is the
    /// record's: the launch with nothing between `vpn-zone run` and here
    /// (the fallback without `--registered`). A start time that cannot be
    /// read matches no process — the container is kept, the safe way round.
    pub fn myself() -> Self {
        let pid = std::process::id() as i32;
        Self {
            pid,
            start: crate::sys::start_time(pid).unwrap_or(u64::MAX),
        }
    }
}

/// Is anybody else still living in this container?
///
/// The registry is the one `vpn-zone run` writes: one file per program, one
/// line per launch, `pid zone selector`. Liveness and the start time of a
/// pid are parameters so that the tests can answer them without spawning
/// processes.
///
/// **Only the launch's own record is not "anybody else"** — `myself`, by
/// its pid AND its start time (review 2026-09-27, J9). It used to be this
/// process's pid, and with a compositor there is `wl-sandbox` between the
/// launcher and here: the record names the launcher, which became
/// `wl-sandbox` and forked, so this process's pid was never in the
/// registry, the launcher was alive until after this check, and a
/// throwaway container was never erased at its program's exit (`gc` swept
/// it later). A record with the same pid and another start time is another
/// launch that got the number since: a tenant like any other.
pub fn others_alive<F, S>(regdir: &Path, myself: Registered, is_alive: F, start_of: S) -> bool
where
    F: Fn(i32) -> bool,
    S: Fn(i32) -> Option<u64>,
{
    if regdir.as_os_str().is_empty() || !regdir.is_dir() {
        return false;
    }
    let Ok(entries) = fs::read_dir(regdir) else {
        return false;
    };
    for entry in entries.flatten() {
        // The lock file and any directory read as an error — skip, as the
        // Python version did.
        let Ok(text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in text.lines() {
            let field = line.split(' ').next().unwrap_or("");
            if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = field.parse::<i32>() else {
                continue;
            };
            if pid == myself.pid && start_of(pid) == Some(myself.start) {
                continue;
            }
            if is_alive(pid) {
                return true;
            }
        }
    }
    false
}

/// `execvp`, which only ever returns when the program could not be started.
///
/// Public because [`crate::wl_sandbox`] starts programs the same way; the
/// NUL-byte handling and the `OsString` argv are not worth having twice.
pub fn exec_command(cmd: &[OsString]) -> io::Error {
    let mut owned = Vec::with_capacity(cmd.len());
    for arg in cmd {
        match CString::new(arg.as_bytes()) {
            Ok(c) => owned.push(c),
            Err(_) => {
                return io::Error::new(io::ErrorKind::InvalidInput, "argument contains a NUL byte")
            }
        }
    }
    let mut argv: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    // SAFETY: argv is NULL-terminated and every pointer in it is a valid C
    // string owned by `owned`, which outlives the call.
    unsafe { libc::execvp(argv[0], argv.as_ptr()) };
    io::Error::last_os_error()
}

/// Exit code to report for a child that has been waited for.
///
/// A child killed by a signal gives `128 + signal`, the shell convention
/// (`vpn-zone run` is started from shells and `.desktop` files, so that is the
/// number a caller will recognise). Anything else — a stopped child that
/// somehow got reported — is a plain failure.
///
/// Public because [`crate::wl_sandbox`] waits for a child too, and both layers
/// of one launch should report the same number.
pub fn exit_code_of(status: libc::c_int) -> u8 {
    if libc::WIFEXITED(status) {
        // WEXITSTATUS is already 0..=255.
        libc::WEXITSTATUS(status) as u8
    } else if libc::WIFSIGNALED(status) {
        128u8.saturating_add(libc::WTERMSIG(status) as u8)
    } else {
        1
    }
}

/// `rm -rf`, errors ignored — the caller has nothing useful to do about them
/// and the next `vpn-zone gc` sweeps up whatever is left.
fn remove_tree(path: &Path) {
    if path.as_os_str().is_empty() {
        return;
    }
    let _ = crate::sys::remove_tree(path);
}

/// For messages only: an argument may be any byte string, and a message is
/// worth more than an exact round-trip.
fn lossy(name: &OsStr) -> std::borrow::Cow<'_, str> {
    name.to_string_lossy()
}

/// Mount the profile, drop the capabilities, run the program.
///
/// Returns only when the program could not be started or when this was a
/// throwaway container (which has to be outlived and cleaned up).
/// The network namespace `vpn-zone run` checked before it handed the launch to
/// `nsenter` (`net:[…]`). Set, it must be the one this process is in.
pub const ENV_EXPECT_NETNS: &str = "VPN_ZONE_EXPECT_NETNS";

/// Let this launch reach the host's cameras: every capture node of the
/// devtmpfs the zone keeps out of its programs' reach (`zone::DEVTMPFS`),
/// and the cameras' links (`/dev/v4l`), bound into this launch's `/dev` — in
/// its own mount namespace, a slave copy of the zone's (`launch::
/// entry_argv`), and nowhere else. A camera plugged in later is not here:
/// restart the program. Never fatal: a camera not bound is one the program
/// does not get.
fn give_capture() -> Result<(), String> {
    let host = Path::new(crate::zone::DEVTMPFS);
    let v4l = host.join("v4l");
    if v4l.is_dir() {
        let to = Path::new("/dev/v4l");
        let made = if to.is_dir() {
            Ok(())
        } else {
            fs::create_dir(to).and_then(|()| std::os::unix::fs::lchown(to, Some(0), Some(0)))
        };
        made.and_then(|()| crate::sys::mount(v4l.as_os_str(), to, "", libc::MS_BIND, ""))
            .map_err(|e| format!("cannot give /dev/v4l: {e}"))?;
    }
    for entry in fs::read_dir(host)
        .map_err(|e| format!("cannot read {}: {e}", host.display()))?
        .flatten()
    {
        let name = entry.file_name();
        if crate::zone::is_capture_node(&name.to_string_lossy()) {
            let to = Path::new("/dev").join(&name);
            crate::zone::give_node(&entry.path(), &to, &|_, _| true)
                .map_err(|e| format!("cannot give {}: {e}", to.display()))?;
        }
    }
    Ok(())
}

/// Give this launch the devices its container is given (`docs/PERMISSIONS.md`
/// §11.12): each node bound from the devtmpfs the zone keeps out of its
/// programs' reach (`zone::DEVTMPFS`) into this launch's `/dev`, in its own
/// mount namespace. Each is checked here once more by its number and udev's
/// word on it (`devices::Pass::still`): the number may have gone to another
/// device since the launch listed them — then it is not given. When the
/// device goes, the zone unlinks the stand-in under the bind, and the bind
/// goes with it. What cannot be given is said, not fatal: nothing is given
/// that is not the one.
fn give_devices(passes: &[crate::devices::Pass]) {
    let udev = Path::new("/run/udev/data");
    let host = Path::new(crate::zone::DEVTMPFS);
    let unwatched = crate::zone::unwatched();
    for pass in passes {
        let Ok(rel) = pass.path.strip_prefix("/dev") else {
            continue;
        };
        let from = host.join(rel);
        // Where the zone's watch does not look, nothing is given: a device
        // gone there would stay bound.
        if unwatched.iter().any(|dir| from.starts_with(dir)) {
            eprintln!(
                "profile-run: {} not given — the zone does not watch where it is",
                pass.path.display()
            );
            continue;
        }
        let checked = |major, minor| pass.still(udev, major, minor);
        match crate::zone::give_node(&from, &pass.path, &checked) {
            Ok(true) => {}
            Ok(false) => eprintln!(
                "profile-run: {} is another device now — not given",
                pass.path.display()
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("profile-run: {} not given: {e}", pass.path.display()),
        }
    }
}

/// Give this launch every device of the host — «без изоляции» (2e of
/// `docs/PERMISSIONS.md` §11.15), or a container given `all`: the devtmpfs
/// the zone keeps out of its programs' reach (`zone::DEVTMPFS`) bound over
/// this launch's `/dev`, whole, in its own mount namespace. A device plugged
/// in later is there and one unplugged goes: the devtmpfs is the kernel's
/// own. What the zone's `/dev` has of its own — its terminals, its shared
/// memory and queues — is taken along first and put back over it: the
/// host's terminals stay out of reach even so (the devtmpfs's `pts` is an
/// empty directory).
fn give_all_devices() -> Result<(), String> {
    let dev = Path::new("/dev");
    let mut kept = Vec::new();
    for name in ["pts", "shm", "mqueue", "hugepages"] {
        let path = dev.join(name);
        if path.is_dir() {
            let tree = crate::sys::clone_tree(&path)
                .map_err(|e| format!("cannot keep {}: {e}", path.display()))?;
            kept.push((path, tree));
        }
    }
    crate::sys::mount(
        std::ffi::OsStr::new(crate::zone::DEVTMPFS),
        dev,
        "",
        libc::MS_BIND,
        "",
    )
    .map_err(|e| format!("cannot bind the host's devices over /dev: {e}"))?;
    for (path, tree) in kept {
        if path.is_dir() {
            crate::sys::attach_tree(&tree, &path)
                .map_err(|e| format!("cannot put {} back: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// While it lives, what this process makes is the zone root's from the
/// start (`setfsuid`/`setfsgid` 0 — `profile-run` has the zone's
/// capabilities): made as the user, a directory of the zone's `/dev` would
/// be the programs' to change until it was handed over.
struct AsZoneRoot {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl AsZoneRoot {
    /// `None` where it could not be.
    fn enter() -> Option<Self> {
        // SAFETY: get*id(2) cannot fail; setfs*id(2) take ids and return the
        // previous ones — asked with -1, the current one, unchanged.
        unsafe {
            let (uid, gid) = (libc::getuid(), libc::getgid());
            libc::setfsgid(0);
            libc::setfsuid(0);
            let now = (libc::setfsuid(u32::MAX), libc::setfsgid(u32::MAX));
            let guard = Self { uid, gid };
            (now == (0, 0)).then_some(guard)
        }
    }
}

impl Drop for AsZoneRoot {
    fn drop(&mut self) {
        // SAFETY: back to the ids this process has.
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
        }
        // The kernel takes the file capabilities out of the effective set
        // when the fsuid goes from 0 to another (capabilities(7)); the
        // layer is still to be mounted, with them.
        raise_effective_capabilities();
    }
}

/// The launch's status pipe ([`ENV_STATUS_FD`]): taken out of the
/// environment, believed only as an open pipe, and closed on every `exec`
/// from here on — nothing this process starts has it. `None`: not given.
fn take_status_fd() -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let value = std::env::var_os(ENV_STATUS_FD)?;
    std::env::remove_var(ENV_STATUS_FD);
    let fd: libc::c_int = value.to_str()?.parse().ok().filter(|&fd| fd > 2)?;
    // SAFETY: fstat of a number that may be no descriptor at all: it fails
    // then, into a zeroed struct of our own.
    let is_pipe = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO
    };
    if !is_pipe {
        return None;
    }
    // SAFETY: fcntl on that descriptor, open as just seen.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: an open descriptor this process was handed, owned by nobody
    // else here.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Every capability dropped: the effective, permitted and inheritable sets
/// emptied (the ambient one is already).
fn drop_all_capabilities() {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: capset with a version 3 header and two zeroed data words.
    unsafe {
        libc::syscall(libc::SYS_capset, &mut header, data.as_ptr());
    }
}

/// The standard descriptors pointed at `/dev/null`: a subreaper that
/// outlives its main program must not hold a pipe it was started with open
/// — `$(cellward run …)` would wait for its daemons.
fn quiet_stdio() {
    use std::os::fd::AsRawFd;
    let Ok(null) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    else {
        return;
    };
    for fd in 0..3 {
        // SAFETY: dup2 of a descriptor we hold onto a standard one of ours.
        unsafe { libc::dup2(null.as_raw_fd(), fd) };
    }
}

/// Every process of this pid namespace with its parent, from `/proc` (the
/// namespace's own: this process is a member of it).
fn process_table() -> Vec<(i32, i32)> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| Some((pid, crate::sys::parent_of(pid)?)))
        .collect()
}

/// The launch's subreaper, in a container's instance (the module's words):
/// the program forked with the signal mask it would have had, then every
/// child reaped — the program and every orphan it leaves, adopted
/// (`PR_SET_CHILD_SUBREAPER`) — and every signal of [`FORWARDED`] passed on
/// to all of them. The main program's status is said to the waiter at once
/// (`status`); this process ends when nothing it started is left, with that
/// status. Its capabilities are gone before the fork — it holds nothing the
/// program lacks —, it is not dumpable (the program's to trace otherwise),
/// and its waiter's end is a TERM to it (`PR_SET_PDEATHSIG`) until the main
/// program's end is said: the launch's waiter killed ends the launch.
fn supervise(cmd: &[OsString], mut status: Option<std::os::fd::OwnedFd>) -> u8 {
    use std::io::Write;
    drop_all_capabilities();
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    // SAFETY: sigemptyset and sigaddset fill a sigset_t of our own.
    let waited = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in FORWARDED {
            libc::sigaddset(&mut set, sig);
        }
        libc::sigaddset(&mut set, libc::SIGCHLD);
        set
    };
    let before = match crate::init::block(&waited) {
        Ok(mask) => mask,
        Err(e) => {
            eprintln!("profile-run: cannot block the launch's signals ({e}) — not starting");
            return EXIT_NOT_STARTED;
        }
    };
    // SAFETY: single-threaded, so the child may allocate before its exec.
    let main = unsafe { libc::fork() };
    if main < 0 {
        eprintln!("cannot fork: {}", io::Error::last_os_error());
        return EXIT_NOT_STARTED;
    }
    if main == 0 {
        crate::init::set_mask(&before);
        let e = exec_command(cmd);
        eprintln!("cannot start {}: {e}", lossy(&cmd[0]));
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(EXIT_NOT_STARTED)) };
    }
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
    }
    quiet_stdio();
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let me = unsafe { libc::getpid() };
    let mut launch = Subreaper::new(main);
    loop {
        // SAFETY: an all-zero siginfo_t is a valid one to be filled.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: a sigset_t and a siginfo_t of our own.
        let sig = unsafe { libc::sigwaitinfo(&waited, &mut info) };
        if sig < 0 {
            continue;
        }
        if sig != libc::SIGCHLD {
            // A TERM ends the launch: the whole tree below, as a stop of the
            // launcher's scope did (`descendants`); the others go to the
            // children, which pass them on as they see fit.
            let table = process_table();
            let targets = if sig == libc::SIGTERM {
                descendants(me, &table)
            } else {
                forward_targets(me, &table)
            };
            for pid in targets {
                // SAFETY: kill(2) takes no pointers; a process of this
                // launch's tree in this pid namespace, read just now.
                unsafe { libc::kill(pid, sig) };
            }
            continue;
        }
        loop {
            let mut raw: libc::c_int = 0;
            // SAFETY: `raw` is a valid pointer for the duration of the call.
            let dead = unsafe { libc::waitpid(-1, &mut raw, libc::WNOHANG) };
            if dead > 0 {
                if let Some(code) = launch.reaped(dead, exit_code_of(raw)) {
                    // Said, and the waiter's end is no stop of ours any more.
                    // SAFETY: prctl with these arguments takes no pointers.
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0, 0, 0, 0) };
                    if let Some(pipe) = status.take() {
                        let _ = fs::File::from(pipe).write_all(&status_word(code));
                    }
                }
                continue;
            }
            if dead < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                return launch.code();
            }
            break;
        }
    }
}

pub fn run(args: Args) -> u8 {
    // The launch's status pipe first, before anything is started: nothing
    // else has it.
    let status = take_status_fd();
    // The instance's pid namespace (stage 3): the one `container-enter`
    // made this launch's, or it does not start — as its network below.
    let in_own_pids = match std::env::var_os(ENV_EXPECT_PIDNS) {
        Some(expected) => {
            std::env::remove_var(ENV_EXPECT_PIDNS);
            let here = fs::read_link("/proc/self/ns/pid").ok();
            if here.as_deref().map(Path::as_os_str) != Some(expected.as_os_str()) {
                eprintln!(
                    "profile-run: in the pid namespace {} instead of the instance's {} — not \
                     starting",
                    here.map_or("?".to_owned(), |p| p.display().to_string()),
                    expected.to_string_lossy()
                );
                return EXIT_NOT_STARTED;
            }
            true
        }
        None => false,
    };
    let into_zone = std::env::var_os(ENV_EXPECT_NETNS).is_some();
    // The zone entered is the zone checked: `nsenter` finds it by a number,
    // later, in a child of wl-sandbox, and a number can change hands in
    // between (review 2026-09-25). Here, inside, the kernel says which
    // network this is; anything else than what was checked does not start.
    if let Some(expected) = std::env::var_os(ENV_EXPECT_NETNS) {
        std::env::remove_var(ENV_EXPECT_NETNS);
        let here = fs::read_link("/proc/self/ns/net").ok();
        if here.as_deref().map(Path::as_os_str) != Some(expected.as_os_str()) {
            eprintln!(
                "profile-run: entered {} instead of the zone's {} — not starting",
                here.map_or("?".to_owned(), |p| p.display().to_string()),
                expected.to_string_lossy()
            );
            return EXIT_NOT_STARTED;
        }
        // In a zone, the user's own group and no other (review 2026-09-25,
        // third round). The session's groups open doors a zone must not
        // have: libvirt's and docker's daemons start things in the host's
        // network for their members, `input` reads every key pressed. Only
        // here can they go — in the zone's user namespace, with the
        // capabilities `nsenter --keep-caps` carried over — and a launch
        // that cannot shed them does not start.
        if let Err(e) = own_group_only() {
            eprintln!("profile-run: cannot shed the session's groups ({e}) — not starting");
            return EXIT_NOT_STARTED;
        }
    }
    // The container's own storage first: the zone covers all of it, and the
    // layer and the sandbox below need this one directory where it was.
    if let Some(path) = &args.storage {
        if let Err(e) = give_storage_back(path) {
            eprintln!("profile-run: {e} — the program is not started");
            return EXIT_NOT_STARTED;
        }
    }
    // The X server's sockets of this launch's own (`crate::x11`): the zone's
    // `/tmp/.X11-unix` is every program of the zone's, and an X server shows
    // whoever reaches it everything its clients show and type. Fatal: that
    // server would be in all their reach.
    if args.own_x11 {
        if let Err(e) = crate::sys::mount(
            OsStr::new("tmpfs"),
            Path::new(crate::x11::X11_DIR),
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=1777,size=64k",
        ) {
            eprintln!(
                "profile-run: no {} of the launch's own ({e}) — the program is not started",
                crate::x11::X11_DIR
            );
            return EXIT_NOT_STARTED;
        }
    }
    // The cameras, where this launch is let them, and the devices its
    // container is given: never fatal — what is not given, the program
    // does not get. Every device, where it is given all of them.
    if args.all_devices {
        if let Err(e) = give_all_devices() {
            eprintln!("profile-run: the host's devices are not given: {e}");
        }
    } else if args.camera || !args.devices.is_empty() {
        match AsZoneRoot::enter() {
            Some(_root) => {
                if args.camera {
                    if let Err(e) = give_capture() {
                        eprintln!("profile-run: the cameras are not given: {e}");
                    }
                }
                give_devices(&args.devices);
            }
            None => eprintln!("profile-run: cannot act as the zone's root — no device given"),
        }
    }
    let mounted = if args.profile_dir.as_os_str().is_empty() {
        Vec::new()
    } else {
        match mount_profile(&args.profile_dir, &args.share) {
            Ok(mounted) => mounted,
            Err(e) => {
                eprintln!("profile-run: no layer ({e}) — the program is not started");
                return EXIT_NOT_STARTED;
            }
        }
    };

    // The trust layer: after the home layer (its NSS databases live there) and
    // before anything that starts the program. (`docs/CERTIFICATES.md`)
    if let Some(dir) = &args.trust {
        let home = args.nss_home.clone().or_else(home_dir).unwrap_or_default();
        // What is provably the container's own: a named sandbox's home, or the
        // home under this launch's layer. Nothing else.
        let private = match &args.nss_home {
            Some(sandbox_home) => vec![sandbox_home.clone()],
            None => mounted,
        };
        let certutil = args
            .certutil
            .clone()
            .unwrap_or_else(|| PathBuf::from("certutil"));
        let bwrap = args.bwrap.clone().unwrap_or_else(|| PathBuf::from("bwrap"));
        let layer = crate::trust::Layer {
            dir,
            certutil: &certutil,
            bwrap: &bwrap,
            home: &home,
            private: &private,
            extra: &args.trust_extra,
        };
        match crate::trust::apply(&layer) {
            Ok(warnings) => {
                for warning in warnings {
                    eprintln!("trust: {warning}");
                }
            }
            Err(e) => {
                // Fail closed: a program the user expects to trust the
                // container's roots and that silently does not is a broken
                // launch, and "run without the layer" must not be a path
                // anyone takes by accident.
                eprintln!("trust: {e} — the program is not started");
                return EXIT_NOT_STARTED;
            }
        }
    }
    // After the mounts and never before them: a directory entered earlier
    // would be the one UNDER the overlay.
    if args.cwd.is_some() {
        enter_start_dir(args.cwd.as_deref());
    }

    // Signals to its own and nobody else's (docs/THREAT-MODEL.md X5): `kill`
    // checks the user and not the namespace, so a program of the zone could
    // signal every process of the user's on the host — kill the compositor,
    // the session. A Landlock domain of this launch's own confines its
    // signals to itself and what it starts (LANDLOCK_SCOPE_SIGNAL, Linux
    // 6.12); a program of another launch, in the same zone too, is outside it,
    // and signals into it from outside (`cellward kill`, the supervisor) are
    // not its business. Put in while the zone's capabilities are still held:
    // they stand in for no_new_privs, which would change what the program
    // may exec. A kernel without it is said, and the launch goes on — this
    // is a denial of service closed, not a leak.
    if into_zone {
        use std::os::fd::AsRawFd;
        match crate::sys::signal_scope() {
            Some(scope) => {
                if let Err(e) = crate::sys::restrict_self(scope.as_raw_fd()) {
                    eprintln!(
                        "profile-run: cannot keep the program's signals to its own ({e}) — it \
                         can signal the host's processes of the user"
                    );
                }
            }
            None => eprintln!(
                "profile-run: this kernel cannot keep a program's signals to its own \
                 (Landlock scopes, Linux 6.12) — it can signal the host's processes of the user"
            ),
        }
        // The network namespace's socket families and no other
        // (`seccomp::ZONE_SOCKET_FAMILIES`): AF_VSOCK is no namespace's, and a
        // program of the zone reached the host's vsock listeners around the
        // tunnel. Fatal when it cannot be put in: that is a way out.
        if let Err(e) = crate::seccomp::Filter::zone_sockets().and_then(|f| f.load()) {
            eprintln!(
                "profile-run: cannot keep the program to its network's socket families ({e}) \
                 — not starting"
            );
            return EXIT_NOT_STARTED;
        }
    }

    // Nothing below this line needs privileges.
    clear_ambient_capabilities();

    // In an instance's own pid namespace: the launch's subreaper, not the
    // program (the module's words). A throwaway's layer goes with its
    // instance there (`zone::keep`): never one of those.
    if in_own_pids && !args.ephemeral {
        return supervise(&args.cmd, status);
    }
    drop(status);

    if !args.ephemeral {
        let e = exec_command(&args.cmd);
        eprintln!("cannot start {}: {e}", lossy(&args.cmd[0]));
        return EXIT_NOT_STARTED;
    }

    // --- THROWAWAY CONTAINER ---
    // `exec` is not an option here: somebody has to outlive the program and
    // take the directory away afterwards, so it is started as a child instead.
    // The mount points need no cleaning — the mount namespace dies with its
    // last process.
    //
    // Caveat: a program that daemonises itself and lets its first process exit
    // will have the directory pulled out from under it, because the wait ends
    // too early. Browsers and Electron applications do not behave that way (in
    // their own profile they stay in the foreground), but it is worth knowing.
    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it execs.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let e = exec_command(&args.cmd);
        eprintln!("cannot start {}: {e}", lossy(&args.cmd[0]));
        // _exit, not exit: the parent's atexit handlers and buffers are not
        // ours to run twice.
        unsafe { libc::_exit(EXIT_NOT_STARTED as libc::c_int) };
    }
    if pid < 0 {
        eprintln!("cannot fork: {}", io::Error::last_os_error());
        return EXIT_NOT_STARTED;
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }

    // The layer is erased for the LAST tenant only. Several programs can be
    // put into one throwaway container (`--tmp-profile --join`), and removing
    // it when the first one exits would pull the filesystem out from under the
    // others. The count comes from the shared launch registry; this launch's
    // own record is excluded — the one `--registered` names (the launcher,
    // `wl-sandbox` by now, still alive above us), or, from a launcher that
    // did not say, our own pid, which survived the `exec` into this binary
    // when nothing forked in between (J9, 2026-09-27).
    let running = args.regdir.parent().unwrap_or(Path::new(""));
    let myself = args.registered.unwrap_or_else(Registered::myself);
    if others_alive(
        &args.regdir,
        myself,
        |pid| crate::registry::alive(running, pid),
        crate::sys::start_time,
    ) {
        let name = args
            .profile_dir
            .file_name()
            .unwrap_or(args.profile_dir.as_os_str());
        println!(
            "throwaway container {} kept: programs are still running in it",
            lossy(name)
        );
    } else {
        remove_tree(&args.profile_dir);
        if let Some(path) = &args.storage {
            take_storage_back(path);
        }
        remove_tree(&args.regdir);
    }
    exit_code_of(status)
}

/// A throwaway container's storage, given back into a zone
/// ([`give_storage_back`]), is a mount point here: its contents went with
/// the layer, and the real directory, in the zone's keep, goes now. The
/// empty one it was mounted on in the zone's cover stays, as a rule: the
/// first mount of it is under the layer, out of reach, and keeps it busy.
/// Outside a zone nothing was mounted, and the directory went already.
fn take_storage_back(path: &Path) {
    let Some(home) = home_dir() else {
        return;
    };
    let Some(kept) = crate::home_layer::kept_storage_of(&home, path) else {
        return;
    };
    if !home.join(crate::home_layer::KEPT_STORAGE).is_dir() {
        return;
    }
    let Ok(target) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: a NUL-terminated path that outlives the call.
    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
    let _ = fs::remove_dir(path);
    let _ = fs::remove_dir(&kept);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The main program's end is said once; an orphan's end is not the
    /// launch's; the subreaper ends with the main program's status.
    #[test]
    fn the_subreaper_says_the_main_programs_end_once() {
        let mut launch = Subreaper::new(5);
        assert_eq!(launch.reaped(9, 0), None);
        assert_eq!(launch.reaped(5, 42), Some(42));
        assert_eq!(launch.reaped(5, 0), None);
        assert_eq!(launch.reaped(11, 143), None);
        assert_eq!(launch.code(), 42);
        // Nothing reaped of the main program: a failure.
        assert_eq!(Subreaper::new(5).code(), 1);
        assert_eq!(status_word(137), [b'S', 137]);
    }

    /// A signal goes to every child: the program, and the orphans it left
    /// that were handed to the subreaper — not to their own children, and
    /// not to anybody else.
    #[test]
    fn a_signal_goes_to_the_program_and_the_orphans_it_adopted() {
        // 3 is the subreaper: 4 the program, 7 an orphan it adopted, 8 the
        // orphan's child, 2 its own parent, 9 another launch's.
        let table = [(2, 1), (3, 0), (4, 3), (7, 3), (8, 7), (9, 6)];
        assert_eq!(forward_targets(3, &table), [4, 7]);
        assert!(forward_targets(5, &table).is_empty());
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            assert!(FORWARDED.contains(&sig), "{sig}");
        }
        assert!(!FORWARDED.contains(&libc::SIGKILL));
        assert!(!FORWARDED.contains(&libc::SIGCHLD));
    }

    /// A TERM goes to the launch's whole tree (stage 4): the program is in
    /// its instance's epoch, out of reach of its launcher's scope's stop —
    /// the orphan's child as well, never another launch's or a parent.
    #[test]
    fn a_term_goes_to_the_whole_tree_below() {
        let table = [(2, 1), (3, 0), (4, 3), (7, 3), (8, 7), (10, 8), (9, 6)];
        assert_eq!(descendants(3, &table), [4, 7, 8, 10]);
        assert_eq!(descendants(7, &table), [8, 10]);
        assert!(descendants(5, &table).is_empty());
        // A table that says a process is its own parent is no loop.
        assert_eq!(descendants(3, &[(3, 3), (4, 3), (4, 4)]), [4]);
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn slot_names_stay_one_level_deep() {
        assert_eq!(slot_name(".config"), ".config");
        assert_eq!(slot_name(".local/share"), ".local_share");
        assert_eq!(
            SUBDIRS.map(slot_name),
            [".config", ".local_share", ".cache", ".mozilla", ".pki"].map(String::from)
        );
    }

    #[test]
    fn arguments_are_split_on_the_first_separator() {
        let a = Args::parse(&argv(&[
            "/state/prof",
            "nl",
            "0",
            "/state/.running/prof",
            "--",
            "sh",
            "-c",
            "echo -- hi",
        ]))
        .unwrap();
        assert_eq!(a.profile_dir, PathBuf::from("/state/prof"));
        assert_eq!(a.zone, OsString::from("nl"));
        assert!(!a.ephemeral);
        assert_eq!(a.regdir, PathBuf::from("/state/.running/prof"));
        assert_eq!(a.cmd, argv(&["sh", "-c", "echo -- hi"]));
    }

    #[test]
    fn the_main_profile_is_an_empty_directory_argument() {
        let a = Args::parse(&argv(&["", "direct", "0", "", "--", "firefox"])).unwrap();
        assert_eq!(a.profile_dir, PathBuf::from(""));
        assert!(a.profile_dir.as_os_str().is_empty());
        assert_eq!(a.regdir, PathBuf::from(""));
        assert!(!a.ephemeral);
    }

    #[test]
    fn only_a_literal_one_means_throwaway() {
        assert!(
            Args::parse(&argv(&["/tmp/p", "nl", "1", "/r", "--", "x"]))
                .unwrap()
                .ephemeral
        );
        for not_one in ["0", "", "true", "yes"] {
            assert!(
                !Args::parse(&argv(&["/tmp/p", "nl", not_one, "/r", "--", "x"]))
                    .unwrap()
                    .ephemeral,
                "{not_one:?} must not be taken for a throwaway container"
            );
        }
    }

    #[test]
    fn trailing_arguments_may_be_omitted() {
        let a = Args::parse(&argv(&["/tmp/p", "nl", "--", "x"])).unwrap();
        assert!(!a.ephemeral);
        assert_eq!(a.regdir, PathBuf::from(""));
    }

    #[test]
    fn the_working_directory_comes_first_and_is_optional() {
        let a = Args::parse(&argv(&[
            "--cwd",
            "/home/u/src",
            "/state/prof",
            "nl",
            "0",
            "/r",
            "--",
            "x",
        ]))
        .unwrap();
        assert_eq!(a.cwd, Some(PathBuf::from("/home/u/src")));
        assert_eq!(a.profile_dir, PathBuf::from("/state/prof"));
        assert_eq!(a.zone, OsString::from("nl"));
        assert_eq!(a.regdir, PathBuf::from("/r"));
        assert_eq!(a.cmd, argv(&["x"]));
        // The main profile after it: an empty directory argument is still one.
        let a = Args::parse(&argv(&["--cwd", "/w", "", "nl", "0", "", "--", "x"])).unwrap();
        assert!(a.profile_dir.as_os_str().is_empty());
        assert_eq!(a.zone, OsString::from("nl"));
        // Older command lines have none.
        assert_eq!(
            Args::parse(&argv(&["/p", "nl", "--", "x"])).unwrap().cwd,
            None
        );
        // An empty value is no value.
        let a = Args::parse(&argv(&["--cwd", "", "/p", "nl", "--", "x"])).unwrap();
        assert_eq!(a.cwd, None);
        assert_eq!(a.profile_dir, PathBuf::from("/p"));
    }

    #[test]
    fn the_storage_and_the_shares_come_before_the_positionals() {
        let a = Args::parse(&argv(&[
            "--storage",
            "/home/u/.local/state/vpn-profiles/w",
            "--share",
            "/home/u/Projects",
            "--share",
            "/home/u/.claude",
            "/home/u/.local/state/vpn-profiles/w",
            "nl",
            "0",
            "",
            "--",
            "prog",
        ]))
        .unwrap();
        assert_eq!(
            a.storage,
            Some(PathBuf::from("/home/u/.local/state/vpn-profiles/w"))
        );
        assert_eq!(
            a.share,
            [
                PathBuf::from("/home/u/Projects"),
                PathBuf::from("/home/u/.claude")
            ]
        );
        assert_eq!(
            a.profile_dir,
            PathBuf::from("/home/u/.local/state/vpn-profiles/w")
        );
    }

    #[test]
    fn the_trust_flags_come_before_the_positionals_in_any_order() {
        let a = Args::parse(&argv(&[
            "--trust",
            "/s/sb/work/trust",
            "--cwd",
            "/w",
            "--certutil",
            "/store/certutil",
            "--nss-home",
            "/s/sb/work/home",
            "",
            "nl",
            "0",
            "",
            "--",
            "x",
        ]))
        .unwrap();
        assert_eq!(a.trust, Some(PathBuf::from("/s/sb/work/trust")));
        assert_eq!(a.nss_home, Some(PathBuf::from("/s/sb/work/home")));
        assert_eq!(a.certutil, Some(PathBuf::from("/store/certutil")));
        assert_eq!(a.cwd, Some(PathBuf::from("/w")));
        assert!(a.profile_dir.as_os_str().is_empty());
        assert_eq!(a.zone, OsString::from("nl"));
        // None of them by default.
        let a = Args::parse(&argv(&["/p", "nl", "--", "x"])).unwrap();
        assert_eq!((a.trust, a.nss_home, a.certutil), (None, None, None));
        // Declared directories repeat.
        let a = Args::parse(&argv(&[
            "--trust-extra",
            "/nix/store/a",
            "--trust",
            "/t",
            "--trust-extra",
            "/nix/store/b",
            "/p",
            "nl",
            "--",
            "x",
        ]))
        .unwrap();
        assert_eq!(
            a.trust_extra,
            [PathBuf::from("/nix/store/a"), PathBuf::from("/nix/store/b")]
        );
        assert_eq!(a.profile_dir, PathBuf::from("/p"));
    }

    #[test]
    fn the_start_directory_falls_back_to_home_and_then_to_the_root() {
        assert_eq!(
            start_dirs(Some(Path::new("/w")), Some(Path::new("/home/u"))),
            [
                PathBuf::from("/w"),
                PathBuf::from("/home/u"),
                PathBuf::from("/")
            ]
        );
        assert_eq!(
            start_dirs(None, Some(Path::new("/home/u"))),
            [PathBuf::from("/home/u"), PathBuf::from("/")]
        );
        assert_eq!(start_dirs(None, None), [PathBuf::from("/")]);
        assert_eq!(start_dirs(Some(Path::new("")), None), [PathBuf::from("/")]);
    }

    #[test]
    fn broken_command_lines_are_rejected() {
        assert_eq!(
            Args::parse(&argv(&["/tmp/p", "nl", "0", "/r", "firefox"])),
            Err(ArgError::NoSeparator)
        );
        assert_eq!(
            Args::parse(&argv(&["/tmp/p", "nl", "0", "/r", "--"])),
            Err(ArgError::EmptyCommand)
        );
        assert_eq!(
            Args::parse(&argv(&["/tmp/p", "--", "firefox"])),
            Err(ArgError::MissingArguments)
        );
    }

    #[test]
    fn exit_codes_follow_the_shell_convention() {
        // Hand-built wait(2) statuses: low byte 0 means "exited", and the
        // signal number lives in the low seven bits otherwise.
        assert_eq!(exit_code_of(0), 0);
        assert_eq!(exit_code_of(3 << 8), 3);
        assert_eq!(exit_code_of(libc::SIGKILL), 128 + 9);
    }

    /// A directory of the shape `vpn-zone run` writes, removed on drop.
    struct Reg {
        dir: PathBuf,
    }

    impl Reg {
        fn new(tag: &str, files: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("vpn-zone-core-test-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            for (name, body) in files {
                fs::write(dir.join(name), body).unwrap();
            }
            Self { dir }
        }
    }

    impl Drop for Reg {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_live_stranger_keeps_the_container() {
        let reg = Reg::new(
            "alive",
            &[
                ("firefox", "100 nl prof\n"),
                ("telegram", "200 nl prof\n"),
                (".lock", ""),
            ],
        );
        let alive: HashSet<i32> = [200].into_iter().collect();
        assert!(others_alive(
            &reg.dir,
            me(100),
            |pid| alive.contains(&pid),
            started
        ));
        // 200 is the only live one, and if it is us there is nobody else.
        assert!(!others_alive(
            &reg.dir,
            me(200),
            |pid| alive.contains(&pid),
            started
        ));
    }

    /// Every process of these tests started at tick 7, unless said otherwise.
    fn started(_pid: i32) -> Option<u64> {
        Some(7)
    }

    fn me(pid: i32) -> Registered {
        Registered { pid, start: 7 }
    }

    /// The launch's own record is the one excluded — by its pid and its
    /// start time (J9): not this process's pid, which with `wl-sandbox`
    /// between the launcher and `profile-run` is in no record at all.
    #[test]
    fn only_the_launchs_own_record_is_not_another_tenant() {
        let reg = Reg::new(
            "own-record",
            &[("firefox", "300 nl prof\n"), ("telegram", "400 nl prof\n")],
        );
        // The launcher (300, wl-sandbox by now) is alive above us; 400 is
        // not: nobody else.
        assert!(!others_alive(&reg.dir, me(300), |pid| pid == 300, started));
        // With 400 alive, somebody else.
        assert!(others_alive(
            &reg.dir,
            me(300),
            |pid| pid == 300 || pid == 400,
            started
        ));
        // Our own pid (what was excluded before) is no record's: the
        // launcher's record still counts as another tenant unless it is
        // named.
        assert!(others_alive(&reg.dir, me(4242), |pid| pid == 300, started));
        // The record's pid with another start time is another process that
        // got the number since — a tenant like any other.
        assert!(others_alive(
            &reg.dir,
            Registered { pid: 300, start: 6 },
            |pid| pid == 300,
            started
        ));
        // A pid whose start cannot be read is not ours to skip either.
        assert!(others_alive(&reg.dir, me(300), |pid| pid == 300, |_| None));
    }

    #[test]
    fn the_registered_flag_reads_pid_and_start_or_nothing() {
        assert_eq!(
            Registered::parse("1234:98765"),
            Some(Registered {
                pid: 1234,
                start: 98765
            })
        );
        assert_eq!(Registered::parse(&me(12).arg()), Some(me(12)));
        for bad in [
            "", "1234", ":5", "5:", "0:5", "-1:5", "1:-5", "1:2:3", "a:1", "1 :2",
        ] {
            assert_eq!(Registered::parse(bad), None, "{bad:?}");
        }
        let a = Args::parse(&argv(&[
            "--registered",
            "55:66",
            "--cwd",
            "/w",
            "/state/tmp",
            "nl",
            "1",
            "/state/.running/tmp",
            "--",
            "sh",
        ]))
        .unwrap();
        assert_eq!(a.registered, Some(Registered { pid: 55, start: 66 }));
        assert_eq!(a.cwd, Some(PathBuf::from("/w")));
        assert!(a.ephemeral);
        // Unreadable: none, and the rest still parses.
        let a = Args::parse(&argv(&["--registered", "x", "", "nl", "0", "", "--", "sh"])).unwrap();
        assert_eq!(a.registered, None);
        assert_eq!(a.zone, OsString::from("nl"));
    }

    #[test]
    fn dead_records_and_junk_lines_do_not_keep_the_container() {
        let reg = Reg::new(
            "dead",
            &[
                ("firefox", "100 nl prof\n101 nl prof\n"),
                // Everything that is not a decimal pid in the first field is
                // ignored, including a stray blank line.
                ("junk", "\nnot-a-pid nl prof\n1x2 nl\n  \n"),
            ],
        );
        assert!(!others_alive(&reg.dir, me(999), |_| false, started));
        assert!(!others_alive(&reg.dir, me(999), |pid| pid == 42, started));
    }

    #[test]
    fn a_missing_or_unnamed_registry_means_nobody_else() {
        assert!(!others_alive(Path::new(""), me(1), |_| true, started));
        assert!(!others_alive(
            Path::new("/nonexistent/vpn-zone-core/registry"),
            me(1),
            |_| true,
            started
        ));
    }
}
