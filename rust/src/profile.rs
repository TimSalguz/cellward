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
    /// `--storage PATH`: the container's storage directory, which the zone
    /// covers — given back at `PATH` from the zone's keep
    /// (`home_layer::KEPT_STORAGE`), in this launch's mount namespace only,
    /// before anything else.
    pub storage: Option<PathBuf>,
    /// `--camera`: the host's cameras let this launch — the covers the zone
    /// put over them are taken off in this mount namespace
    /// ([`uncover_capture`]).
    pub camera: bool,
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
        let (mut cwd, mut trust, mut nss_home, mut certutil) = (None, None, None, None);
        let mut trust_extra = Vec::new();
        let mut share = Vec::new();
        let mut storage = None;
        let mut camera = false;
        while let Some(flag) = positional.first() {
            if flag == "--camera" {
                camera = true;
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
            cwd,
            trust,
            nss_home,
            certutil,
            storage,
            camera,
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
        return Err(format!("the zone keeps no {}", kept.display()));
    }
    if fs::symlink_metadata(path).is_err() {
        fs::create_dir(path).map_err(|e| format!("cannot make {}: {e}", path.display()))?;
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
    let below = crate::home_layer::submounts(
        &fs::read_to_string("/proc/self/mountinfo").unwrap_or_default(),
        &home,
    );
    // The grants, checked again: the file is the host's, but a link along a
    // path may have changed since it was written. As written and as
    // resolved, and relative to the home they resolve in.
    let real_home = fs::canonicalize(&home).unwrap_or_else(|_| home.clone());
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
        give_back(&real, &home, rel)?;
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

/// Drop the ambient capability set before handing control to the program.
///
/// Errors are ignored deliberately: on a kernel without ambient capabilities
/// (< 4.3) `prctl` answers EINVAL, and there is nothing to clear there anyway.
fn clear_ambient_capabilities() {
    // SAFETY: prctl with these two constants takes no pointers.
    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    }
}

/// Is there a live process with this pid? The real liveness test, the one
/// [`others_alive`] is given in production.
pub fn proc_is_alive(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).is_dir()
}

/// Is anybody else still living in this container?
///
/// The registry is the one `vpn-zone run` writes: one file per program, one
/// line per launch, `pid zone selector`. Liveness is a parameter so that the
/// tests can answer it without spawning processes.
pub fn others_alive<F>(regdir: &Path, myself: i32, is_alive: F) -> bool
where
    F: Fn(i32) -> bool,
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
            if pid != myself && is_alive(pid) {
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

/// Let this launch reach the host's cameras. The zone covers them in its mount
/// namespace (`zone::hide_devices`); this one is a slave copy of it
/// (`launch::entry_argv`), where the covers are taken off — here, and nowhere
/// else. It stays a slave: every other device the zone covers later — a
/// security key, a serial adapter plugged in while this runs — is covered here
/// too, and so is a camera plugged in later (restart the program for it; the
/// zone's holder uncovering a device in the launches it is let is to come).
fn uncover_capture() -> Result<(), String> {
    let off = |path: &Path| {
        let Ok(target) = CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        // SAFETY: a NUL-terminated path and constant flags. Until nothing is
        // mounted there any more: a node covered twice has two covers.
        while unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) }
            == 0
        {}
    };
    off(Path::new("/dev/v4l"));
    for entry in fs::read_dir("/dev")
        .map_err(|e| format!("cannot read /dev: {e}"))?
        .flatten()
    {
        if crate::zone::is_capture_node(&entry.file_name().to_string_lossy()) {
            off(&entry.path());
        }
    }
    Ok(())
}

pub fn run(args: Args) -> u8 {
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
    // The cameras, where this launch is let them: never fatal — a camera
    // that stays covered is one the program does not get.
    if args.camera {
        if let Err(e) = uncover_capture() {
            eprintln!("profile-run: the cameras stay covered: {e}");
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
        let layer = crate::trust::Layer {
            dir,
            certutil: &certutil,
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

    // Nothing below this line needs privileges.
    clear_ambient_capabilities();

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
    // others. The count comes from the shared launch registry; our own pid —
    // which survived the `exec` into this binary — is excluded.
    let running = args.regdir.parent().unwrap_or(Path::new(""));
    if others_alive(&args.regdir, std::process::id() as i32, |pid| {
        crate::registry::alive(running, pid)
    }) {
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
        remove_tree(&args.regdir);
    }
    exit_code_of(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
        assert!(others_alive(&reg.dir, 100, |pid| alive.contains(&pid)));
        // 200 is the only live one, and if it is us there is nobody else.
        assert!(!others_alive(&reg.dir, 200, |pid| alive.contains(&pid)));
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
        assert!(!others_alive(&reg.dir, 999, |_| false));
        assert!(!others_alive(&reg.dir, 999, |pid| pid == 42));
    }

    #[test]
    fn a_missing_or_unnamed_registry_means_nobody_else() {
        assert!(!others_alive(Path::new(""), 1, |_| true));
        assert!(!others_alive(
            Path::new("/nonexistent/vpn-zone-core/registry"),
            1,
            |_| true
        ));
    }
}
