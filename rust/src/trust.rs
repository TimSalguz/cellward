//! Extra root certificates of one container (`docs/CERTIFICATES.md`).
//!
//! Some networks require trusting a root certificate the host does not: a
//! national CA, a corporate TLS-inspection root, a test CA. Whoever holds the
//! key of a trusted root reads and alters every TLS connection of every program
//! that trusts it — so such a certificate belongs to a CONTAINER and nothing
//! else. The host never trusts it, the container next door never trusts it,
//! and the same program started without that container never trusts it.
//!
//! Three layers, all laid down by `vpn-zone-core profile-run` in the mount
//! namespace of ONE launch, before the program starts:
//!
//! 1. **the bundle.** On NixOS one file carries most of the trust: OpenSSL,
//!    GnuTLS and p11-kit read it — and NSS reads p11-kit, because nixpkgs makes
//!    `libnssckbi.so` a symlink to `p11-kit-trust.so`. A copy of the host's
//!    bundle with the container's certificates appended is bind-mounted over
//!    the file every well-known bundle path resolves to. The host's file is
//!    never touched;
//! 2. **the environment.** `SSL_CERT_FILE` and its relatives name the SYSTEM
//!    path, never a path of the container. Environment variables leak
//!    (`systemctl --user import-environment` from inside the container), and a
//!    leaked variable then means the host's ordinary bundle: the content comes
//!    from the mount, and a mount cannot leak;
//! 3. **the NSS databases** Chromium, Electron and binary Firefox forks read
//!    (`~/.pki/nssdb`, `cert9.db` of Firefox-family profiles). Written with
//!    `certutil` only when the database lies under a directory proven to be the
//!    container's own — the overlay layer this launch just mounted, or the home
//!    of a named sandbox. That check is what stands between a certificate and
//!    the host: an overlay slot is only stacked where the host directory
//!    exists, so without it `certutil` would create `~/.pki/nssdb` IN THE REAL
//!    HOME and the host's Chromium would trust the certificate from then on.
//!
//! A bundle that cannot be laid down stops the launch; a database that cannot
//! be proven private is skipped with a warning.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::sys;

/// The directory inside a container's policy directory
/// (`containers/<name>`) that holds its certificates, one
/// `<sha256>.pem` per certificate. Its existence is what switches the layer on
/// — an empty one still cleans stale entries out of the NSS databases.
pub const DIR: &str = "trust";

/// The bundle paths the TLS stacks of a Linux system read: p11-kit's compiled
/// list on nixpkgs plus the Debian/Fedora names. On NixOS all of them resolve
/// to one file in the store.
pub const BUNDLE_PATHS: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/certs/ca-bundle.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/var/lib/ca-certificates/ca-bundle.pem",
];

/// The variables that name a bundle file. All of them get the SYSTEM path.
pub const ENV_VARS: [&str; 6] = [
    "SSL_CERT_FILE",
    "NIX_SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NODE_EXTRA_CA_CERTS",
];

/// Name of the file, inside an NSS database directory, that records which
/// fingerprints this project installed there. Equal stamp — no `certutil` at
/// all; a fingerprint in the stamp and no longer in the container — removed.
pub const STAMP: &str = ".vpn-zones-trust";

/// The name the tmpfs-backed bundle gets inside the (covered) trust directory.
const BUNDLE_FILE: &str = "bundle.crt";

/// Nickname prefix in the NSS databases: says whose entry it is.
const NICK_PREFIX: &str = "vpn-zones ";

const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

/// Where Firefox-family browsers keep their profiles, relative to the home.
/// Every direct subdirectory holding a `cert9.db` is a profile database.
const MOZILLA_ROOTS: [&str; 5] = [
    ".mozilla/firefox",
    ".librewolf",
    ".zen",
    ".floorp",
    ".waterfox",
];

/// One stored certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// Lower-case hex SHA-256 of the DER form: also the file name.
    pub sha256: String,
    pub path: PathBuf,
}

/// 64 lower-case hex digits.
pub fn is_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The certificates of a trust directory, by fingerprint. Anything that is not
/// `<fingerprint>.pem` is not a certificate of ours and is ignored.
pub fn stored(dir: &Path) -> Vec<Stored> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<Stored> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let sha256 = name.strip_suffix(".pem")?;
            is_fingerprint(sha256).then(|| Stored {
                sha256: sha256.to_owned(),
                path: e.path(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    out
}

/// The nickname a certificate gets in an NSS database.
pub fn nickname(sha256: &str) -> String {
    format!("{NICK_PREFIX}{}", &sha256[..sha256.len().min(16)])
}

/// What `openssl x509 -noout -fingerprint -sha256 -subject -issuer -enddate
/// -ext basicConstraints` says about a certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertInfo {
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    /// `basicConstraints CA:TRUE`. Nothing else may become a trust anchor here.
    pub is_ca: bool,
}

/// Read that output. Keyed by the line prefixes, not by their order: OpenSSL
/// prints the options in the order they were given, and that is not a promise
/// worth depending on. `None` when there is no usable fingerprint.
pub fn parse_x509_text(text: &str) -> Option<CertInfo> {
    let mut info = CertInfo::default();
    let mut constraints_follow = false;
    for line in text.lines() {
        let t = line.trim();
        let fingerprint = t
            .strip_prefix("sha256 Fingerprint=")
            .or_else(|| t.strip_prefix("SHA256 Fingerprint="));
        if let Some(fp) = fingerprint {
            info.sha256 = fp
                .chars()
                .filter(|c| *c != ':')
                .collect::<String>()
                .to_ascii_lowercase();
        } else if let Some(v) = t.strip_prefix("subject=") {
            info.subject = v.trim().to_owned();
        } else if let Some(v) = t.strip_prefix("issuer=") {
            info.issuer = v.trim().to_owned();
        } else if let Some(v) = t.strip_prefix("notAfter=") {
            info.not_after = v.trim().to_owned();
        } else if t.starts_with("X509v3 Basic Constraints") {
            constraints_follow = true;
            continue;
        } else if constraints_follow {
            info.is_ca = t.split(',').any(|part| part.trim() == "CA:TRUE");
        }
        constraints_follow = false;
    }
    is_fingerprint(&info.sha256).then_some(info)
}

/// How many PEM certificates a file holds. A trust file must hold exactly one:
/// a bundle added "as a certificate" would smuggle in every root inside it.
pub fn count_pem_certs(bytes: &[u8]) -> usize {
    bytes
        .windows(PEM_BEGIN.len())
        .filter(|w| *w == PEM_BEGIN)
        .count()
}

/// The host's bundle followed by the container's certificates, each part
/// ending in a newline so that no two PEM blocks run into each other.
pub fn merged_bundle(base: &[u8], pems: &[Vec<u8>]) -> Vec<u8> {
    let mut out = base.to_vec();
    for pem in pems {
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(pem);
    }
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

/// The fingerprints a stamp file records.
pub fn parse_stamp(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| is_fingerprint(l))
        .map(str::to_owned)
        .collect()
}

/// A stamp file's content for a set of fingerprints.
pub fn stamp_text(fingerprints: &BTreeSet<String>) -> String {
    let mut out = String::new();
    for fp in fingerprints {
        out.push_str(fp);
        out.push('\n');
    }
    out
}

/// The NSS databases under a home: `.pki/nssdb` (whether it exists yet or
/// not — Chromium creates it on first start, and a certificate has to be there
/// before) and every Firefox-family profile that already has a `cert9.db`.
pub fn nss_databases(home: &Path) -> Vec<PathBuf> {
    let mut out = vec![home.join(".pki/nssdb")];
    for root in MOZILLA_ROOTS {
        let Ok(entries) = fs::read_dir(home.join(root)) else {
            continue;
        };
        let mut profiles: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join("cert9.db").is_file())
            .collect();
        profiles.sort();
        out.extend(profiles);
    }
    out
}

/// Is `path` inside one of `roots`? Components, not bytes: `/home/u/.pki2` is
/// not inside `/home/u/.pki`.
pub fn under_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| !root.as_os_str().is_empty() && path.starts_with(root))
}

/// The bind targets: every bundle path that exists, resolved by hand to the
/// file it really is (`mount(2)` follows the chain and lands there anyway —
/// resolving first is what lets two names of one file be bound once), plus a
/// file named by `NIX_SSL_CERT_FILE`/`SSL_CERT_FILE` outside that list.
fn bind_targets(extra: Option<&Path>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let candidates = BUNDLE_PATHS.iter().map(Path::new).chain(extra);
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let target = sys::link_target(path);
        if seen.insert(target.clone()) {
            out.push(target);
        }
    }
    out
}

/// The bundle file a variable names, when it names one that exists.
fn env_bundle() -> Option<PathBuf> {
    ["NIX_SSL_CERT_FILE", "SSL_CERT_FILE"]
        .iter()
        .filter_map(std::env::var_os)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Everything the layer needs, gathered by `profile-run`.
#[derive(Debug, Clone)]
pub struct Layer<'a> {
    /// The container's trust directory.
    pub dir: &'a Path,
    pub certutil: &'a Path,
    /// bwrap: certutil works on a database in a box where nothing else is.
    pub bwrap: &'a Path,
    /// The home the program will see: `$HOME` with its overlay, or the home
    /// of a named sandbox as it lies on disk.
    pub home: &'a Path,
    /// Directories proven to be the container's own. An NSS database outside
    /// all of them is never written.
    pub private: &'a [PathBuf],
    /// Certificate directories declared in Nix, in the same `<sha256>.pem`
    /// shape; read-only, built by the module.
    pub extra: &'a [PathBuf],
}

/// Lay the layer down. `Ok` carries the warnings to print; `Err` means the
/// launch must stop.
pub fn apply(layer: &Layer<'_>) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    let mut certs: Vec<(String, Vec<u8>)> = Vec::new();
    let dirs = std::iter::once(layer.dir).chain(layer.extra.iter().map(PathBuf::as_path));
    for cert in dirs.flat_map(stored) {
        // The same certificate declared and added by hand is one certificate.
        if certs.iter().any(|(fp, _)| *fp == cert.sha256) {
            continue;
        }
        let pem = fs::read(&cert.path).map_err(|e| {
            format!(
                "cannot read the trusted certificate {}: {e}",
                cert.path.display()
            )
        })?;
        certs.push((cert.sha256, pem));
    }

    if !certs.is_empty() {
        bind_bundle(layer.dir, &certs)?;
    }
    sync_nss(layer, &certs, &mut warnings);
    Ok(warnings)
}

/// Layers 1 and 2: the bundle bind and the environment.
fn bind_bundle(dir: &Path, certs: &[(String, Vec<u8>)]) -> Result<(), String> {
    let env_file = env_bundle();
    let targets = bind_targets(env_file.as_deref());
    // The base is what the host trusts right now: the file a variable names,
    // otherwise the first system bundle. With no bundle at all there is nothing
    // to add to — and a bundle of ONLY the extra roots would replace every
    // other root for OpenSSL, which is not what anybody asked for.
    let base_path = env_file
        .clone()
        .or_else(|| targets.first().cloned())
        .ok_or("the system has no certificate bundle to add the container's roots to")?;
    let base = fs::read(&base_path)
        .map_err(|e| format!("cannot read the bundle {}: {e}", base_path.display()))?;
    let pems: Vec<Vec<u8>> = certs.iter().map(|(_, pem)| pem.clone()).collect();
    let bundle = merged_bundle(&base, &pems);

    // The bundle has to live in a file only this launch can see: a tmpfs over
    // the trust directory itself (the certificates are already in memory).
    sys::mount(
        OsStr::new("tmpfs"),
        dir,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=0755,size=8m",
    )
    .map_err(|e| format!("cannot mount a tmpfs over {}: {e}", dir.display()))?;
    let source = dir.join(BUNDLE_FILE);
    fs::write(&source, &bundle)
        .and_then(|()| fs::set_permissions(&source, fs::Permissions::from_mode(0o444)))
        .map_err(|e| format!("cannot write {}: {e}", source.display()))?;

    for target in &targets {
        sys::mount(source.as_os_str(), target, "", libc::MS_BIND, "").map_err(|e| {
            format!(
                "cannot bind the container's bundle over {}: {e}",
                target.display()
            )
        })?;
        // Read-only on top, best effort: the program could only spoil its own
        // copy anyway.
        let _ = sys::mount(
            OsStr::new(""),
            target,
            "",
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
            "",
        );
    }

    // The SYSTEM path — never the tmpfs one. A variable that leaks out of the
    // container then names the host's ordinary bundle.
    let system = BUNDLE_PATHS
        .iter()
        .find(|p| Path::new(p).is_file())
        .copied()
        .unwrap_or(BUNDLE_PATHS[0]);
    for var in ENV_VARS {
        std::env::set_var(var, system);
    }
    Ok(())
}

/// Layer 3: bring every provably private NSS database in line with the
/// container's certificates.
fn sync_nss(layer: &Layer<'_>, certs: &[(String, Vec<u8>)], warnings: &mut Vec<String>) {
    let want: BTreeSet<String> = certs.iter().map(|(fp, _)| fp.clone()).collect();
    // The roots and each database as they really are, links resolved: a
    // sandboxed program could make `.pki` or `.mozilla` a link to the host's
    // own, and a path compared as it is written would pass as the container's
    // (review 2026-09-25) — the host's browsers would trust the container's
    // roots then.
    let roots: Vec<PathBuf> = layer
        .private
        .iter()
        .filter_map(|r| crate::container::resolved(r))
        .collect();
    for written in nss_databases(layer.home) {
        let Some(db) = crate::container::resolved(&written).filter(|r| under_any(r, &roots)) else {
            if !want.is_empty() {
                warnings.push(format!(
                    "{} is not the container's own (it lies outside its layer) — the extra roots \
                     are NOT installed there; a program reading it needs a container with a home \
                     of its own",
                    written.display()
                ));
            }
            continue;
        };
        sync_database(layer, &db, &roots, certs, &want, warnings);
    }
}

/// One database brought in line with the container's certificates.
///
/// The database and every name in it are the container's: a program of a
/// sandbox cannot reach the host's `~/.pki`, but it can make its own
/// `cert9.db` a link there — and certutil, or SQLite's journal beside it,
/// run from here, where the real home is in sight, would write the host's
/// (review 2026-09-27). So the directory is opened once, not through a link,
/// and found to be the container's once open; certutil gets that
/// descriptor in a box where nothing else is ([`certutil`]), and the stamp
/// is read and written through it, never through a link.
fn sync_database(
    layer: &Layer<'_>,
    db: &Path,
    roots: &[PathBuf],
    certs: &[(String, Vec<u8>)],
    want: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    if fs::symlink_metadata(db).is_err() {
        // Nothing there and nothing to put there.
        if want.is_empty() {
            return;
        }
        // Chromium makes `.pki/nssdb` on its first start, and a certificate
        // has to be there before.
        if let Err(e) = fs::DirBuilder::new().recursive(true).mode(0o700).create(db) {
            warnings.push(format!("cannot create {}: {e}", db.display()));
            return;
        }
    }
    let dir = match open_database(db, roots) {
        Ok(dir) => dir,
        Err(e) => {
            warnings.push(e);
            return;
        }
    };
    let old = read_in(&dir, STAMP)
        .map(|t| parse_stamp(&t))
        .unwrap_or_default();
    if old == *want {
        return;
    }
    let run = |args: &[&str], input: Option<&[u8]>| certutil(layer, &dir, db, args, input);
    if !plain_in(&dir, "cert9.db") {
        if let Err(e) = run(&["-N", "--empty-password"], None) {
            warnings.push(e);
            return;
        }
    }
    let mut done: BTreeSet<String> = old.clone();
    for fp in old.difference(want) {
        // A certificate no longer in the container. An entry that is
        // already gone is fine too.
        let _ = run(&["-D", "-n", &nickname(fp)], None);
        done.remove(fp);
    }
    for (fp, pem) in certs.iter().filter(|(fp, _)| !old.contains(fp)) {
        let args = ["-A", "-n", &nickname(fp), "-t", "C,,", "-a"];
        match run(&args, Some(pem)) {
            Ok(()) => {
                done.insert(fp.clone());
            }
            Err(e) => warnings.push(e),
        }
    }
    if let Err(e) = write_in(&dir, STAMP, &stamp_text(&done)) {
        warnings.push(format!("cannot write {}: {e}", db.join(STAMP).display()));
    }
}

/// The database's directory, opened: never through a link at its end, and —
/// wherever links before it led — the container's own once open. Whatever
/// is done to the database from here on goes through this descriptor, and
/// the directory cannot be swapped for another after the check.
fn open_database(db: &Path, roots: &[PathBuf]) -> Result<OwnedFd, String> {
    let path = CString::new(db.as_os_str().as_bytes())
        .map_err(|_| format!("{}: a NUL in the path", db.display()))?;
    // SAFETY: a NUL-terminated path; the descriptor is owned right below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot open {}: {}",
            db.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: just opened, and nobody else's.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let real = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|e| format!("cannot tell where {} is: {e}", db.display()))?;
    if !under_any(&real, roots) {
        return Err(format!(
            "{} is not the container's own (it lies outside its layer) — the extra roots are \
             NOT installed there",
            db.display()
        ));
    }
    Ok(fd)
}

/// A file of the database, read — never through a link. `None` when it is
/// not there, or not a plain file.
fn read_in(dir: &OwnedFd, name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    // SAFETY: a directory descriptor and a NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: just opened, and nobody else's.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(1 << 16).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Is `name` a plain file in the directory — not a link to one?
fn plain_in(dir: &OwnedFd, name: &str) -> bool {
    let Ok(name) = CString::new(name) else {
        return false;
    };
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a directory descriptor, a NUL-terminated name, a stat to fill.
    let found = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0;
    found && st.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// A file of the database, written whole: a new file beside it, renamed over
/// the name — a rename replaces a link, it never writes where one points.
fn write_in(dir: &OwnedFd, name: &str, text: &str) -> std::io::Result<()> {
    let tmp = CString::new(format!(".{name}.{}.new", std::process::id()))?;
    let name = CString::new(name)?;
    let at = dir.as_raw_fd();
    // SAFETY: a directory descriptor and NUL-terminated names throughout.
    unsafe { libc::unlinkat(at, tmp.as_ptr(), 0) };
    // SAFETY: as above; the mode is openat's third, variadic argument.
    let fd = unsafe {
        libc::openat(
            at,
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: just opened, and nobody else's.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let written = file.write_all(text.as_bytes());
    drop(file);
    // SAFETY: as above.
    let renamed = written.and_then(|()| {
        if unsafe { libc::renameat(at, tmp.as_ptr(), at, name.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    });
    if renamed.is_err() {
        // SAFETY: as above.
        unsafe { libc::unlinkat(at, tmp.as_ptr(), 0) };
    }
    renamed
}

/// Bring the NSS databases of a home that is the container's own by
/// construction (a named sandbox's, on disk) in line with its certificates,
/// from outside any launch. Returns the warnings.
pub fn sync_home(certutil: &Path, bwrap: &Path, dir: &Path, home: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut certs = Vec::new();
    for cert in stored(dir) {
        match fs::read(&cert.path) {
            Ok(pem) => certs.push((cert.sha256, pem)),
            Err(e) => warnings.push(format!("cannot read {}: {e}", cert.path.display())),
        }
    }
    let private = [home.to_path_buf()];
    let layer = Layer {
        dir,
        certutil,
        bwrap,
        home,
        private: &private,
        extra: &[],
    };
    sync_nss(&layer, &certs, &mut warnings);
    warnings
}

/// Create the database directory and an empty database in it when missing.
/// Where the database is in certutil's box.
const BOX_DB: &str = "/db";

/// `certutil <args>` on the database `dir`, stdin from `input` when given —
/// in a box of its own (bwrap, every namespace its own) where there is
/// nothing but the database, bound from the descriptor, and the programs'
/// directories, read-only: a link the container left in the database leads
/// nowhere from there. `shown` names the database in messages.
fn certutil(
    layer: &Layer<'_>,
    dir: &OwnedFd,
    shown: &Path,
    args: &[&str],
    input: Option<&[u8]>,
) -> Result<(), String> {
    let tool = program_path(layer.certutil)
        .ok_or_else(|| format!("no {} to run", layer.certutil.display()))?;
    let fd = dir.as_raw_fd();
    let mut cmd = Command::new(layer.bwrap);
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session"]);
    for system in ["/nix/store", "/usr", "/bin", "/lib", "/lib64"] {
        cmd.args(["--ro-bind-try", system, system]);
    }
    cmd.args(["--dev", "/dev", "--tmpfs", "/tmp"])
        .arg("--bind-fd")
        .arg(fd.to_string())
        .arg(BOX_DB)
        .arg("--")
        .arg(&tool)
        .args(args)
        .arg("-d")
        .arg(format!("sql:{BOX_DB}"));
    // SAFETY: fcntl and prctl only, both async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // The descriptor goes to bwrap; none of this process's
            // capabilities do (`profile-run` may still hold the zone's).
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
            Ok(())
        });
    }
    let mut child = cmd
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", layer.bwrap.display()))?;
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let _ = stdin.write_all(bytes);
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "certutil {} on {}: {}",
            args.first().copied().unwrap_or(""),
            shown.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// A program's own path, links resolved — what the box has of it: a bare
/// name looked up in `PATH` here, where `PATH` leads somewhere.
fn program_path(program: &Path) -> Option<PathBuf> {
    if program.as_os_str().as_bytes().contains(&b'/') {
        return fs::canonicalize(program).ok();
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
        .and_then(|p| fs::canonicalize(p).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("vpn-zone-trust-test-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn openssl_output_is_read_by_prefix_and_only_a_ca_is_a_ca() {
        let text = "\
sha256 Fingerprint=0F:1E:2D:3C:4B:5A:69:78:87:96:A5:B4:C3:D2:E1:F0:0F:1E:2D:3C:4B:5A:69:78:87:96:A5:B4:C3:D2:E1:F0
subject=C=XX, O=Test, CN=Test Root CA
issuer=C=XX, O=Test, CN=Test Root CA
notAfter=Jan  1 00:00:00 2030 GMT
X509v3 Basic Constraints: critical
    CA:TRUE
";
        let info = parse_x509_text(text).unwrap();
        assert_eq!(info.sha256, FP);
        assert_eq!(info.subject, "C=XX, O=Test, CN=Test Root CA");
        assert_eq!(info.not_after, "Jan  1 00:00:00 2030 GMT");
        assert!(info.is_ca);

        // A leaf certificate, and one without the extension at all.
        let leaf = text.replace("CA:TRUE", "CA:FALSE");
        assert!(!parse_x509_text(&leaf).unwrap().is_ca);
        let bare = text
            .replace(
                "X509v3 Basic Constraints: critical\n",
                "No extensions in certificate\n",
            )
            .replace("    CA:TRUE\n", "");
        assert!(!parse_x509_text(&bare).unwrap().is_ca);
        // "CA:TRUE" somewhere else is not the constraint.
        let elsewhere = bare.replace("CN=Test Root CA", "CN=CA:TRUE");
        assert!(!parse_x509_text(&elsewhere).unwrap().is_ca);
        // A pathlen next to it is still a CA.
        let pathlen = text.replace("CA:TRUE", "CA:TRUE, pathlen:0");
        assert!(parse_x509_text(&pathlen).unwrap().is_ca);
        // No fingerprint, no certificate.
        assert_eq!(parse_x509_text("subject=CN=x\n"), None);
    }

    #[test]
    fn a_trust_file_holds_exactly_one_certificate() {
        let one = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(count_pem_certs(one), 1);
        assert_eq!(
            count_pem_certs(&[one.as_slice(), one.as_slice()].concat()),
            2
        );
        assert_eq!(count_pem_certs(b"\x30\x82\x01\x0a"), 0);
    }

    #[test]
    fn the_bundle_is_the_base_then_the_extra_roots_never_glued_together() {
        assert_eq!(
            merged_bundle(b"BASE", &[b"ONE".to_vec(), b"TWO\n".to_vec()]),
            b"BASE\nONE\nTWO\n"
        );
        assert_eq!(merged_bundle(b"BASE\n", &[]), b"BASE\n");
        assert_eq!(merged_bundle(b"", &[b"ONE".to_vec()]), b"ONE\n");
    }

    #[test]
    fn stored_certificates_are_the_fingerprint_named_ones() {
        let tmp = TempDir::new("stored");
        fs::write(tmp.0.join(format!("{FP}.pem")), "x").unwrap();
        fs::write(tmp.0.join("notes.pem"), "x").unwrap();
        fs::write(tmp.0.join(BUNDLE_FILE), "x").unwrap();
        fs::write(tmp.0.join(format!("{}.pem", FP.to_uppercase())), "x").unwrap();
        let got = stored(&tmp.0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sha256, FP);
        assert!(stored(Path::new("/nonexistent/trust")).is_empty());
        assert_eq!(nickname(FP), "vpn-zones 0f1e2d3c4b5a6978");
    }

    #[test]
    fn stamps_round_trip_and_ignore_junk() {
        let set: BTreeSet<String> = [FP.to_owned()].into_iter().collect();
        assert_eq!(parse_stamp(&stamp_text(&set)), set);
        assert!(parse_stamp("junk\n\n").is_empty());
        assert_eq!(stamp_text(&BTreeSet::new()), "");
    }

    #[test]
    fn nss_databases_are_the_pki_one_and_the_existing_browser_profiles() {
        let tmp = TempDir::new("nss");
        let home = &tmp.0;
        fs::create_dir_all(home.join(".mozilla/firefox/abc.default")).unwrap();
        fs::write(home.join(".mozilla/firefox/abc.default/cert9.db"), "").unwrap();
        fs::create_dir_all(home.join(".mozilla/firefox/Crash Reports")).unwrap();
        fs::create_dir_all(home.join(".zen/xyz")).unwrap();
        fs::write(home.join(".zen/xyz/cert9.db"), "").unwrap();
        assert_eq!(
            nss_databases(home),
            vec![
                home.join(".pki/nssdb"),
                home.join(".mozilla/firefox/abc.default"),
                home.join(".zen/xyz"),
            ]
        );
    }

    #[test]
    fn privacy_is_decided_by_path_components() {
        let roots = vec![
            PathBuf::from("/home/u/.pki"),
            PathBuf::from("/home/u/.mozilla"),
        ];
        assert!(under_any(Path::new("/home/u/.pki/nssdb"), &roots));
        assert!(under_any(Path::new("/home/u/.mozilla/firefox/abc"), &roots));
        assert!(!under_any(Path::new("/home/u/.pki2/nssdb"), &roots));
        assert!(!under_any(Path::new("/home/u/.zen/xyz"), &roots));
        // No roots, or an empty one, proves nothing.
        assert!(!under_any(Path::new("/home/u/.pki/nssdb"), &[]));
        assert!(!under_any(Path::new("/x"), &[PathBuf::new()]));
    }

    #[test]
    fn a_database_outside_the_container_is_never_written() {
        // The trap: an overlay slot not stacked (no ~/.pki on the host) must not
        // make certutil create the database in the real home.
        let tmp = TempDir::new("outside");
        let home = tmp.0.join("home");
        let trust = tmp.0.join("trust");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&trust).unwrap();
        let layer = Layer {
            dir: &trust,
            // Would fail loudly if it were ever run.
            certutil: Path::new("/nonexistent/certutil"),
            bwrap: Path::new("/nonexistent/bwrap"),
            home: &home,
            private: &[tmp.0.join("somewhere-else")],
            extra: &[],
        };
        let certs = vec![(FP.to_owned(), b"PEM".to_vec())];
        let mut warnings = Vec::new();
        sync_nss(&layer, &certs, &mut warnings);
        assert!(
            !home.join(".pki").exists(),
            "a database appeared in the real home"
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("NOT installed"), "{warnings:?}");

        // Nothing to install and nothing installed: not a word.
        let mut warnings = Vec::new();
        sync_nss(&layer, &[], &mut warnings);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// `.pki` made a link to the host's own is not the container's, whatever
    /// its written path says.
    #[test]
    fn a_database_linked_out_of_the_layer_is_not_the_containers() {
        let base = std::env::temp_dir().join(format!("vz-trust-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let home = base.join("sandbox/home");
        let host = base.join("host/.pki");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&host).unwrap();
        std::os::unix::fs::symlink(&host, home.join(".pki")).unwrap();
        let roots = vec![crate::container::resolved(&home).unwrap()];
        let written = home.join(".pki/nssdb");
        assert!(
            under_any(&written, std::slice::from_ref(&home)),
            "as written it looks inside"
        );
        let real = crate::container::resolved(&written).unwrap();
        assert!(
            !under_any(&real, &roots),
            "resolved it is the host's: {}",
            real.display()
        );
        let _ = fs::remove_dir_all(&base);
    }
}
