//! Nested filesystem rules. Parents mount first; explicit children override
//! inherited access. A rule is never silently ignored on a mount failure.
use crate::{container, tools::Tools};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};
pub const FILE: &str = "folder-rules";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ReadOnly,
    Real,
    Overlay,
}
impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ro" => Some(Self::ReadOnly),
            "rw" => Some(Self::Real),
            "overlay" => Some(Self::Overlay),
            _ => None,
        }
    }
    pub fn word(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::Real => "rw",
            Self::Overlay => "overlay",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub path: PathBuf,
    pub mode: Mode,
}
pub fn parse(text: &str) -> Result<Vec<Rule>, String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (mode, path) = line
            .split_once('\t')
            .ok_or("неверный формат правила папки")?;
        let mode = Mode::parse(mode).ok_or("неизвестный режим папки")?;
        if path.contains(['\t', '\r', '\n']) || !Path::new(path).is_absolute() {
            return Err("нужен абсолютный путь папки".into());
        }
        let path = container::lexical(Path::new(path));
        if out.iter().any(|r: &Rule| r.path == path) {
            return Err("два правила одной папки".into());
        }
        out.push(Rule { path, mode });
    }
    order(&mut out);
    Ok(out)
}
pub fn order(rules: &mut [Rule]) {
    rules.sort_by(|a, b| {
        a.path
            .components()
            .count()
            .cmp(&b.path.components().count())
            .then(a.path.cmp(&b.path))
    });
}
pub fn load(tools: &Tools, record: &str) -> Result<Vec<Rule>, String> {
    let file = container::policy_dir(tools, record).join(FILE);
    match fs::read_to_string(file) {
        Ok(s) => parse(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}
pub fn validate(home: &Path, path: &Path) -> Result<PathBuf, String> {
    if let Some(why) = container::forbidden_path(home, path) {
        return Err(why);
    }
    let real = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let real_home = fs::canonicalize(home).unwrap_or_else(|_| home.to_owned());
    if let Some(why) = container::forbidden_path(&real_home, &real) {
        return Err(why);
    }
    if !real.is_dir() {
        return Err("выберите каталог".into());
    }
    Ok(real)
}
pub fn set(tools: &Tools, record: &str, word: &str, path: &str) -> Result<(), String> {
    if word == "hide" {
        return Err("Полная невидимость папок ещё не поддерживается; пустая точка монтирования не заменяет скрытие имени".into());
    }
    let c = container::load(tools, record).ok_or("контейнер не найден")?;
    fs::create_dir_all(&c.policy).map_err(|e| e.to_string())?;
    // Share the record's writer lock with other container settings. Two
    // approvals must not lose each other's rules during read/modify/write.
    let _policy_lock = crate::registry::lock(&c.policy).map_err(|e| e.to_string())?;
    let path = if let Some(rel) = path.strip_prefix("~/") {
        tools.home.join(rel)
    } else {
        PathBuf::from(path)
    };
    if path.to_string_lossy().contains(['\n', '\r', '\t']) {
        return Err("в пути управляющий символ".into());
    }
    let path = container::lexical(&path);
    let real = if word == "inherit" {
        path.clone()
    } else {
        validate(&tools.home, &path)?
    };
    for protected in [
        &tools.config,
        &tools.state,
        &tools.profiles,
        &tools.sandboxes,
    ] {
        for p in [&path, &real] {
            if p.starts_with(protected) || protected.starts_with(p) {
                return Err("состояние Cellward не выдаётся".into());
            }
            if let Ok(protected) = fs::canonicalize(protected) {
                if p.starts_with(&protected) || protected.starts_with(p) {
                    return Err("состояние Cellward не выдаётся".into());
                }
            }
        }
    }
    if word != "inherit"
        && c.paths.iter().any(|p| {
            p.source == container::Source::Nix
                && (p.value.starts_with(&path) || path.starts_with(&p.value))
        })
    {
        return Err("пересекающийся доступ задан в Nix — измените его там".into());
    }
    if c.home == container::Home::Main && word != "inherit" {
        return Err("Для правил папок выберите свой дом или overlay-дом; настоящий дом уже доступен напрямую".into());
    }
    let mut rules = load(tools, record)?;
    rules.retain(|r| r.path != path);
    if word != "inherit" {
        rules.push(Rule {
            path,
            mode: Mode::parse(word).ok_or("неизвестный режим папки")?,
        });
    }
    order(&mut rules);
    let text: String = rules
        .iter()
        .map(|r| format!("{}\t{}\n", r.mode.word(), r.path.display()))
        .collect();
    fs::create_dir_all(&c.policy).map_err(|e| e.to_string())?;
    use std::{
        io::Write,
        os::unix::fs::OpenOptionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT_POLICY: AtomicU64 = AtomicU64::new(0);
    let temp = c.policy.join(format!(
        ".folder-rules-{}-{}",
        std::process::id(),
        NEXT_POLICY.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, c.policy.join(FILE))
    })();
    let _ = fs::remove_file(temp);
    result.map_err(|e: std::io::Error| e.to_string())
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub shared: bool,
    pub rule: Rule,
    pub source: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
}
/// Resolve all sources before any parent mount hides them. Per-path persistent
/// layers use an identity file to detect a hash collision instead of sharing data.
pub fn prepare(
    home: &Path,
    data: &Path,
    rules: &[Rule],
    protected: &[PathBuf],
) -> Result<Vec<Mount>, String> {
    let mut rules = rules.to_vec();
    order(&mut rules);
    let mut out: Vec<Mount> = Vec::new();
    for rule in rules {
        let source = validate(home, &rule.path)?;
        for protected in protected {
            let real = fs::canonicalize(protected).unwrap_or_else(|_| protected.clone());
            if [&rule.path, &source].iter().any(|p| {
                p.starts_with(protected)
                    || protected.starts_with(p)
                    || p.starts_with(&real)
                    || real.starts_with(p)
            }) {
                return Err("папка пересекается с защищённым состоянием Cellward".into());
            }
        }
        for parent in &out {
            if rule.path.starts_with(&parent.rule.path) && !source.starts_with(&parent.source) {
                return Err(
                    "вложенная ссылка выходит из родительского правила; выберите настоящий путь"
                        .into(),
                );
            }
        }
        let mut hash = 0xcbf29ce484222325u64;
        use std::os::unix::ffi::OsStrExt;
        for byte in rule.path.as_os_str().as_bytes() {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
        let dir = data.join("folder-layers").join(format!("{hash:016x}"));
        let (upper, work) = (dir.join("upper"), dir.join("work"));
        if !data.as_os_str().is_empty() {
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            identity_file(&dir.join("path"), rule.path.as_os_str().as_bytes())?;
        }
        if rule.mode == Mode::Overlay {
            if data.as_os_str().is_empty() {
                return Err("нет хранилища слоя папки".into());
            }
            for p in [&upper, &work] {
                fs::create_dir_all(p).map_err(|e| e.to_string())?;
            }
        }
        out.push(Mount {
            shared: false,
            rule,
            source,
            upper,
            work,
        });
    }
    Ok(out)
}
/// Publish an immutable identity atomically. Rewriting it at every launch
/// exposes an empty/truncated file to concurrent launches and looks like a
/// hash collision. A fully written temporary inode is linked without replacing
/// an existing identity, so genuine collisions still fail closed.
fn identity_file(path: &Path, value: &[u8]) -> Result<(), String> {
    if !path.exists() {
        use std::{
            io::Write,
            sync::atomic::{AtomicU64, Ordering},
        };
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temp = path.with_file_name(format!(
            ".identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)?;
            file.write_all(value)?;
            file.sync_all()?;
            match fs::hard_link(&temp, path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e),
            }
        })();
        let _ = fs::remove_file(temp);
        result.map_err(|e: std::io::Error| e.to_string())?;
    }
    if fs::read(path).map_err(|e| e.to_string())? != value {
        return Err("коллизия хранилища слоёв".into());
    }
    Ok(())
}

pub fn bwrap_args(out: &mut Vec<OsString>, mounts: &[Mount]) {
    for m in mounts {
        match m.rule.mode {
            Mode::ReadOnly | Mode::Real => out.extend([
                if m.rule.mode == Mode::Real {
                    "--bind"
                } else {
                    "--ro-bind"
                }
                .into(),
                m.source.as_os_str().into(),
                m.rule.path.as_os_str().into(),
            ]),
            Mode::Overlay if m.shared => out.extend([
                "--bind".into(),
                m.source.as_os_str().into(),
                m.rule.path.as_os_str().into(),
            ]),
            Mode::Overlay => out.extend([
                "--overlay-src".into(),
                m.source.as_os_str().into(),
                "--overlay".into(),
                m.upper.as_os_str().into(),
                m.work.as_os_str().into(),
                m.rule.path.as_os_str().into(),
            ]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "cw-folder-rules-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn nested_rules_order_sources_before_parent_mounts_and_persist_layers() {
        let t = Temp::new();
        let home = t.0.join("home");
        let parent = home.join("Projects");
        let child = parent.join("shared");
        let nested = child.join("cache");
        fs::create_dir_all(&nested).unwrap();
        let rules = parse(&format!(
            "overlay\t{}\nrw\t{}\noverlay\t{}\n",
            nested.display(),
            child.display(),
            parent.display()
        ))
        .unwrap();
        assert_eq!(
            rules.iter().map(|r| r.path.clone()).collect::<Vec<_>>(),
            vec![parent, child, nested]
        );
        let first = prepare(&home, &t.0.join("data"), &rules, &[]).unwrap();
        fs::write(first[0].upper.join("kept"), "private").unwrap();
        let again = prepare(&home, &t.0.join("data"), &rules, &[]).unwrap();
        assert_eq!(
            fs::read_to_string(again[0].upper.join("kept")).unwrap(),
            "private"
        );
        assert_ne!(again[0].upper, again[2].upper);
    }
    #[test]
    fn protected_state_and_retargeted_aliases_stop_preparation() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        let home = t.0.join("home");
        let safe = home.join("docs");
        let state = home.join("custom-state");
        fs::create_dir_all(&safe).unwrap();
        fs::create_dir_all(&state).unwrap();
        let alias = home.join("alias");
        symlink(&safe, &alias).unwrap();
        let rule = Rule {
            path: alias.clone(),
            mode: Mode::ReadOnly,
        };
        assert!(prepare(&home, &t.0.join("data"), &[rule.clone()], &[state.clone()]).is_ok());
        fs::remove_file(&alias).unwrap();
        symlink(&state, &alias).unwrap();
        assert!(prepare(&home, &t.0.join("data"), &[rule], &[state]).is_err());
        assert!(validate(&home, &home).is_err());
        assert!(validate(&home, &home.join(".config")).is_err());
    }
    #[test]
    fn concurrent_identity_publication_never_exposes_a_partial_value() {
        let t = Temp::new();
        let path = t.0.join("identity");
        let gate = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let gate = gate.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    for _ in 0..20 {
                        identity_file(&path, b"one complete canonical path").unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(identity_file(&path, b"a different path with the same hash").is_err());
    }

    #[test]
    fn ambiguous_or_injected_rules_are_rejected() {
        assert!(parse("rw\trelative").is_err());
        assert!(parse("rw\t/a\nro\t/a/../a").is_err());
        assert!(parse("rw\t/a\t/b").is_err());
        assert!(parse("bogus\t/a").is_err());
    }
}

/// Instance setup runs as its subordinate root, but overlay work/copy-up
/// credentials must belong to the desktop user. Otherwise kernel-created
/// work directories become inaccessible to the host's ordinary cleanup.
/// Retain the setup capabilities for traversing protected keep directories.
pub fn with_fs_owner<T>(
    uid: u32,
    gid: u32,
    run: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    struct Restore {
        uid: u32,
        gid: u32,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restore this thread's previous filesystem credentials.
            unsafe {
                libc::setfsuid(self.uid);
                libc::setfsgid(self.gid);
            }
            crate::profile::raise_effective_capabilities();
        }
    }
    // SAFETY: filesystem credential calls take scalar IDs and act only on
    // the current setup thread; the guard restores them on every exit.
    let guard = unsafe {
        Restore {
            gid: libc::setfsgid(gid) as u32,
            uid: libc::setfsuid(uid) as u32,
        }
    };
    crate::profile::raise_effective_capabilities();
    // SAFETY: querying current filesystem IDs with an unmapped sentinel.
    if unsafe { (libc::setfsuid(u32::MAX), libc::setfsgid(u32::MAX)) } != (uid as i32, gid as i32) {
        return Err("не установить владельца файловых слоёв".into());
    }
    let result = run();
    drop(guard);
    result
}

/// Pin host sources and mount mutable layers once, before the instance's
/// HOME overlay can hide them. Launches only bind these views; they never
/// share an upper/work across independent overlay mounts (unsupported by
/// overlayfs), or mistake the HOME overlay for a real writable host path.
pub fn mount_shared(
    home: &Path,
    data: &Path,
    rules: &[Rule],
    protected: &[PathBuf],
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for m in prepare(home, data, rules, protected)? {
        let dir = m.upper.parent().ok_or("нет каталога слоя")?;
        let view = dir.join("view");
        fs::create_dir_all(&view).map_err(|e| e.to_string())?;
        let metadata = fs::metadata(&m.source).map_err(|e| e.to_string())?;
        let identity = format!("{}:{}", metadata.dev(), metadata.ino());
        fs::write(dir.join("source"), identity).map_err(|e| e.to_string())?;
        fs::write(
            dir.join("source-path"),
            m.source.as_os_str().as_encoded_bytes(),
        )
        .map_err(|e| e.to_string())?;
        fs::write(dir.join("mode"), m.rule.mode.word()).map_err(|e| e.to_string())?;
        if m.rule.mode != Mode::Overlay {
            crate::sys::mount(
                m.source.as_os_str(),
                &view,
                "",
                libc::MS_BIND | libc::MS_REC,
                "",
            )
            .map_err(|e| format!("не закрепить исходную папку {}: {e}", m.rule.path.display()))?;
            continue;
        }
        let options = crate::home_layer::overlay_options(&m.source, &m.upper, &m.work)
            .ok_or("путь не поддерживается overlayfs")?;
        crate::sys::mount(
            std::ffi::OsStr::new("overlay"),
            &view,
            "overlay",
            libc::MS_NOSUID | libc::MS_NODEV,
            &options,
        )
        .map_err(|e| format!("не смонтировать общий слой {}: {e}", m.rule.path.display()))?;
    }
    Ok(())
}

/// Verify this container's actual upper directory, not merely filesystem
/// type: the host's own HOME may itself already be an unrelated overlay.
pub fn home_layer_mounted(home: &Path, data: &Path) -> bool {
    let encode = |path: &Path| {
        path.to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
            .replace('\n', "\\012")
    };
    let upper = crate::home_layer::layer_dirs(data).0;
    let homes = [
        encode(home),
        encode(&fs::canonicalize(home).unwrap_or_else(|_| home.to_owned())),
    ];
    let uppers = [
        format!("upperdir={}", encode(&upper)),
        format!(
            "upperdir={}",
            encode(&fs::canonicalize(&upper).unwrap_or(upper))
        ),
    ];
    let Ok(info) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let Some(active) = info
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .nth(4)
                .is_some_and(|p| homes.iter().any(|h| p == h))
        })
        .last()
    else {
        return false;
    };
    active.split_once(" - ").is_some_and(|(_, tail)| {
        let fields: Vec<_> = tail.split_whitespace().collect();
        fields.first() == Some(&"overlay")
            && fields
                .get(2)
                .is_some_and(|opts| opts.split(',').any(|o| uppers.iter().any(|u| o == u)))
    })
}

pub fn prepare_for_launch(
    home: &Path,
    data: &Path,
    rules: &[Rule],
    protected: &[PathBuf],
    shared: bool,
) -> Result<Vec<Mount>, String> {
    use std::os::unix::fs::MetadataExt;
    let mut mounts = prepare(home, data, rules, protected)?;
    if !shared {
        return Ok(mounts);
    }
    let info = fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?;
    for m in &mut mounts {
        let dir = m.upper.parent().ok_or("нет каталога слоя")?;
        let view = dir.join("view");
        let encoded = view
            .to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
            .replace('\n', "\\012");
        let mounted = info.lines().any(|l| {
            l.split_whitespace().nth(4) == Some(encoded.as_str())
                && (m.rule.mode != Mode::Overlay
                    || l.split_once(" - ")
                        .is_some_and(|(_, fs)| fs.starts_with("overlay ")))
        });
        if !mounted && m.rule.mode != Mode::Overlay {
            // Legacy live grants may already expose the host filesystem.
            // Never mistake a directory in the HOME overlay for that source.
            if !home_layer_mounted(home, data)
                || fs::metadata(&m.source).map_err(|e| e.to_string())?.dev()
                    != fs::metadata(home).map_err(|e| e.to_string())?.dev()
            {
                continue;
            }
        }
        if !mounted
            || fs::read_to_string(dir.join("mode")).ok().as_deref() != Some(m.rule.mode.word())
        {
            return Err(format!(
                "общий слой {} не подготовлен: остановите контейнер и запустите снова",
                m.rule.path.display()
            ));
        }
        let source = fs::metadata(&m.source).map_err(|e| e.to_string())?;
        let same_path = fs::read(dir.join("source-path")).ok().as_deref()
            == Some(m.source.as_os_str().as_encoded_bytes());
        let same_inode = fs::read_to_string(dir.join("source")).ok().as_deref()
            == Some(format!("{}:{}", source.dev(), source.ino()).as_str());
        // A shared whole-home overlay changes the visible st_dev. The
        // pinned folder view still refers to the original host directory;
        // require its original canonical path instead of comparing devices
        // from two different filesystems. A path retarget requires restart.
        if !same_path || (!home_layer_mounted(home, data) && !same_inode) {
            return Err(format!(
                "исходная папка {} изменилась: перезапустите контейнер",
                m.rule.path.display()
            ));
        }
        if m.rule.mode != Mode::Overlay {
            let pinned = fs::metadata(&view).map_err(|e| e.to_string())?;
            if fs::read_to_string(dir.join("source")).ok().as_deref()
                != Some(format!("{}:{}", pinned.dev(), pinned.ino()).as_str())
            {
                return Err("закреплённый источник папки изменился".into());
            }
        }
        m.source = view;
        m.shared = true;
    }
    Ok(mounts)
}

#[cfg(test)]
mod shared_mount_tests {
    use super::*;
    use std::{ffi::OsStr, process::Command};
    #[test]
    #[ignore = "run in a private unshare --user --map-current-user --keep-caps --mount namespace"]
    fn concurrent_launches_use_the_same_folder_and_home_mounts() {
        let home = PathBuf::from(std::env::var("CW_FOLDER_TEST_HOME").unwrap());
        let data = home.join(".local/state/vpn-profiles/test");
        let project = home.join("Projects");
        for p in [
            project.join("shared/cache"),
            project.join("reference"),
            data.join("home"),
            home.join(".config/vpn-zones/containers/test"),
        ] {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(home.join(".config/vpn-zones/containers/test/perms"), "").unwrap();
        std::env::set_var("HOME", &home);
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");
        let rules = vec![
            Rule {
                path: project.clone(),
                mode: Mode::Overlay,
            },
            Rule {
                path: project.join("shared"),
                mode: Mode::Real,
            },
            Rule {
                path: project.join("shared/cache"),
                mode: Mode::Overlay,
            },
            Rule {
                path: project.join("reference"),
                mode: Mode::ReadOnly,
            },
        ];
        mount_shared(&home, &data, &rules, &[]).unwrap();
        let layer = std::env::var("CW_FOLDER_TEST_KIND").unwrap() == "layer";
        if layer {
            let kept = home
                .join(crate::home_layer::KEPT_STORAGE)
                .join("profiles/test");
            fs::create_dir_all(&kept).unwrap();
            crate::sys::mount(
                data.as_os_str(),
                &kept,
                "",
                libc::MS_BIND | libc::MS_REC,
                "",
            )
            .unwrap();
            crate::profile::mount_profile(&data, &[]).unwrap();
            assert!(
                home_layer_mounted(&home, &data),
                "cannot verify the instance's own upper directory"
            );
        }
        let mut children = Vec::new();
        let code = r#"from pathlib import Path
import sys,time,errno
p=Path(sys.argv[1]);me=sys.argv[2];other='two' if me=='one' else 'one'
(p/other).exists()
(p/me).write_text('layer')
(p/'shared'/me).write_text('real')
(p/'shared/cache'/me).write_text('cache')
(Path.home()/('root-'+me)).write_text('home')
try:(p/'reference/bad').write_text('bad')
except OSError as e:assert e.errno in (errno.EROFS,errno.EACCES)
else:raise AssertionError('read-only write')
deadline=time.monotonic()+20
while not (p/other).exists() or not (Path.home()/('root-'+other)).exists():
 assert time.monotonic()<deadline,'incoherent shared mount'
 time.sleep(.1)
assert (p/'shared/cache'/other).read_text()=='cache'
time.sleep(.2)
"#;
        for name in ["one", "two"] {
            // Like container-enter: each launch has its own mount
            // namespace, inheriting the same already-mounted views.
            let mut cmd = Command::new(std::env::var("CW_FOLDER_UNSHARE").unwrap());
            cmd.args(["--mount", "--propagation", "private", "--"])
                .arg(std::env::var("CW_FOLDER_CORE").unwrap());
            if layer {
                cmd.args([
                    OsStr::new("profile-run"),
                    OsStr::new("--home-shared"),
                    OsStr::new("--folder-shared"),
                    OsStr::new("--storage"),
                    data.as_os_str(),
                ]);
            } else {
                cmd.arg("profile-run")
                    .arg("--storage")
                    .arg(&data)
                    .args(["", "offline", "0", "", "--"])
                    .arg(std::env::var("CW_FOLDER_CORE").unwrap());
                cmd.args([
                    "fs-sandbox",
                    "--bwrap",
                    &std::env::var("CW_FOLDER_BWRAP").unwrap(),
                    "--dbus-proxy",
                    "/nonexistent",
                    "synthetic",
                    "--name",
                    "test",
                    "--folder-shared",
                    "on",
                ]);
            }
            for r in &rules {
                cmd.arg("--folder-rule")
                    .arg(format!("{}\t{}", r.mode.word(), r.path.display()));
            }
            if layer {
                cmd.arg(&data).args(["offline", "0", ""]);
            }
            cmd.arg("--")
                .arg(std::env::var("CW_FOLDER_PYTHON").unwrap())
                .args(["-c", code])
                .arg(&project)
                .arg(name);
            children.push(cmd.spawn().unwrap());
        }
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
    }
}
