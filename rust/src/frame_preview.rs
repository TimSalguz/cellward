//! A cosmetic preview lives only while its host editor owns a lease. No
//! persistent setting is replaced, including when the editor crashes.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const SUFFIX: &str = ".live-preview";

fn text(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(513)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= 512).then_some(text)
}

pub(crate) fn read(dir: &Path, name: &str) -> Option<String> {
    if !dir.is_absolute() {
        return None;
    }
    let raw = text(&dir.join(format!("{name}{SUFFIX}")))?;
    let (owner, value) = raw.split_once('\n')?;
    let mut fields = owner.split('\t');
    let pid = fields.next()?.parse::<i32>().ok().filter(|p| *p > 0)?;
    let stamp = fields.next()?;
    let lease = fields.next()?;
    if fields.next().is_some()
        || !lease.starts_with(&format!("_frame-preview-{pid}-"))
        || !lease
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || crate::sys::process_stamp(pid).as_deref() != Some(stamp)
        || text(&dir.join(lease)).as_deref() != Some(owner)
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

pub(crate) struct Session {
    dir: PathBuf,
    lease: PathBuf,
    owner: String,
    serial: u64,
}

impl Session {
    pub(crate) fn new(dir: &Path) -> io::Result<Self> {
        if !dir.is_absolute() {
            return Err(io::Error::other("preview needs an absolute config path"));
        }
        let pid = std::process::id();
        let stamp = crate::sys::process_stamp(pid as i32)
            .ok_or_else(|| io::Error::other("preview owner unavailable"))?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let name = format!("_frame-preview-{pid}-{nonce}");
        let owner = format!("{pid}\t{stamp}\t{name}");
        fs::create_dir_all(dir)?;
        let lease = dir.join(name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lease)?
            .write_all(owner.as_bytes())?;
        Ok(Self {
            dir: dir.to_owned(),
            lease,
            owner,
            serial: 0,
        })
    }

    pub(crate) fn set(&mut self, name: &str, value: &str) -> io::Result<()> {
        if !matches!(
            name,
            crate::frame::WIDTH_SETTING
                | crate::frame::RADIUS_SETTING
                | crate::frame::OUTER_RADIUS_SETTING
                | crate::frame::HOVER_EDGE_SETTING
                | crate::frame::RESIZE_CORNER_SETTING
        ) || value.len() > 64
            || value.chars().any(char::is_control)
        {
            return Err(io::Error::other("not a numeric frame preview"));
        }
        self.serial += 1;
        let tmp = self.dir.join(format!(
            "{}.{}",
            self.lease.file_name().unwrap().to_string_lossy(),
            self.serial
        ));
        let result = (|| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
                .write_all(format!("{}\n{value}", self.owner).as_bytes())?;
            fs::rename(&tmp, self.dir.join(format!("{name}{SUFFIX}")))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Only our unique lease: another editor may have replaced a value
        // file meanwhile. Removing its value would cancel its preview too.
        let _ = fs::remove_file(&self.lease);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_override_nix_but_cancel_never_rewrites_it_or_local_settings() {
        let base = std::env::temp_dir().join(format!(
            "cw-frame-preview-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(base.join("declared")).unwrap();
        crate::declared::declare(
            &base.join("declared").join(crate::frame::WIDTH_SETTING),
            "4",
        );
        let local = crate::frame::override_path(&base, crate::frame::WIDTH_SETTING);
        fs::write(&local, "6").unwrap();
        assert_eq!(crate::frame::width(&base).0, 6);
        let mut first = Session::new(&base).unwrap();
        first.set(crate::frame::WIDTH_SETTING, "1").unwrap();
        assert_eq!(crate::frame::width(&base).0, 1);
        let mut other = Session::new(&base).unwrap();
        other.set(crate::frame::WIDTH_SETTING, "2").unwrap();
        drop(first);
        assert_eq!(
            crate::frame::width(&base).0,
            2,
            "older editor cannot cancel the newer one"
        );
        assert!(other.set("network", "host").is_err());
        drop(other);
        assert_eq!(crate::frame::width(&base).0, 6);
        assert_eq!(fs::read_to_string(&local).unwrap(), "6");
        assert_eq!(
            fs::read_to_string(base.join("declared").join(crate::frame::WIDTH_SETTING)).unwrap(),
            "4"
        );
        fs::remove_dir_all(base).unwrap();
    }
}
