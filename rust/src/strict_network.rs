//! Live strict egress controller. Packet identity is minted before exec;
//! destination tuples are policy/display fields, never authorization keys.
use crate::netqueue::{driver::Driver, socket::Socket, Held, Ticket, Token};
use crate::verdicts::Verdict;
use std::collections::HashMap;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub const READY: &str = "strict-network";
pub const REQUIRED: &str = "strict-network-required";
pub const FLAG: &str = "strict_network";
const TABLE: &str = "cellward_owner";
const QUEUE: u16 = 713;
const DIAGNOSTIC: &str = "cellward-doctor-probe";

pub fn mode(dir: &Path) -> &'static str {
    if !dir.join(REQUIRED).exists() {
        "legacy"
    } else if dir.join(READY).is_file() {
        "strict"
    } else {
        "strict-failed"
    }
}

struct Mapping {
    path: String,
    leaf: String,
    program: String,
    generation: u128,
    panel: Option<(i32, u64)>,
    token: Token,
}
pub struct Runtime {
    driver: Driver<Socket>,
    session: u128,
    revision: u64,
    mappings: Vec<Mapping>,
    asker: crate::netask::Asker<Ticket>,
    pending: HashMap<Ticket, (Held, crate::flows::Key, Option<String>)>,
    config: PathBuf,
    dir: PathBuf,
    record: Option<String>,
    rules: crate::netrules::Rules,
    failed: bool,
}

impl Runtime {
    pub fn start(
        core: &Path,
        nft: &Path,
        space: &OwnedFd,
        epoch: &crate::epoch::Epoch,
        config: &Path,
        dir: &Path,
        asker: crate::netask::Asker<Ticket>,
        record: Option<String>,
    ) -> Result<Self, String> {
        let (probe, _) = UnixStream::pair().map_err(|e| e.to_string())?;
        authenticated_peer(&probe)
            .ok_or("strict registration requires SO_PEERPIDFD (Linux 6.5+)")?;
        let mut bytes = [0; 16];
        crate::bridge::random_bytes(&mut bytes).map_err(|e| e.to_string())?;
        let session = u128::from_ne_bytes(bytes).max(1);
        let driver = Driver::bind(
            crate::bridge::owner_socket(core, space)?,
            session,
            QUEUE,
            u64::from(epoch.n),
            1,
        )
        .map_err(|e| e.to_string())?;
        let rules = load_rules(config, record.as_deref());
        let runtime = Self {
            driver,
            session,
            revision: 1,
            mappings: Vec::new(),
            asker,
            pending: HashMap::new(),
            config: config.into(),
            dir: dir.into(),
            record,
            rules,
            failed: false,
        };
        crate::bridge::owner_rules(core, nft, space, &classification(&[], false)?)?;
        fs::write(dir.join(READY), format!("{session:032x}\n")).map_err(|e| e.to_string())?;
        Ok(runtime)
    }

    pub fn queue_fd(&self) -> Option<RawFd> {
        self.driver.fd()
    }
    pub fn ui_fd(&self) -> RawFd {
        self.asker.fd()
    }
    pub fn ready(&self) -> bool {
        self.driver.has_ready()
    }

    /// Does not acquire the instance LOCK: enter holds it shared while
    /// waiting for this exact registration. The kernel peer, not the request,
    /// supplies the waiter identity; only its waiting fork can be registered.
    pub fn register(
        &mut self,
        conn: &UnixStream,
        line: &str,
        epoch: &crate::epoch::Epoch,
        registry: &Path,
        core: &Path,
        nft: &Path,
        space: &OwnedFd,
    ) -> Result<(), String> {
        if self.failed {
            return Err("strict controller failed; restart the instance".into());
        }
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        let [kind @ ("REGISTER" | "DIAGNOSTIC"), session, child] = words.as_slice() else {
            return Err("invalid registration".into());
        };
        if u128::from_str_radix(session, 16).ok() != Some(self.session) {
            return Err("stale strict controller".into());
        }
        let child: i32 = child
            .parse()
            .ok()
            .filter(|p| *p > 1)
            .ok_or("invalid child")?;
        if crate::bridge::peer_uid(conn.as_raw_fd()) != Some(unsafe { libc::getuid() }) {
            return Err("foreign registration uid".into());
        }
        let peer = authenticated_peer(conn).ok_or("registration peer cannot be kernel-pinned")?;
        // Namespace links are ptrace-protected for this non-dumpable waiter.
        // Authority is the kernel-pinned peer, live registry generation and
        // its direct child in the EXACT epoch-root launch cgroup. Apps cannot
        // create a sibling there: cgroupfs is covered, and a newly mounted
        // cgroup namespace is rooted below their existing launch cgroup.
        let start = crate::sys::start_time(peer.pid).ok_or("waiter generation missing")?;
        let held = crate::origin::Peer::of_pid(child).ok_or("child exited")?;
        if crate::sys::parent_of(child) != Some(peer.pid) {
            return Err("not this waiter's child".into());
        }
        // Diagnostics gain no IP permission, even with a global allow rule.
        // A caller cannot turn this into an arbitrary application allowance.
        let (program, panel) = if *kind == "DIAGNOSTIC" {
            (DIAGNOSTIC.to_owned(), None)
        } else {
            let (program, panel) = registered_launch(registry, peer.pid)
                .ok_or("launch is not registered on the host")?;
            (program, Some(panel))
        };
        let leaf = crate::epoch::leaf_name(peer.pid, start);
        let cg = fs::read_to_string(format!("/proc/{child}/cgroup")).map_err(|e| e.to_string())?;
        let path = crate::kill::cgroup_of(&cg).ok_or("no child cgroup")?;
        let leaf = if path == format!("{}/{}", epoch.path, leaf) {
            leaf
        } else if path == format!("{}/denied/{}", epoch.path, leaf) {
            crate::epoch::denied_leaf(&leaf)
        } else {
            return Err("child is not in its dedicated launch cgroup".into());
        };
        if !held.alive() || !peer.alive() || crate::sys::start_time(peer.pid) != Some(start) {
            return Err("launch generation changed".into());
        }
        if self.mappings.iter().any(|m| m.path == path) {
            return Err("launch identity already registered".into());
        }
        let generation = (u128::from(peer.pid as u32) << 64) | u128::from(start);
        let token = self
            .driver
            .register(program.clone(), generation)
            .map_err(|e| format!("strict registry: {e:?}"))?;
        let panel = panel.and_then(|pid| crate::sys::start_time(pid).map(|stamp| (pid, stamp)));
        self.mappings.push(Mapping {
            path: path.into(),
            leaf,
            program,
            generation,
            panel,
            token,
        });
        // Do not re-resolve archived directories which may have been swept.
        // Existing rules retain the kernel birth identity after removal.
        let rule = format!(
            "add rule inet {TABLE} launches {}\n",
            mapping_clause(self.mappings.last().unwrap())?
        );
        let result = crate::bridge::owner_rules(core, nft, space, &rule).and_then(|()| {
            self.driver
                .activate_after_mapping_ack(token)
                .map_err(|e| format!("activation: {e:?}"))
        });
        if result.is_err() {
            self.fail();
        }
        result
    }

    pub fn handle(&mut self) -> Result<(), String> {
        let result = self.handle_inner();
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn handle_inner(&mut self) -> Result<(), String> {
        if self.failed {
            return Ok(());
        }
        let rules = load_rules(&self.config, self.record.as_deref());
        if rules != self.rules {
            self.asker.cancel_all();
            self.pending.clear();
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or("policy generation exhausted")?;
            self.driver
                .change_policy(self.revision)
                .map_err(|e| e.to_string())?;
            self.rules = rules;
        }
        for (ticket, verdict) in self.asker.answered() {
            if let Some((held, key, name)) = self.pending.remove(&ticket) {
                // answered() may have saved a permanent rule. Re-read before
                // emitting the kernel verdict, without trusting tuple caches.
                let rules = load_rules(&self.config, self.record.as_deref());
                let permitted = packet_verdict(&rules, &key, name.as_deref(), &held.launch.program)
                    != Some(Verdict::Deny);
                self.driver
                    .decide(ticket, verdict == Verdict::Allow && permitted)
                    .map_err(|e| e.to_string())?;
            }
        }
        let names = crate::flows::read(&self.dir)
            .map(|(_, names)| names)
            .unwrap_or_default();
        for held in self.driver.receive().map_err(|e| e.to_string())? {
            let Some(destination) = held.destination else {
                self.driver
                    .decide(held.ticket, false)
                    .map_err(|e| e.to_string())?;
                continue;
            };
            let key = crate::flows::Key {
                proto: destination.protocol,
                lport: destination.local_port,
                remote: destination.address,
                rport: destination.port,
            };
            let name = crate::flows::name_of(&names, &key.remote).map(str::to_owned);
            let rules = load_rules(&self.config, self.record.as_deref());
            let verdict = packet_verdict(&rules, &key, name.as_deref(), &held.launch.program);
            let verdict = verdict.or_else(|| {
                let panel = self
                    .mappings
                    .iter()
                    .find(|m| {
                        m.generation == held.launch.generation && m.program == held.launch.program
                    })
                    .and_then(|m| m.panel);
                self.asker
                    .ask_held(&held, panel, crate::netask::destination(&key, &names))
            });
            if let Some(verdict) = verdict {
                self.driver
                    .decide(held.ticket, verdict == Verdict::Allow)
                    .map_err(|e| e.to_string())?;
            } else {
                self.pending.insert(held.ticket, (held, key, name));
            }
        }
        Ok(())
    }

    pub fn renew(
        &mut self,
        epoch: &crate::epoch::Epoch,
        core: &Path,
        nft: &Path,
        space: &OwnedFd,
    ) -> Result<(), String> {
        self.asker.cancel_all();
        self.pending.clear();
        let result = (|| {
            self.driver
                .change_epoch(u64::from(epoch.n))
                .map_err(|e| e.to_string())?;
            let old = std::mem::take(&mut self.mappings);
            for mapping in old {
                let path = epoch.leaf_dir(&mapping.leaf);
                if !path.is_dir() {
                    continue;
                }
                let token = self
                    .driver
                    .register(mapping.program.clone(), mapping.generation)
                    .map_err(|e| format!("strict registry: {e:?}"))?;
                self.mappings.push(Mapping {
                    path: format!("{}/{}", epoch.path, mapping.leaf),
                    token,
                    ..mapping
                });
            }
            crate::bridge::owner_rules(core, nft, space, &classification(&self.mappings, true)?)?;
            for mapping in &self.mappings {
                self.driver
                    .activate_after_mapping_ack(mapping.token)
                    .map_err(|e| format!("activation: {e:?}"))?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }

    pub fn fail(&mut self) {
        self.failed = true;
        self.asker.cancel_all();
        self.pending.clear();
        self.driver.close();
        let _ = fs::remove_file(self.dir.join(READY));
    }
}

fn load_rules(config: &Path, record: Option<&str>) -> crate::netrules::Rules {
    record.map_or_else(
        || crate::netrules::Rules::template_only(config),
        |r| crate::netrules::Rules::load(config, r),
    )
}

fn packet_verdict(
    rules: &crate::netrules::Rules,
    key: &crate::flows::Key,
    name: Option<&str>,
    program: &str,
) -> Option<Verdict> {
    if program == DIAGNOSTIC || rules.decide(Some(program)) == crate::netrules::Rule::Deny {
        Some(Verdict::Deny)
    } else {
        rules.of_flow(key, name, Some(program))
    }
}

fn authenticated_peer(conn: &UnixStream) -> Option<crate::origin::Peer> {
    let pid = crate::sys::peer_pid(conn.as_raw_fd())?;
    let mut fd = -1i32;
    let mut len = std::mem::size_of_val(&fd) as libc::socklen_t;
    // No pidfd_open-by-PID fallback: credentials of a dead Unix peer must
    // never be rebound to a newly reused numeric PID.
    if unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            std::ptr::from_mut(&mut fd).cast(),
            &mut len,
        )
    } != 0
        || fd < 0
    {
        return None;
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    if len as usize != std::mem::size_of_val(&fd) {
        return None;
    }
    let peer = crate::origin::Peer {
        pid,
        pidfd,
        mnt: None,
    };
    if !peer.alive() {
        return None;
    }
    Some(peer)
}

/// Registry PID alone is insufficient. Only a live recorded generation and
/// an unambiguous launcher key may become an authoritative launch identity.
fn registered_launch(registry: &Path, pid: i32) -> Option<(String, i32)> {
    // Start stamps are global: .running/.started, not a per-container subdir.
    let started = registry.parent()?;
    let mut launches: HashMap<i32, Option<String>> = HashMap::new();
    for entry in fs::read_dir(registry).ok()?.flatten() {
        let key = entry.file_name().to_str()?.to_owned();
        if key.starts_with('.') {
            continue;
        }
        let Ok(text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for record in text.lines().filter_map(crate::registry::parse_record) {
            if !crate::registry::launched(started, record.pid) {
                continue;
            }
            match launches.entry(record.pid) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(Some(key.clone()));
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    if e.get().as_ref() != Some(&key) {
                        e.insert(None);
                    }
                }
            }
        }
    }
    let mut at = pid;
    for _ in 0..64 {
        let peer = crate::origin::Peer::of_pid(at)?;
        if let Some(key) = launches.get(&at) {
            let key = key.clone()?;
            return (peer.alive() && crate::registry::launched(started, at)).then_some((key, at));
        }
        let parent = crate::sys::parent_of(at)?;
        if !peer.alive() || parent <= 1 {
            return None;
        }
        at = parent;
    }
    None
}

fn classification(mappings: &[Mapping], replace: bool) -> Result<String, String> {
    let mut text = if replace {
        format!("delete table inet {TABLE}\n")
    } else {
        String::new()
    };
    text.push_str(&format!("table inet {TABLE} {{ chain launches {{\n"));
    for mapping in mappings {
        text.push_str(&mapping_clause(mapping)?);
        text.push('\n');
    }
    text.push_str(" }\n chain output { type filter hook output priority -5; policy drop;\n meta mark set 0\n oifname \"lo\" accept\n icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n jump launches\n counter drop\n }\n}\n");
    if text.len() > 1024 * 1024 {
        return Err("strict rule capacity exhausted".into());
    }
    Ok(text)
}

fn mapping_clause(mapping: &Mapping) -> Result<String, String> {
    if !crate::epoch::sane_path(&mapping.path) {
        return Err("invalid launch cgroup path".into());
    }
    let path = mapping
        .path
        .strip_prefix('/')
        .ok_or("absolute cgroup path required")?;
    let level = mapping.path.split('/').filter(|p| !p.is_empty()).count();
    Ok(format!(
        "socket cgroupv2 level {level} \"{path}\" meta mark set {} queue num {QUEUE}",
        mapping.token.mark()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_registry_requires_a_live_generation_and_unique_launcher_key() {
        let root = std::env::temp_dir().join(format!("cw-strict-registry-{}", std::process::id()));
        let registry = root.join(".running/work");
        fs::create_dir_all(&registry).unwrap();
        let pid = std::process::id() as i32;
        fs::write(registry.join("helium"), format!("{pid} host work\n")).unwrap();
        assert!(registered_launch(&registry, pid).is_none());
        crate::registry::note_start(registry.parent().unwrap(), pid, false).unwrap();
        assert_eq!(
            registered_launch(&registry, pid),
            Some(("helium".into(), pid))
        );
        fs::write(registry.join("other"), format!("{pid} host work\n")).unwrap();
        assert!(
            registered_launch(&registry, pid).is_none(),
            "ambiguous program accepted"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn classifier_drops_unregistered_egress_and_clears_application_marks_first() {
        let rules = classification(&[], false).unwrap();
        assert!(rules.contains("policy drop"));
        assert!(rules.find("meta mark set 0").unwrap() < rules.find("jump launches").unwrap());
        assert!(!rules.contains("bypass"));
        assert!(!rules.contains("policy accept"));
        assert!(rules.contains("counter drop"));
        let mut session = crate::netqueue::Session::new(1, QUEUE, 1, 1).unwrap();
        let token = session.register("test".into(), 1).unwrap();
        let mapping = Mapping {
            path: "/unit@a\\x2db.service/e1/l1-1".into(),
            leaf: "l1-1".into(),
            program: "test".into(),
            generation: 1,
            panel: None,
            token,
        };
        let clause = mapping_clause(&mapping).unwrap();
        // nft's cgroup path token preserves literal systemd backslashes.
        // Doubling them changes the filesystem path and fails resolution.
        assert!(clause.contains("a\\x2db.service"));
        assert!(!clause.contains("a\\\\x2db.service"));
    }

    #[test]
    #[ignore = "explicit kernel preflight in a disposable user/net namespace"]
    fn classifier_is_accepted_by_nft_in_a_disposable_namespace() {
        use std::io::Write;
        let mut child = std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "--",
                "nft",
                "-c",
                "-f",
                "-",
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(classification(&[], false).unwrap().as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }
}
