//! Live strict egress controller. Packet identity is minted before exec;
//! destination tuples are policy/display fields, never authorization keys.
use crate::netqueue::{driver::Driver, socket::Socket, Held, Ticket, Token};
use crate::verdicts::Verdict;
use std::collections::HashMap;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod archive;

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
    // Only a fresh registration/epoch resolves a live path. Queue rotation
    // preserves the kernel map; archive reads deliberately leave this empty.
    path: String,
    leaf: String,
    program: String,
    generation: u128,
    panel: Option<(i32, u64)>,
    token: Token,
    cgroup: u64,
    level: u8,
    epoch: u64,
}
pub struct Runtime {
    driver: Driver<Socket>,
    session: u128,
    revision: u64,
    archive: Arc<archive::Archive>,
    asker: crate::netask::Asker<Ticket>,
    pending: HashMap<Ticket, (Held, crate::flows::Key, Option<String>)>,
    config: PathBuf,
    dir: PathBuf,
    record: Option<String>,
    rules: crate::netrules::Rules,
    failed: bool,
    core: PathBuf,
    nft: PathBuf,
    space: OwnedFd,
}

impl Runtime {
    #[allow(clippy::too_many_arguments)]
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
        let mut driver = Driver::bind(
            crate::bridge::owner_socket(core, space)?,
            session,
            QUEUE,
            u64::from(epoch.n),
            1,
        )
        .map_err(|e| e.to_string())?;
        let archive = Arc::new(archive::Archive::create(dir, session).map_err(|e| e.to_string())?);
        attach_archive(&mut driver, &archive)?;
        let rules = load_rules(config, record.as_deref());
        let runtime = Self {
            driver,
            session,
            revision: 1,
            archive,
            asker,
            pending: HashMap::new(),
            config: config.into(),
            dir: dir.into(),
            record,
            rules,
            failed: false,
            core: core.into(),
            nft: nft.into(),
            space: space.try_clone().map_err(|e| e.to_string())?,
        };
        crate::bridge::owner_rules(
            core,
            nft,
            space,
            &classification(&[], epoch.level() + 1, false)?,
        )?;
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
        self.driver.has_ready() || self.driver.rotation_due()
    }

    /// Does not acquire the instance LOCK: enter holds it shared while
    /// waiting for this exact registration. The kernel peer, not the request,
    /// supplies the waiter identity; only its waiting fork can be registered.
    #[allow(clippy::too_many_arguments)]
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
        if path != format!("{}/{}", epoch.path, leaf) {
            return Err("child is not in its dedicated launch cgroup".into());
        }
        if !held.alive() || !peer.alive() || crate::sys::start_time(peer.pid) != Some(start) {
            return Err("launch generation changed".into());
        }
        let cgroup = fs::metadata(epoch.leaf_dir(&leaf))
            .map_err(|e| e.to_string())?
            .ino();
        if self
            .archive
            .contains_cgroup(cgroup)
            .map_err(|e| e.to_string())?
        {
            return Err("launch identity already registered".into());
        }
        let generation = (u128::from(peer.pid as u32) << 64) | u128::from(start);
        let token = self
            .driver
            .register(program.clone(), generation)
            .map_err(|e| format!("strict registry: {e:?}"))?;
        let panel = panel.and_then(|pid| crate::sys::start_time(pid).map(|stamp| (pid, stamp)));
        let mapping = Mapping {
            path: path.into(),
            leaf,
            program,
            generation,
            panel,
            token,
            cgroup,
            level: u8::try_from(epoch.level() + 1)
                .map_err(|_| "cgroup depth exceeds kernel limit")?,
            epoch: u64::from(epoch.n),
        };
        if let Err(error) = self.archive.append(&mapping) {
            self.fail();
            return Err(error.to_string());
        }
        // Do not re-resolve archived directories which may have been swept.
        // Existing rules retain the kernel birth identity after removal.
        let rule = format!(
            "add element inet {TABLE} launch_ids {{ {} }}\n",
            mapping_clause(&mapping)?
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
        if self.driver.rotation_due() {
            self.rotate_queue()?;
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
        let answers = self.asker.answered();
        // answered() can persist a rule. One coherent snapshot per intake
        // round avoids opening config files for every packet in a burst.
        let current = load_rules(&self.config, self.record.as_deref());
        for (ticket, verdict) in answers {
            if let Some((held, key, name)) = self.pending.remove(&ticket) {
                // answered() may have saved a permanent rule. Re-read before
                // emitting the kernel verdict, without trusting tuple caches.
                let permitted =
                    packet_verdict(&current, &key, name.as_deref(), &held.launch.program)
                        != Some(Verdict::Deny);
                self.driver
                    .decide(ticket, verdict == Verdict::Allow && permitted)
                    .map_err(|e| e.to_string())?;
            }
        }
        let names = crate::flows::read(&self.dir)
            .map(|(_, names)| names)
            .unwrap_or_default();
        let mut decisions = Vec::new();
        for held in self.driver.receive_round().map_err(|e| e.to_string())? {
            let Some(destination) = held.destination else {
                decisions.push((held.ticket, false));
                continue;
            };
            let key = crate::flows::Key {
                proto: destination.protocol,
                lport: destination.local_port,
                remote: destination.address,
                rport: destination.port,
            };
            let name = crate::flows::name_of(&names, &key.remote).map(str::to_owned);
            let verdict = packet_verdict(&current, &key, name.as_deref(), &held.launch.program);
            let verdict = if verdict.is_some() {
                verdict
            } else {
                let mapping = self
                    .archive
                    .read(held.ticket.token_mark())
                    .map_err(|e| e.to_string())?
                    .ok_or("held packet has no immutable archive record")?;
                if mapping.generation != held.launch.generation
                    || mapping.program != held.launch.program
                {
                    return Err("held packet archive identity changed".into());
                }
                self.asker.ask_held(
                    &held,
                    mapping.panel,
                    crate::netask::destination(&key, &names),
                )
            };
            if let Some(verdict) = verdict {
                decisions.push((held.ticket, verdict == Verdict::Allow));
            } else {
                self.pending.insert(held.ticket, (held, key, name));
            }
        }
        self.driver
            .decide_round(decisions)
            .map_err(|e| e.to_string())?;
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
            let count = self.archive.count();
            let mut mappings = Vec::new();
            for index in 1..=count {
                let mapping = self
                    .archive
                    .read(index)
                    .map_err(|e| e.to_string())?
                    .ok_or("missing launch archive row")?;
                // Already archived epochs are tombstones, not live groups.
                if mapping.epoch + 1 != u64::from(epoch.n) {
                    continue;
                }
                let path = epoch.leaf_dir(&mapping.leaf);
                if !path.is_dir() {
                    continue;
                }
                let token = self
                    .driver
                    .register(mapping.program.clone(), mapping.generation)
                    .map_err(|e| format!("strict registry: {e:?}"))?;
                let mapping = Mapping {
                    path: format!("{}/{}", epoch.path, mapping.leaf),
                    cgroup: fs::metadata(&path).map_err(|e| e.to_string())?.ino(),
                    epoch: u64::from(epoch.n),
                    token,
                    ..mapping
                };
                self.archive.append(&mapping).map_err(|e| e.to_string())?;
                mappings.push(mapping);
            }
            crate::bridge::owner_rules(
                core,
                nft,
                space,
                &classification(&mappings, epoch.level() + 1, true)?,
            )?;
            for mapping in &mappings {
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

    fn rotate_queue(&mut self) -> Result<(), String> {
        // Fence and ACK before destroying a queue. Unmatched/late packets
        // cannot slip through while the kernel queue ID counter resets.
        crate::bridge::owner_rules(&self.core, &self.nft, &self.space,
            &format!("add chain inet {TABLE} rotation {{ type filter hook output priority -6; policy drop; }}\n"))?;
        let mut bytes = [0; 16];
        crate::bridge::random_bytes(&mut bytes).map_err(|e| e.to_string())?;
        let id = u128::from_ne_bytes(bytes).max(1);
        if id == self.driver.session_id() {
            return Err("queue generation collision".into());
        }
        self.asker.rotate_session(self.driver.session_id(), id);
        self.pending.clear();
        self.driver.close();
        // The archive's registration session remains stable. Only packet/UI
        // tickets change generation; in-progress launch registrations keep
        // working across this internal queue rotation.
        let epoch = crate::epoch::read(&self.dir).ok_or("rotation has no network epoch")?;
        let mut driver = Driver::bind(
            crate::bridge::owner_socket(&self.core, &self.space)?,
            id,
            QUEUE,
            u64::from(epoch.n),
            self.revision,
        )
        .map_err(|e| e.to_string())?;
        attach_archive(&mut driver, &self.archive)?;
        self.driver = driver;
        crate::bridge::owner_rules(
            &self.core,
            &self.nft,
            &self.space,
            &format!("delete chain inet {TABLE} rotation\n"),
        )?;
        Ok(())
    }

    /// Host-only maintenance uses the same path as automatic counter
    /// rotation, so real kernel tests need not send a billion packets.
    pub(crate) fn maintenance_rotate(&mut self) -> Result<(), String> {
        if self.failed {
            return Err("strict controller is closed".into());
        }
        let result = self.rotate_queue();
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
    } else if crate::relay::to_forwarder(key) {
        // Preserve the explicit DNS-forwarder exception for an asking app.
        Some(Verdict::Allow)
    } else if rules.blocked(name, &key.remote) {
        Some(Verdict::Deny)
    } else {
        // The relay deliberately ignores some protocols for legacy gating.
        // A decoded strict packet must NEVER inherit that automatic allow.
        rules.decide(Some(program)).verdict()
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

fn attach_archive(
    driver: &mut Driver<Socket>,
    archive: &Arc<archive::Archive>,
) -> Result<(), String> {
    let count = archive.count();
    let archive = archive.clone();
    driver
        .set_archive(count, move |token| {
            Ok(archive.read(token)?.map(|m| crate::netqueue::Launch {
                program: m.program,
                generation: m.generation,
                epoch: m.epoch,
            }))
        })
        .map_err(|e| e.to_string())
}

fn classification(mappings: &[Mapping], level: u32, replace: bool) -> Result<String, String> {
    let mut text = if replace {
        format!("delete table inet {TABLE}\n")
    } else {
        String::new()
    };
    if !(1..=255).contains(&level) {
        return Err("invalid launch cgroup depth".into());
    }
    text.push_str(&format!(
        "table inet {TABLE} {{\n map launch_ids {{ typeof socket cgroupv2 level 0 : meta mark;\n"
    ));
    if !mappings.is_empty() {
        text.push_str("elements = { ");
        for (i, mapping) in mappings.iter().enumerate() {
            if u32::from(mapping.level) != level {
                return Err("mixed launch cgroup depth".into());
            }
            if i != 0 {
                text.push_str(", ");
            }
            text.push_str(&mapping_clause(mapping)?);
        }
        text.push_str(" }\n");
    }
    text.push_str(&format!(" }}\n chain output {{ type filter hook output priority -5; policy drop;\n meta mark set 0\n oifname \"lo\" accept\n icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept\n meta mark set socket cgroupv2 level {level} map @launch_ids\n meta mark != 0 queue num {QUEUE}\n counter drop\n }}\n}}\n"));
    if text.len() > 1024 * 1024 {
        return Err("strict rule capacity exhausted".into());
    }
    Ok(text)
}

fn mapping_clause(mapping: &Mapping) -> Result<String, String> {
    if mapping.cgroup == 0 || mapping.level == 0 || !crate::epoch::sane_path(&mapping.path) {
        return Err("invalid kernel cgroup identity".into());
    }
    // nftables <=1.1.6 interprets numeric cgroup map keys as paths. Resolve
    // the live group once, retaining its full-width kernel ID thereafter.
    Ok(format!(
        "\"{}\" : {}",
        mapping
            .path
            .strip_prefix('/')
            .ok_or("absolute cgroup path required")?,
        mapping.token.mark()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_never_inherits_legacy_ungated_protocol_allowance() {
        let root = std::env::temp_dir().join(format!("cw-strict-policy-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let rules = crate::netrules::Rules::template_only(&root);
        let key = crate::flows::Key {
            proto: 50,
            lport: 0,
            remote: "198.51.100.1".parse().unwrap(),
            rport: 0,
        };
        assert_eq!(
            rules.of_flow(&key, None, Some("test")),
            Some(Verdict::Allow)
        );
        assert_eq!(packet_verdict(&rules, &key, None, "test"), None);
        assert_eq!(
            packet_verdict(&rules, &key, None, DIAGNOSTIC),
            Some(Verdict::Deny)
        );
        fs::remove_dir_all(root).unwrap();
    }

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
        let rules = classification(&[], 2, false).unwrap();
        assert!(rules.contains("policy drop"));
        assert!(rules.find("meta mark set 0").unwrap() < rules.find("map @launch_ids").unwrap());
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
            cgroup: 0x1_0000_0001,
            level: 2,
            epoch: 1,
        };
        let clause = mapping_clause(&mapping).unwrap();
        assert!(clause.contains("a\\x2db.service"));
        assert!(!clause.contains("a\\\\x2db.service"));
        assert!(classification(&[mapping], 3, false).is_err());
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
            .write_all(classification(&[], 2, false).unwrap().as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }
}
