//! The task manager's view of the containers (`cellward tasks`): each
//! instance's launches — by the cgroup of each one's (`crate::epoch`,
//! `e<N>/l<waiter>-<start>`) — and their processes, with what they use.
//!
//! **Read without privileges, and without cgroup controllers.** Who is in a
//! launch: its cgroup's `cgroup.procs`. What each process uses: its
//! `/proc/<pid>/stat` (CPU time) and `status` (resident memory), which the
//! user reads also of a process that closes its descriptors. Resident sizes
//! are summed, so memory shared between a launch's processes counts more
//! than once — what `top` does too; a launch's `memory.current` needs the
//! memory controller in the instance's tree, which would forbid a process
//! in the epoch itself (`crate::epoch`'s fallback): not now.
//!
//! **What can be done.** A launch paused and resumed (`cgroup.freeze` of its
//! cgroup) or ended (`cgroup.kill`): every process of it at once, a child
//! forked meanwhile too. The user's own cgroups; a program in a container
//! cannot reach them — cgroupfs is covered there.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::tools::Tools;

/// One process of a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: i32,
    pub comm: String,
    /// Resident memory, in KiB (`VmRSS`).
    pub rss_kib: u64,
    /// CPU time used so far, in clock ticks (`utime + stime`).
    pub ticks: u64,
}

/// One launch of an instance: its cgroup and what is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// Its cgroup's name (`crate::epoch::leaf_name`).
    pub leaf: String,
    /// Its program's key in the registry, when its launch is still known.
    pub program: Option<String>,
    /// That program's name for the person (`.labels/<key>`).
    pub label: Option<String>,
    /// Paused (`cgroup.freeze`).
    pub frozen: bool,
    pub procs: Vec<Proc>,
}

impl Launch {
    pub fn rss_kib(&self) -> u64 {
        self.procs.iter().map(|p| p.rss_kib).sum()
    }

    pub fn ticks(&self) -> u64 {
        self.procs.iter().map(|p| p.ticks).sum()
    }
}

/// One instance and its launches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub network: String,
    pub launches: Vec<Launch>,
}

/// `utime + stime` of a `stat` text (after the name, which may hold
/// anything, a `)` too).
pub fn ticks_of(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After the name: state is field 3, utime 14 and stime 15 — here 0, 11, 12.
    Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
}

/// `VmRSS` of a `status` text, in KiB; 0 for a process with none (a
/// zombie, a kernel thread).
pub fn rss_of(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// A process as the user may read it; `None` once it is gone.
fn proc_of(pid: i32) -> Option<Proc> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    Some(Proc {
        pid,
        comm,
        rss_kib: rss_of(&status),
        ticks: ticks_of(&stat).unwrap_or(0),
    })
}

/// Every running instance, its launches and their processes, now.
pub fn snapshot(tools: &Tools) -> Vec<Instance> {
    crate::instance::running(&tools.state)
        .into_iter()
        .map(|i| {
            let registry = tools
                .state
                .join(".running")
                .join(crate::instance::container_of(&i.id).unwrap_or(crate::registry::MAIN));
            let launches = match crate::epoch::read(&i.dir) {
                Some(epoch) => crate::epoch::leaves(&epoch.dir())
                    .into_iter()
                    .map(|leaf| launch_of(tools, &registry, &epoch.leaf_dir(&leaf), leaf))
                    .filter(|l| !l.procs.is_empty())
                    .collect(),
                None => Vec::new(),
            };
            Instance {
                id: i.id,
                network: i.network,
                launches,
            }
        })
        .collect()
}

fn launch_of(tools: &Tools, registry: &Path, dir: &Path, leaf: String) -> Launch {
    let procs: Vec<Proc> =
        crate::epoch::procs_of(&fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default())
            .into_iter()
            .filter_map(proc_of)
            .collect();
    let program = crate::epoch::leaf_of(&leaf)
        .filter(|(waiter, start)| crate::sys::start_time(*waiter) == Some(*start))
        .and_then(|(waiter, _)| crate::owners::launch_of(registry, waiter))
        .map(|(key, _)| key);
    let label = program
        .as_ref()
        .and_then(|key| crate::cli::read_setting(&tools.state.join(".labels").join(key)));
    let frozen = fs::read_to_string(dir.join("cgroup.events"))
        .is_ok_and(|t| t.lines().any(|l| l.trim() == "frozen 1"));
    Launch {
        leaf,
        program,
        label,
        frozen,
        procs,
    }
}

/// The cgroup of launch `leaf` of instance `id`, in its current epoch:
/// `None` for a name no launch's, or no such instance or epoch.
pub fn leaf_dir(tools: &Tools, id: &str, leaf: &str) -> Option<PathBuf> {
    if !crate::instance::valid_id(id) || !crate::epoch::is_leaf(leaf) {
        return None;
    }
    let epoch = crate::epoch::read(&crate::instance::dir(&tools.state, id))?;
    let dir = epoch.leaf_dir(leaf);
    dir.is_dir().then_some(dir)
}

/// What can be done to a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Pause,
    Resume,
    Kill,
}

impl Act {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "pause" => Some(Self::Pause),
            "resume" => Some(Self::Resume),
            "kill" => Some(Self::Kill),
            _ => None,
        }
    }
}

/// `act` done to the launch whose cgroup is `dir`.
pub fn act(dir: &Path, act: Act) -> std::io::Result<()> {
    match act {
        Act::Pause => fs::write(dir.join("cgroup.freeze"), "1"),
        Act::Resume => fs::write(dir.join("cgroup.freeze"), "0"),
        Act::Kill => {
            // Thawed first: a frozen process takes a SIGKILL only once it
            // runs again.
            let _ = fs::write(dir.join("cgroup.freeze"), "0");
            fs::write(dir.join("cgroup.kill"), "1")
        }
    }
}

/// Clock ticks a second (`sysconf(_SC_CLK_TCK)`).
pub fn ticks_per_second() -> u64 {
    // SAFETY: sysconf takes an integer and returns one.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 {
        t as u64
    } else {
        100
    }
}

/// CPU use of each launch between two snapshots `seconds` apart, in percent
/// of one core: by `(instance, leaf)`.
pub fn cpu_between(
    before: &[Instance],
    after: &[Instance],
    seconds: f64,
) -> HashMap<(String, String), f64> {
    let then: HashMap<(&str, &str), u64> = before
        .iter()
        .flat_map(|i| {
            i.launches
                .iter()
                .map(move |l| ((i.id.as_str(), l.leaf.as_str()), l.ticks()))
        })
        .collect();
    let hz = ticks_per_second() as f64;
    let then = &then;
    after
        .iter()
        .flat_map(|i| {
            i.launches.iter().map(move |l| {
                let was = then.get(&(i.id.as_str(), l.leaf.as_str())).copied();
                let used = was.map_or(0, |w| l.ticks().saturating_sub(w));
                (
                    (i.id.clone(), l.leaf.clone()),
                    if seconds > 0.0 {
                        used as f64 / hz / seconds * 100.0
                    } else {
                        0.0
                    },
                )
            })
        })
        .collect()
}

/// The snapshot as JSON, with each launch's CPU use where known.
pub fn json(instances: &[Instance], cpu: &HashMap<(String, String), f64>) -> String {
    use crate::status::string;
    let launch = |id: &str, l: &Launch| {
        let procs: Vec<String> = l
            .procs
            .iter()
            .map(|p| {
                format!(
                    "{{\"pid\":{},\"comm\":{},\"rss_kib\":{}}}",
                    p.pid,
                    string(&p.comm),
                    p.rss_kib
                )
            })
            .collect();
        format!(
            "{{\"leaf\":{},\"program\":{},\"label\":{},\"frozen\":{},\"rss_kib\":{},\"cpu\":{},\"procs\":[{}]}}",
            string(&l.leaf),
            l.program.as_deref().map_or("null".to_owned(), string),
            l.label.as_deref().map_or("null".to_owned(), string),
            l.frozen,
            l.rss_kib(),
            cpu.get(&(id.to_owned(), l.leaf.clone()))
                .map_or("null".to_owned(), |c| format!("{c:.1}")),
            procs.join(",")
        )
    };
    let items: Vec<String> = instances
        .iter()
        .map(|i| {
            let launches: Vec<String> = i.launches.iter().map(|l| launch(&i.id, l)).collect();
            format!(
                "{{\"id\":{},\"network\":{},\"launches\":[{}]}}",
                string(&i.id),
                string(&i.network),
                launches.join(",")
            )
        })
        .collect();
    format!("{{\"instances\":[{}]}}", items.join(","))
}

/// `cellward tasks [--json] [--watch <ms>]` and `cellward tasks
/// pause|resume|kill <instance> <launch>`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    const USAGE: &str = "cellward tasks [--json] [--watch <мс>]\n\
                         cellward tasks pause|resume|kill <экземпляр> <запуск>";
    let words: Vec<&str> = match args.iter().map(|a| a.to_str()).collect::<Option<_>>() {
        Some(w) => w,
        None => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    if let [verb, id, leaf] = words.as_slice() {
        if let Some(what) = Act::parse(verb) {
            let Some(dir) = leaf_dir(tools, id, leaf) else {
                eprintln!("нет запуска {leaf} у экземпляра {id}");
                return 1;
            };
            return match act(&dir, what) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("не вышло: {e}");
                    1
                }
            };
        }
    }
    let mut as_json = false;
    let mut watch = None;
    let mut rest = words.iter();
    while let Some(w) = rest.next() {
        match *w {
            "--json" => as_json = true,
            "--watch" => match rest.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(ms) if ms >= 200 => watch = Some(ms),
                _ => {
                    eprintln!("{USAGE}");
                    return 2;
                }
            },
            _ => {
                eprintln!("{USAGE}");
                return 2;
            }
        }
    }
    let interval = std::time::Duration::from_millis(watch.unwrap_or(1000));
    let mut before = snapshot(tools);
    let mut at = std::time::Instant::now();
    loop {
        std::thread::sleep(interval);
        let after = snapshot(tools);
        let cpu = cpu_between(&before, &after, at.elapsed().as_secs_f64());
        at = std::time::Instant::now();
        if as_json {
            println!("{}", json(&after, &cpu));
        } else {
            print_table(&after, &cpu);
        }
        if watch.is_none() {
            return 0;
        }
        before = after;
    }
}

fn print_table(instances: &[Instance], cpu: &HashMap<(String, String), f64>) {
    for i in instances {
        println!("{} · {}", i.id, i.network);
        for l in &i.launches {
            let name = l.label.as_deref().or(l.program.as_deref()).unwrap_or("?");
            println!(
                "  {name}{} · {} МБ · ЦП {} · процессов {}",
                if l.frozen { " (на паузе)" } else { "" },
                l.rss_kib() / 1024,
                cpu.get(&(i.id.clone(), l.leaf.clone()))
                    .map_or("?".to_owned(), |c| format!("{c:.0}%")),
                l.procs.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_processs_use_is_read_from_proc() {
        let stat = "4242 (a (weird) name) S 1 2 3 4 5 6 7 8 9 10 150 50 0 0 20 0 1 0 999";
        assert_eq!(ticks_of(stat), Some(200));
        assert_eq!(ticks_of("4242 (short) S 1"), None);
        assert_eq!(rss_of("Name:\tx\nVmRSS:\t  20480 kB\n"), 20480);
        assert_eq!(rss_of("Name:\tkworker\n"), 0);
        // This process, as the snapshot reads it.
        let me = proc_of(std::process::id() as i32).unwrap();
        assert!(me.rss_kib > 0 && !me.comm.is_empty());
    }

    #[test]
    fn cpu_is_ticks_between_two_looks() {
        let one = |ticks: u64| {
            vec![Instance {
                id: "work".into(),
                network: "nl".into(),
                launches: vec![Launch {
                    leaf: "l1-2".into(),
                    program: None,
                    label: None,
                    frozen: false,
                    procs: vec![Proc {
                        pid: 1,
                        comm: "x".into(),
                        rss_kib: 10,
                        ticks,
                    }],
                }],
            }]
        };
        let hz = ticks_per_second();
        let cpu = cpu_between(&one(0), &one(hz), 2.0);
        assert_eq!(cpu[&("work".to_owned(), "l1-2".to_owned())].round(), 50.0);
        let json = json(&one(0), &cpu);
        assert!(
            json.contains("\"leaf\":\"l1-2\"") && json.contains("\"cpu\":50.0"),
            "{json}"
        );
        assert_eq!(Act::parse("kill"), Some(Act::Kill));
        assert_eq!(Act::parse("rm"), None);
    }
}
