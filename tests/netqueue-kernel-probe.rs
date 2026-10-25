//! Explicit disposable-user+netns probe, never a host firewall operation.
//! Build separately with libc; this does not require rebuilding all of core.
#[path = "../rust/src/netqueue.rs"]
pub mod netqueue;
use netqueue::{socket, wire};
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn checked(command: &str, args: &[&str], input: Option<&str>) -> io::Result<()> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()?;
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    if !child.wait()?.success() {
        return Err(io::Error::other(format!("{command} failed")));
    }
    Ok(())
}

fn ack(socket: &socket::Socket, sequence: u32) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        socket.wait(deadline.saturating_duration_since(Instant::now()))?;
        if let Some(messages) = socket.receive()? {
            if messages.len() != 1 {
                return Err(io::Error::other("unexpected ACK batch"));
            }
            return match messages[0] {
                wire::Message::Ack {
                    sequence: got,
                    errno: 0,
                } if got == sequence => Ok(()),
                wire::Message::Ack { errno, .. } if errno < 0 => {
                    Err(io::Error::from_raw_os_error(-errno))
                }
                _ => Err(io::Error::other("wrong kernel ACK")),
            };
        }
    }
}

fn main() -> io::Result<()> {
    let mode = std::env::args().nth(1);
    if matches!(mode.as_deref(), Some("send-once" | "send-marked")) {
        let to = std::env::args()
            .nth(2)
            .ok_or_else(|| io::Error::other("missing destination"))?;
        let to: SocketAddr = to.parse().map_err(io::Error::other)?;
        let sender = UdpSocket::bind(if to.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })?;
        if mode.as_deref() == Some("send-marked") {
            let mark = 0xf0f0u32;
            if unsafe {
                libc::setsockopt(
                    sender.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    std::ptr::from_ref(&mark).cast(),
                    std::mem::size_of_val(&mark) as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        sender.send_to(b"owner-proof", to)?;
        return Ok(());
    }
    // Refuse accidental execution in the host's user/net namespaces. No
    // privilege escalation or persistent service is part of this probe.
    let expected = std::env::var("CELLWARD_PROBE_OUTER_NETNS")
        .map_err(|_| io::Error::other("run through the private-netns wrapper"))?;
    let net = std::fs::read_link("/proc/self/ns/net")?;
    if net.to_string_lossy() == expected {
        return Err(io::Error::other("refusing host network namespace"));
    }
    let mapping = std::fs::read_to_string("/proc/self/uid_map")?;
    let map: Vec<_> = mapping.split_whitespace().collect();
    if map.len() != 3 || map[0] != "0" || map[1] == "0" || map[2] != "1" {
        return Err(io::Error::other(
            "expected a disposable single-user mapping",
        ));
    }
    let interfaces = std::fs::read_to_string("/proc/self/net/dev")?;
    if interfaces.lines().skip(2).any(|line| {
        line.split(':')
            .next()
            .is_none_or(|name| name.trim() != "lo")
    }) {
        return Err(io::Error::other("unexpected network interface"));
    }

    // The invoking Cellward container intentionally hides cgroupfs. Create
    // a PRIVATE mount namespace and cgroup namespace rooted at our current
    // cgroup; mount that view READ-ONLY, solely for nft's cgroup-id resolver.
    // No cgroup is created, moved, configured or written on the host.
    if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/sys/fs/cgroup".as_ptr(),
            c"cgroup2".as_ptr(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    let nft =
        std::env::var("CELLWARD_PROBE_NFT").map_err(|_| io::Error::other("missing nft path"))?;
    let ip = std::env::var("CELLWARD_PROBE_IP").map_err(|_| io::Error::other("missing ip path"))?;
    checked(&ip, &["link", "set", "lo", "up"], None)?;
    let queue = 712;
    let collector = socket::Socket::open_here()?;
    collector.send(&wire::bind(queue, 1, 64).map_err(|e| io::Error::other(format!("{e:?}")))?)?;
    ack(&collector, 1)?;
    let ipv6 = mode.as_deref() == Some("ipv6");
    let receiver = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })?;
    receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut session = netqueue::Session::new(123, queue, 1, 1).unwrap();
    let token = session.register("short-udp".into(), 10).unwrap();
    // Actual socket-cgroup matching, not an application-provided SO_MARK.
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
    let path = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("cgroup v2 required"))?;
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| io::Error::other("invalid test cgroup"))?;
    if relative
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || "/_.:@-".contains(c)))
    {
        return Err(io::Error::other("unexpected cgroup path"));
    }
    let level = if relative.is_empty() {
        0
    } else {
        relative.split('/').count()
    };
    let relative = if relative.is_empty() { "/" } else { relative };
    let rules = format!("table inet cellward_owner_probe {{\n chain output {{\n type filter hook output priority -5; policy accept;\n udp dport {} meta mark set 0 socket cgroupv2 level {level} \"{relative}\" meta mark set {} queue num {queue}\n }}\n}}\n", receiver.local_addr()?.port(), token.mark());
    checked(&nft, &["-f", "-"], Some(&rules))?;
    session.activate(123, token).unwrap();
    // Deliberately reap the UDP process BEFORE asking the kernel queue for
    // the packet. No process fd or live /proc socket can establish identity.
    let child = Command::new(std::env::current_exe()?)
        .arg("send-once")
        .arg(receiver.local_addr()?.to_string())
        .status()?;
    if !child.success() {
        return Err(io::Error::other("short UDP sender failed"));
    }
    collector.wait(Duration::from_secs(2))?;
    let messages = collector
        .receive()?
        .ok_or_else(|| io::Error::other("no held packet"))?;
    if messages.len() != 1 {
        return Err(io::Error::other("unexpected packet batch"));
    }
    let wire::Message::Packet(packet) = &messages[0] else {
        return Err(io::Error::other("expected kernel packet"));
    };
    let held = session
        .hold(123, packet)
        .map_err(|e| io::Error::other(format!("hold: {e:?}")))?;
    if held.launch.program != "short-udp" {
        return Err(io::Error::other("incorrect origin"));
    }
    session.decide(held.ticket, true).unwrap();
    collector.send(&wire::verdict(queue, packet.id(), true, 2))?;
    ack(&collector, 2)?;
    let mut payload = [0; 64];
    let (n, _) = receiver.recv_from(&mut payload)?;
    if &payload[..n] != b"owner-proof" {
        return Err(io::Error::other("bad accepted packet"));
    }
    println!("PASS: kernel cgroup identity survives UDP socket close and sender exit; individual verdict delivers held packet");

    let launch_sender = |mode: &str| -> io::Result<()> {
        if !Command::new(std::env::current_exe()?)
            .arg(mode)
            .arg(receiver.local_addr()?.to_string())
            .status()?
            .success()
        {
            return Err(io::Error::other("short UDP sender failed"));
        }
        Ok(())
    };
    let read_packet = |socket: &socket::Socket| -> io::Result<wire::Packet> {
        socket.wait(Duration::from_secs(2))?;
        let messages = socket
            .receive()?
            .ok_or_else(|| io::Error::other("missing packet"))?;
        if messages.len() != 1 {
            return Err(io::Error::other("unexpected packet batch"));
        }
        match messages.into_iter().next().unwrap() {
            wire::Message::Packet(packet) => Ok(packet),
            _ => Err(io::Error::other("expected packet")),
        }
    };
    let no_delivery = || -> io::Result<()> {
        receiver.set_read_timeout(Some(Duration::from_millis(200)))?;
        match receiver.recv_from(&mut [0; 64]) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(())
            }
            _ => Err(io::Error::other("denied packet was delivered")),
        }
    };

    launch_sender("send-marked")?;
    let packet = read_packet(&collector)?;
    if packet.mark() != token.mark() {
        return Err(io::Error::other("application forged its identity mark"));
    }
    let held = session.hold(123, &packet).unwrap();
    session.decide(held.ticket, false).unwrap();
    collector.send(&wire::verdict(queue, packet.id(), false, 3))?;
    ack(&collector, 3)?;
    no_delivery()?;
    println!("PASS: application SO_MARK is overwritten; DROP does not deliver the packet");

    let unknown_rules = rules.replace(
        &format!("meta mark set {} queue", token.mark()),
        &format!("meta mark set {} queue", token.mark() + 1),
    );
    checked(
        &nft,
        &["-f", "-"],
        Some(&format!(
            "delete table inet cellward_owner_probe\n{unknown_rules}"
        )),
    )?;
    launch_sender("send-once")?;
    let packet = read_packet(&collector)?;
    if session.hold(123, &packet) != Err(netqueue::Error::UnknownToken) {
        return Err(io::Error::other("unknown token accepted"));
    }
    collector.send(&wire::verdict(queue, packet.id(), false, 4))?;
    ack(&collector, 4)?;
    no_delivery()?;
    println!("PASS: an unregistered kernel mark is denied, not assigned to another launch");

    checked(
        &nft,
        &["-f", "-"],
        Some(&format!("delete table inet cellward_owner_probe\n{rules}")),
    )?;
    launch_sender("send-once")?;
    collector.wait(Duration::from_secs(2))?;
    drop(collector); // kernel flushes the outstanding packet as DROP
    no_delivery()?;
    launch_sender("send-once")?; // no listener and no queue bypass
    no_delivery()?;
    println!("PASS: collector exit drops held packets and does not bypass the absent queue");

    // Exercise the production queue-lifetime adapter, not hand-written ACK
    // handling. Reinstall the mapping in the fresh session before activation.
    let mut driver =
        netqueue::driver::Driver::bind(socket::Socket::open_here()?, 456, queue, 1, 1)?;
    let token = driver.register("runtime-udp".into(), 20).unwrap();
    checked(
        &nft,
        &["-f", "-"],
        Some(&format!("delete table inet cellward_owner_probe\n{rules}")),
    )?;
    driver.activate_after_mapping_ack(token).unwrap();
    launch_sender("send-once")?;
    driver.wait(Duration::from_secs(2))?;
    let held = driver.receive()?.remove(0);
    if held.launch.program != "runtime-udp" {
        return Err(io::Error::other("driver assigned incorrect identity"));
    }
    driver.decide(held.ticket, true)?;
    receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    receiver.recv_from(&mut payload)?;
    println!("PASS: runtime driver binds, retains identity and acknowledges individual ACCEPT");

    launch_sender("send-once")?;
    driver.wait(Duration::from_secs(2))?;
    let stale = driver.receive()?.remove(0);
    driver.change_policy(2)?;
    if driver.decide(stale.ticket, true).is_ok() {
        return Err(io::Error::other("old UI reply authorized a new policy"));
    }
    no_delivery()?;
    // A stale callback must not close an otherwise healthy active queue.
    launch_sender("send-once")?;
    driver.wait(Duration::from_secs(2))?;
    let held = driver.receive()?.remove(0);
    driver.decide(held.ticket, false)?;
    no_delivery()?;
    println!("PASS: runtime policy transition drops held data and rejects stale UI approval without killing the queue");

    driver.change_epoch(2)?;
    launch_sender("send-once")?;
    driver.wait(Duration::from_secs(2))?;
    if !driver.receive()?.is_empty() {
        return Err(io::Error::other(
            "old socket identity survived epoch change",
        ));
    }
    no_delivery()?;
    let next = driver.register("runtime-new-epoch".into(), 21).unwrap();
    let next_rules = rules.replace(
        &format!("meta mark set {} queue", token.mark()),
        &format!("meta mark set {} queue", next.mark()),
    );
    checked(
        &nft,
        &["-f", "-"],
        Some(&format!(
            "delete table inet cellward_owner_probe\n{next_rules}"
        )),
    )?;
    driver.activate_after_mapping_ack(next).unwrap();
    launch_sender("send-once")?;
    driver.wait(Duration::from_secs(2))?;
    let held = driver.receive()?.remove(0);
    if held.launch.epoch != 2 || held.launch.program != "runtime-new-epoch" {
        return Err(io::Error::other("new epoch identity incorrect"));
    }
    driver.close();
    no_delivery()?;
    launch_sender("send-once")?;
    no_delivery()?;
    println!("PASS: runtime epoch change rejects old identity; explicit close drops backlog and prevents bypass");
    // The entire namespace, table and bound queue disappear on exit.
    Ok(())
}
