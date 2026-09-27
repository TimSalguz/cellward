"""The VM side of tests/vm-probe-container-ns.py: stage 0 of the container
design (2026-09-27), the kernel and passt mechanisms the later stages rest
on. Run in the VM as alice, or as root of a user namespace of hers:

  relay <passt> <zone pid> <a4> <a6|-> <resolver4> <resolver6|->
      A sibling namespace (`unshare -U -r -n`, a holder of its own) gets a
      tap made by `tap` below; the zone's app namespace gets `passt --fd`,
      started as alice in the zone's user namespace; `vpn-zone-core
      frame-relay` pumps between the two. Prints the pids as JSON once passt
      has written its pid file and the tap has its address.
  tap <stream fd> <a4> <a6|->
      Inside the holder, as its root: make the tap awg0 (not persistent),
      configure it, then exec frame-relay with its descriptor and the
      stream's.
  hold
      A holder: `unshare -U -r -n sleep infinity`; prints its pid.
  abort
      Inside a holder, as its root: a TCP connection and a connected UDP
      socket over its loopback, `ss -K` on both, and what each saw after.
  cgroup <nft path> <cgroup rel path> <level> <cgroup.procs of it>
      Inside a holder, as its root, from a unit of alice's manager: a
      `socket cgroupv2` rule on UDP 7100; a socket born before this process
      moves itself into the cgroup, one after. Prints what arrived.
  pasta-fd <pasta> <a4>
      Informative (J4): pasta, not passt, given a tap descriptor from a
      sibling namespace. Prints what came of it.

Test code only: nothing here is product code, and every wait is bounded.
"""

import errno
import fcntl
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time

WORK = "/tmp/vzprobe"
G4 = "10.254.255.254"
D4 = "10.254.255.253"
D6 = "fd63:656c:6c77::53"
TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


def wait_for(what, check, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise SystemExit(f"timed out waiting for {what}")


def spawn(argv, log, pass_fds=()):
    with open(log, "wb") as out:
        return subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            pass_fds=pass_fds,
            start_new_session=True,
        )


def netns_of(pid):
    try:
        return os.readlink(f"/proc/{pid}/ns/net")
    except OSError:
        return None


def hold():
    """A sibling user+net namespace of alice's, held by a sleep."""
    os.makedirs(WORK, exist_ok=True)
    p = spawn(["unshare", "-U", "-r", "-n", "sleep", "infinity"], f"{WORK}/hold.log")
    mine = netns_of(os.getpid())
    wait_for("the holder's namespace", lambda: netns_of(p.pid) not in (None, mine))
    return p.pid


def inside(pid, *argv):
    return ["nsenter", "-U", "-n", "-t", str(pid), "--", *argv]


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def relay(passt, zone_pid, a4, a6, r4, r6):
    os.makedirs(WORK, exist_ok=True)
    holder = hold()
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pidfile = f"{WORK}/passt.pid"
    if os.path.exists(pidfile):
        os.unlink(pidfile)
    # The argv crate::bridge::passt_argv makes, with the probe's addresses.
    argv = [
        "nsenter", "--preserve-credentials", "-U", "-n", "-t", str(zone_pid), "--",
        passt, "--fd", str(theirs.fileno()), "-f", "-q", "-P", pidfile,
        "--no-dhcp", "--no-dhcpv6", "--no-ra", "--no-map-gw",
        "--map-guest-addr", "none", "-t", "none", "-u", "none",
        "-a", a4, "-n", "16", "-g", G4,
    ]
    argv += ["-a", a6, "-g", "fe80::1"] if a6 != "-" else ["-4"]
    argv += ["--dns-forward", D4, "--dns-host", r4]
    if a6 != "-" and r6 != "-":
        argv += ["--dns-forward", D6, "--dns-host", r6]
    p = spawn(argv, f"{WORK}/passt.log", pass_fds=(theirs.fileno(),))
    theirs.close()
    wait_for("passt's pid file", lambda: read(pidfile).strip() != "" or p.poll() is not None)
    if p.poll() is not None:
        raise SystemExit(f"passt ended at once: {read(WORK + '/passt.log')}")
    r = spawn(
        inside(holder, sys.executable, __file__, "tap", str(ours.fileno()), a4, a6),
        f"{WORK}/relay.log",
        pass_fds=(ours.fileno(),),
    )
    ours.close()

    def configured():
        if r.poll() is not None:
            raise SystemExit(f"the relay ended at once: {read(WORK + '/relay.log')}")
        out = subprocess.run(
            inside(holder, "ip", "-o", "addr", "show", "dev", "awg0"),
            capture_output=True, text=True,
        ).stdout
        return a4 in out and (a6 == "-" or a6 in out)

    wait_for("the relay's tap", configured)
    print(json.dumps({"holder": holder, "passt": p.pid, "relay": r.pid}))


def ip(*args):
    subprocess.run(["ip", *args], check=True)


def make_tap(a4, a6):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH22x", b"awg0", IFF_TAP | IFF_NO_PI))
    mac = "02:" + ":".join(f"{b:02x}" for b in os.urandom(5))
    ip("link", "set", "lo", "up")
    ip("link", "set", "awg0", "address", mac, "mtu", "65520", "up")
    ip("addr", "add", f"{a4}/16", "dev", "awg0")
    ip("route", "add", "default", "via", G4, "dev", "awg0")
    if a6 != "-":
        ip("-6", "addr", "add", f"{a6}/128", "dev", "awg0", "nodad")
        ip("-6", "route", "add", "default", "via", "fe80::1", "dev", "awg0")
    return fd


def tap(stream_fd, a4, a6):
    fd = make_tap(a4, a6)
    os.set_inheritable(fd, True)
    core = shutil.which("vpn-zone-core")
    os.execv(core, [core, "frame-relay", "--tap-fd", str(fd), "--stream-fd", stream_fd])


def outcome(s):
    s.settimeout(5)
    try:
        data = s.recv(16)
        return "EOF" if not data else "DATA"
    except TimeoutError:
        return "alive"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))


def abort():
    ip("link", "set", "lo", "up")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 7000))
    srv.listen()
    tcp = socket.create_connection(("127.0.0.1", 7000), timeout=10)
    conn, _ = srv.accept()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.connect(("127.0.0.1", 7001))
    listed = subprocess.run(["ss", "-tun"], capture_output=True, text=True).stdout
    kills = [
        subprocess.run(["ss", "-K", "-t", "dst", "127.0.0.1:7000"], capture_output=True, text=True),
        subprocess.run(["ss", "-K", "-u", "dst", "127.0.0.1:7001"], capture_output=True, text=True),
    ]
    print(json.dumps({
        "tcp": outcome(tcp),
        "udp": outcome(udp),
        "ss": [k.returncode for k in kills],
        "err": [k.stderr.strip() for k in kills],
        "listed": listed,
    }))
    conn.close()


def cgroup(nft, rel, level, procs):
    ip("link", "set", "lo", "up")
    rules = (
        "table inet vzprobe {\n"
        " chain out {\n"
        "  type filter hook output priority filter; policy accept;\n"
        f'  udp dport 7100 socket cgroupv2 level {level} "{rel}" accept\n'
        "  udp dport 7100 drop\n"
        " }\n"
        "}\n"
    )
    r = subprocess.run([nft, "-f", "-"], input=rules, capture_output=True, text=True)
    if r.returncode != 0:
        print(json.dumps({"loaded": False, "err": r.stderr.strip()}))
        return
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 7100))
    rx.settimeout(3)
    sent = {}

    def send(s, word):
        try:
            s.sendto(word.encode(), ("127.0.0.1", 7100))
            sent[word] = "sent"
        except OSError as e:
            sent[word] = errno.errorcode.get(e.errno, str(e.errno))

    before = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send(before, "stranger")
    with open(procs, "w") as f:
        f.write(str(os.getpid()))
    member = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send(member, "member")
    # Born outside, and still outside after its process moved: a socket's
    # cgroup is the one it was made in.
    send(before, "stranger-after-the-move")
    got = []
    try:
        while True:
            got.append(rx.recv(64).decode())
    except TimeoutError:
        pass
    print(json.dumps({"loaded": True, "got": got, "sent": sent}))


def pasta_fd(pasta, a4):
    """pasta mode, handed a sibling's tap: does it answer the sibling's ARP
    without --config-net? (J4: its tap_is_ready() is pasta_conf_ns.) Against
    a stand-in namespace of its own, not a zone: whatever pasta does to the
    namespace it holds netlink over happens to nothing of the test's."""
    stand_in = hold()
    sibling = hold()
    subprocess.run(inside(stand_in, "ip", "link", "set", "lo", "up"), check=True)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    made = subprocess.run(
        inside(sibling, sys.executable, __file__, "tap-send", str(child.fileno()), a4),
        pass_fds=(child.fileno(),), capture_output=True, text=True, timeout=60,
    )
    child.close()
    result = {"tap": made.returncode}
    try:
        _, fds, _, _ = socket.recv_fds(parent, 16, 1)
        tapfd = fds[0]
        log = f"{WORK}/pasta-fd.log"
        p = spawn(
            inside(
                stand_in, pasta, "--fd", str(tapfd), "--netns-only",
                "--netns", f"/proc/{stand_in}/ns/net", "-f", "-q", "--no-netns-quit",
                "-t", "none", "-u", "none", "-T", "none", "-U", "none", "--no-map-gw",
                "-4", "-a", a4, "-n", "16", "-g", G4,
            ),
            log,
            pass_fds=(tapfd,),
        )
        os.close(tapfd)
        time.sleep(3)
        ping = subprocess.run(
            inside(sibling, "ping", "-c1", "-W3", G4), capture_output=True, text=True,
        )
        neigh = subprocess.run(
            inside(sibling, "ip", "neigh", "show", "dev", "awg0"),
            capture_output=True, text=True,
        )
        result.update({
            "pasta_running": p.poll() is None,
            "ping_gateway": ping.returncode,
            "neigh": neigh.stdout.strip(),
            "log": read(log)[-400:],
        })
        if p.poll() is None:
            p.kill()
    finally:
        os.kill(stand_in, 15)
        os.kill(sibling, 15)
    print(json.dumps(result))


def tap_send(sock_fd, a4):
    fd = make_tap(a4, "-")
    s = socket.socket(fileno=int(sock_fd))
    socket.send_fds(s, [b"tap"], [fd])


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "relay":
        relay(*args)
    elif cmd == "tap":
        tap(*args)
    elif cmd == "hold":
        print(hold())
    elif cmd == "abort":
        abort()
    elif cmd == "cgroup":
        cgroup(*args)
    elif cmd == "pasta-fd":
        pasta_fd(*args)
    elif cmd == "tap-send":
        tap_send(*args)
    else:
        raise SystemExit(f"unknown: {cmd}")


main()
