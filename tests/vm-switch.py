"""tests/vm.nix, continued: a container's network switched live — stage 4 of
the container design of 2026-09-27 (docs/LEAK-MODEL.md «Смена сети на ходу»,
docs/THREAT-MODEL.md N19–N21, docs/GOTCHAS.md §18).

Executed by the main test script with exec(), in its globals (machine,
server, alice, instance, ikey, in_placed, in_placed_q, STATE, spub,
server_ip, PROBE, json, re, shlex; vmreal up): the script is handed to the
driver's build in one environment variable, and the kernel takes 128 KiB
there (MAX_ARG_STRLEN).

Container vmsw runs in vmreal (A), then is switched to vmswb (B) — a second
WireGuard peer of the same server, 10.99.0.3 where A is 10.99.0.2 — with its
programs running: a TCP connection, a connected UDP socket, an unconnected
UDP sender that ignores its errors, an SO_REUSEPORT pair, a running ping, an
IPv6 socket bound to the old address. The server logs every line and
datagram with the address it came from: nothing of before the switch may
ever arrive from B, nothing may arrive during the gap, and DNS after it asks
B's side only. A stand-in zone whose bridge holds its answer until the test
says (vmfake) shows the gap from outside, a failed attach, and the keeper
killed in the middle.
"""

import tempfile

SW = "vmsw"
SW_CORE = alice("command -v vpn-zone-core").strip()
PY = PROBE["py"]
LOGS = "/tmp/sw-tcp.log /tmp/sw-udp.log /tmp/sw-udp6.log"

# The helper the instance's programs run (test code only): senders that
# keep sending whatever becomes of their socket, a stand-in zone, a raw ask
# on a control socket.
HELPER = r'''
import os, select, socket, sys, time

def udp(dst, port, tag, bind=None):
    fam = socket.AF_INET6 if ":" in dst else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if bind:
        s.bind((bind, 0))
    i = 0
    while True:
        i += 1
        try:
            s.sendto(f"{tag}-{i}\n".encode(), (dst, int(port)))
        except OSError:
            pass
        time.sleep(0.3)

def reuse(dst, port, tag):
    socks = []
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(("0.0.0.0", 47123))
        socks.append(s)
    i = 0
    while True:
        i += 1
        try:
            socks[i % 2].sendto(f"{tag}-{i}\n".encode(), (dst, int(port)))
        except OSError:
            pass
        time.sleep(0.3)

def icmp(dst, out):
    # A ping socket (ICMP datagram): the kernel fills its id and checksum;
    # every reply written down at once.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    s.settimeout(0.5)
    seq = 0
    while True:
        seq += 1
        try:
            s.sendto(bytes([8, 0, 0, 0, 0, 0, seq >> 8 & 255, seq & 255]) + b"cellward", (dst, 0))
        except OSError:
            pass
        try:
            data = s.recv(1024)
            if data and data[0] == 0:
                with open(out, "a") as f:
                    f.write(f"reply {seq}\n")
        except OSError:
            pass
        time.sleep(0.3)

def freebind(src, dst, port, tag):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, 78, 1)  # IPV6_FREEBIND
    s.bind((src, 0))
    for i in range(1, 30):
        try:
            s.sendto(f"{tag}-{i}\n".encode(), (dst, int(port)))
        except OSError:
            pass
        time.sleep(0.2)

def ask(path, line):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(path)
    c.sendall(line.encode() + b"\n")
    out = b""
    while True:
        got = c.recv(4096)
        if not got:
            break
        out += got
    print(out.decode(), end="")

def fakezone(d, release, log):
    os.makedirs(d, exist_ok=True)
    def say(what):
        with open(log, "a") as f:
            f.write(what + "\n")
    with open(f"{d}/config.conf", "w") as f:
        f.write("# a test's stand-in: no zone\n")
    start = open("/proc/self/stat").read().rsplit(")", 1)[1].split()[19]
    boot = open("/proc/sys/kernel/random/boot_id").read().strip()
    with open(f"{d}/zone.start", "w") as f:
        f.write(f"{start} {boot}\n")
    with open(f"{d}/zone.pid", "w") as f:
        f.write(f"{os.getpid()}\n")
    path = f"{d}/bridge.sock"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(4)
    open(f"{d}/bridge-rule", "w").close()
    open(f"{d}/ready", "w").close()
    say("up")
    while True:
        c, _ = srv.accept()
        msg, fds, _, _ = socket.recv_fds(c, 1024, 4)
        say(f"asked {len(fds)}")
        while not os.path.exists(release):
            r, _, _ = select.select([c], [], [], 0.2)
            if r and not c.recv(1):
                say("hung up")
                break
        else:
            c.sendall(b"ERR held by the test\n")
            say("refused")
        for fd in fds:
            os.close(fd)
        c.close()

globals()[sys.argv[1]](*sys.argv[2:])
'''

with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
    f.write(HELPER)
    helper_host = f.name
machine.copy_from_host(helper_host, "/tmp/swhelper.py")
machine.succeed("chmod 0644 /tmp/swhelper.py")

# The server's side: every line and datagram logged with where it came from.
with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
    # One line a datagram (the senders end theirs with one): one write.
    f.write('#!/bin/sh\nexec sed -u "s/^/$SOCAT_PEERADDR /" >> "/tmp/sw-$1.log"\n')
    logger_host = f.name
server.copy_from_host(logger_host, "/tmp/swlog.sh")


def launch(unit, net, cmd):
    """A program of vmsw, launched as from the desktop: through the user's
    manager — in the instance's epoch."""
    alice(
        f"systemd-run --user --collect --unit={unit} -E PATH=\"$PATH\" "
        f"cellward run {net} --container {SW} -- {cmd}"
    )


def logged(tag, source):
    """The server's log lines with `tag` that came from `source`."""
    out = server.succeed(f"cat {LOGS} 2>/dev/null || true")
    return [l for l in out.splitlines() if tag in l and source in l]


def sw():
    return instance(SW)


def wait_sw(pred, what):
    for _ in range(240):
        i = sw()
        if i and pred(i):
            return i
        machine.sleep(0.5)
    raise AssertionError(f"{SW}: never {what}: {sw()}")


def journal_of(id_):
    return [
        e for e in json.loads(alice("cellward journal --json"))["events"]
        if e.get("instance") == id_
    ]


def ask_control(id_, line, prefix=""):
    ctl = f"{STATE}/.instances/{ikey(id_)}/control"
    return alice(f"{prefix}{PY} /tmp/swhelper.py ask {ctl} {shlex.quote(line)}")


with subtest("switch: a second network B, and the server's listeners that say who sent what"):
    bpriv = machine.succeed("wg genkey").strip()
    bpub = machine.succeed(f"printf %s '{bpriv}' | wg pubkey").strip()
    server.succeed(f"wg set wg0 peer '{bpub}' allowed-ips 10.99.0.3/32,fd99::3/128")
    alice(
        f"printf '[Interface]\\nPrivateKey = {bpriv}\\nAddress = 10.99.0.3/32, fd99::3/128\\n"
        f"DNS = 10.99.0.1, fd99::1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\\nEndpoint = {server_ip}:51820\\n' > /tmp/vmswb.conf"
    )
    alice("cellward add vmswb /tmp/vmswb.conf")
    alice("cellward up vmswb")
    # A transient service's PATH has no sh or sed in it (red once in CI):
    # the logger's shell and its sed by the system's.
    server.succeed(
        "systemd-run --unit=swtcp -E PATH=/run/current-system/sw/bin socat -u TCP-LISTEN:7301,bind=10.99.0.1,fork,reuseaddr "
        "SYSTEM:'sh /tmp/swlog.sh tcp'"
    )
    server.succeed(
        "systemd-run --unit=swudp -E PATH=/run/current-system/sw/bin socat -u UDP-RECVFROM:7300,bind=10.99.0.1,fork "
        "SYSTEM:'sh /tmp/swlog.sh udp'"
    )
    server.succeed(
        "systemd-run --unit=swudp6 -E PATH=/run/current-system/sw/bin socat -u UDP6-RECVFROM:7302,bind=[fd99::1],fork "
        "SYSTEM:'sh /tmp/swlog.sh udp6'"
    )
    # DNS with every query logged by its source: the same answers.
    server.succeed("systemctl stop dns")
    server.succeed(
        "systemd-run --unit=dnslog dnsmasq -k --user=root --port=53 --bind-interfaces "
        "--listen-address=10.99.0.1 --listen-address=fd99::1 --no-resolv "
        "--address=/leaktest.internal/10.99.0.9 --log-queries --log-facility=/tmp/dns.log"
    )
    server.wait_until_succeeds("ss -lun | grep -q 10.99.0.1:53")
    server.wait_until_succeeds("ss -ltn | grep -q 10.99.0.1:7301")

with subtest("switch: container vmsw in A with its programs, each socket kind open"):
    alice(f"cellward container create {SW} --home layer")
    alice(f"cellward container set {SW} network vmreal")
    launch("swkeep", "vmreal", "sleep infinity")
    wait_sw(lambda i: i["exit"] == "through" and i["live_switch"]["available"], "up and switchable")
    a6_old = re.search(
        r"inet6 (fd63:[0-9a-f:]+)/128",
        in_placed(SW, "vmreal", "ip -6 -o addr show dev awg0"),
    ).group(1)
    # A service ignores SIGPIPE: the loops end on their own write error once
    # socat is gone (red once in CI: both socats ended on their broken
    # socket, and the loops wrote on).
    launch(
        "swtcp",
        "vmreal",
        "sh -c 'i=0; while :; do i=$((i+1)); echo tcp-$i || exit 0; sleep 0.5; done "
        "| socat -u - TCP:10.99.0.1:7301'",
    )
    launch(
        "swcudp",
        "vmreal",
        "sh -c 'i=0; while :; do i=$((i+1)); echo cudp-$i || exit 0; sleep 0.5; done "
        "| socat -u - UDP:10.99.0.1:7300'",
    )
    launch("swuudp", "vmreal", f"{PY} /tmp/swhelper.py udp 10.99.0.1 7300 uudp")
    launch("swreuse", "vmreal", f"{PY} /tmp/swhelper.py reuse 10.99.0.1 7300 reuse")
    launch("swv6", "vmreal", f"{PY} /tmp/swhelper.py udp fd99::1 7302 v6old {a6_old}")
    launch("swping", "vmreal", f"{PY} /tmp/swhelper.py icmp 10.99.0.1 /tmp/sw-ping.out")
    for tag in ["tcp-", "cudp-", "uudp-", "reuse-"]:
        server.wait_until_succeeds(f"grep -q '10.99.0.2 {tag}' {LOGS}", timeout=60)
    server.wait_until_succeeds("grep -q 'v6old-' /tmp/sw-udp6.log", timeout=60)
    machine.wait_until_succeeds("grep -q '^reply' /tmp/sw-ping.out", timeout=60)
    i = sw()
    assert (i["network"], i["epoch"], i["switch"]["state"]) == ("vmreal", 1, "idle"), i
    # Where its programs read the network it is in (stage 4c): read-only.
    note = in_placed(SW, "vmreal", "cat /run/user/1000/cellward/network").strip()
    assert note == "vmreal", note
    in_placed(SW, "vmreal", "sh -c '! echo x > /run/user/1000/cellward/network'")

with subtest("switch: every refusal leaves A attached, its sockets as they were"):
    def flowing():
        before = len(logged("tcp-", "10.99.0.2"))
        server.wait_until_succeeds(
            f"[ $(grep -c '10.99.0.2 tcp-' /tmp/sw-tcp.log) -gt {before} ]", timeout=30
        )

    # Its zone locked (P3).
    alice("cellward lock vmreal")
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            f"export XDG_RUNTIME_DIR=/run/user/1000; cellward container set {SW} network "
            "vmswb --yes 2>&1"
        )
    )
    assert code != 0 and "locked" in out and "--restart" in out, out
    alice("cellward unlock vmreal")
    # A program launched from a login session (P4): outside the epoch.
    machine.succeed(
        "su -l alice -c "
        + shlex.quote(
            f"export XDG_RUNTIME_DIR=/run/user/1000; setsid {SW_CORE} container-enter "
            f"--instance {SW} --network vmreal -- sleep 4848 </dev/null >/dev/null 2>&1 &"
        )
    )
    wait_sw(lambda i: i["live_switch"]["reason"] == "outside", "outside")
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            f"export XDG_RUNTIME_DIR=/run/user/1000; cellward container set {SW} network "
            "vmswb --yes 2>&1"
        )
    )
    assert code != 0 and "outside" in out, out
    machine.succeed("pkill -xf 'sleep 4848'")
    wait_sw(lambda i: i["live_switch"]["available"], "switchable again")
    # The host's network (P6): only by a restart.
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            f"export XDG_RUNTIME_DIR=/run/user/1000; cellward container set {SW} network "
            "unconfined --yes 2>&1"
        )
    )
    assert code != 0 and "--restart" in out, out
    # A peer in a user namespace of its own (P1): no program of a zone or an
    # instance, whatever uid it has, asks — only the host's.
    out = ask_control(SW, "SWITCH vmswb", prefix="unshare -U -r ")
    assert out.startswith("REFUSED from-host"), out
    # An instance of one network (P7): the main home's in A.
    alice(
        "systemd-run --user --collect --unit=swmain -E PATH=\"$PATH\" "
        "cellward run vmreal -- sleep infinity"
    )
    machine.wait_until_succeeds(f"test -f {STATE}/.instances/{ikey('main:vmreal')}/ready", timeout=60)
    out = ask_control("main:vmreal", "SWITCH vmswb")
    assert out.startswith("REFUSED kind"), out
    alice("systemctl --user stop swmain")
    # Not a request at all.
    assert ask_control(SW, "HELLO").startswith("REFUSED request"), "HELLO"
    i = sw()
    assert (i["network"], i["exit"], i["epoch"]) == ("vmreal", "through", 1), i
    flowing()
    kinds = [(e["event"], e.get("why")) for e in journal_of(SW)]
    for why in ["locked", "outside", "from-host"]:
        assert ("switch-refused", why) in kinds, kinds

with subtest("switch: no program reaches the control socket, and the broker has no switch verb"):
    in_placed(SW, "vmreal", f"test ! -e {STATE}/.instances")
    in_placed(
        SW,
        "vmreal",
        "sh -c 'test ! -S /run/user/1000/vpn-zones/broker || printf \"SWITCH vmswb\\n\" "
        "| timeout 10 socat -t3 - UNIX-CONNECT:/run/user/1000/vpn-zones/broker; true'",
    )
    i = sw()
    assert (i["network"], i["epoch"]) == ("vmreal", 1), i

with subtest("switch: A to B live — programs stay, nothing of A goes on in B, DNS follows"):
    dns_before = server.succeed("cat /tmp/dns.log")
    out = alice(f"cellward container set {SW} network vmswb --yes")
    assert "«vmswb»" in out and "эпоха 2" in out, out
    assert "cookies" in out, out
    # The unconnected sender and the pair keep their sockets: named.
    assert "python3" in out, out
    i = sw()
    assert (i["network"], i["exit"], i["why"], i["epoch"]) == ("vmswb", "through", None, 2), i
    assert i["switch"]["state"] == "idle", i
    alice("systemctl --user is-active swkeep swuudp swreuse swv6 swping")
    # A new connection goes out through B.
    out = in_placed(SW, "vmswb", "socat -T10 - TCP:10.99.0.1:8080")
    assert "peer=10.99.0.3" in out, out
    out = in_placed(SW, "vmswb", "getent ahostsv4 after-switch.leaktest.internal")
    assert "10.99.0.9" in out, out
    resolv = in_placed(SW, "vmswb", "cat /etc/resolv.conf")
    assert "nameserver 10.254.255.253" in resolv and "10.99.0.1" not in resolv, resolv
    # The network it is in now, in the same file, rewritten in place (4c).
    note = in_placed(SW, "vmswb", "cat /run/user/1000/cellward/network").strip()
    assert note == "vmswb", note
    # A socket with the old IPv6 source, made after the switch: not out.
    in_placed(SW, "vmswb", f"{PY} /tmp/swhelper.py freebind {a6_old} fd99::1 7302 v6free")
    pings = machine.succeed("grep -c '^reply' /tmp/sw-ping.out").strip()
    # Time for anything old to show up where it must not.
    machine.sleep(6)
    for tag in ["tcp-", "cudp-", "uudp-", "reuse-"]:
        assert not logged(tag, "10.99.0.3"), (tag, logged(tag, "10.99.0.3"))
    for tag in ["v6old-", "v6free-"]:
        assert not logged(tag, "fd99::3"), (tag, logged(tag, "fd99::3"))
    assert machine.succeed("grep -c '^reply' /tmp/sw-ping.out").strip() == pings, pings
    dns = server.succeed("cat /tmp/dns.log")[len(dns_before):]
    assert "after-switch.leaktest.internal from 10.99.0.3" in dns, dns
    assert "from 10.99.0.2" not in dns, dns
    # The TCP connection and the connected UDP socket were broken.
    alice("! systemctl --user is-active swtcp swcudp")
    status = json.loads(alice("cellward status --json"))
    c = next(c for c in status["containers"] if c["name"] == SW)
    assert c["network"]["value"] == "vmswb", c
    assert all(r["network_now"] == "vmswb" for r in c["running"] if r["instance"] == SW), c
    kinds = [e["event"] for e in journal_of(SW)]
    assert "switch-cut" in kinds and "switch" in kinds, kinds
    done = [e for e in journal_of(SW) if e["event"] == "switch"][-1]
    assert (done["from"], done["to"], done["epoch"]) == ("vmreal", "vmswb", "2"), done

with subtest("switch: the gap — nothing but loopback while the next zone has not answered"):
    alice(f"rm -f /tmp/vmfake-release /tmp/vmfake.log && mkdir -p {STATE}/vmfake")
    alice(
        f"systemd-run --user --collect --unit=swfake {PY} /tmp/swhelper.py fakezone "
        f"{STATE}/vmfake /tmp/vmfake-release /tmp/vmfake.log"
    )
    machine.wait_until_succeeds("grep -qx up /tmp/vmfake.log", timeout=30)
    alice(
        "systemd-run --user --collect --unit=swcli "
        f"cellward container set {SW} network vmfake --yes"
    )
    machine.wait_until_succeeds("grep -q '^asked 1' /tmp/vmfake.log", timeout=60)
    i = sw()
    assert (i["network"], i["exit"], i["why"]) == ("vmfake", "none", "switching"), i
    assert (i["switch"]["state"], i["switch"]["from"], i["switch"]["to"]) == (
        "attaching",
        "vmswb",
        "vmfake",
    ), i
    links = machine.succeed(f"nsenter -t {i['pid']} -n ip -o link show")
    assert len(links.strip().splitlines()) == 1 and ": lo:" in links, links
    routes = machine.succeed(f"nsenter -t {i['pid']} -n ip -4 route show")
    assert routes.startswith("unreachable default"), routes
    counts = {tag: len(logged(tag, "10.99.0.")) for tag in ["uudp-", "reuse-"]}
    machine.sleep(3)
    for tag, n in counts.items():
        assert len(logged(tag, "10.99.0.")) == n, (tag, logged(tag, "10.99.0."))
    # The zone refuses: the switch fails at its attach — cut, in the new
    # network, never back in the old one (G7).
    machine.succeed("touch /tmp/vmfake-release")
    machine.wait_until_succeeds("grep -qx refused /tmp/vmfake.log", timeout=60)
    i = wait_sw(lambda i: i["switch"]["state"] == "failed", "failed")
    assert (i["network"], i["exit"], i["why"]) == ("vmfake", "none", "attach-failed"), i
    links = machine.succeed(f"nsenter -t {i['pid']} -n ip -o link show")
    assert len(links.strip().splitlines()) == 1, links
    failed = [e for e in journal_of(SW) if e["event"] == "switch-failed"][-1]
    assert failed["phase"] == "attach", failed

with subtest("switch: back to B from a cut instance; B stopped while bound — no fallback"):
    machine.succeed("rm -f /tmp/vmfake-release")
    alice(f"cellward container set {SW} network vmswb --yes")
    i = wait_sw(lambda i: i["exit"] == "through", "through B again")
    assert (i["network"], i["epoch"]) == ("vmswb", 4), i
    launch("swnofb", "vmswb", f"{PY} /tmp/swhelper.py udp 10.99.0.1 7300 nofb")
    server.wait_until_succeeds(f"grep -q '10.99.0.3 nofb-' {LOGS}", timeout=60)
    alice("cellward down vmswb")
    i = wait_sw(lambda i: i["why"] == "zone-down", "cut by B's end")
    assert (i["network"], i["exit"]) == ("vmswb", "none"), i
    nofb = len(logged("nofb-", "10.99.0.3"))
    machine.sleep(4)
    assert not logged("nofb-", "10.99.0.2"), logged("nofb-", "10.99.0.2")
    assert len(logged("nofb-", "10.99.0.3")) == nofb

with subtest("switch: B back — a new epoch; a socket of the one before stays mute"):
    alice("cellward up vmswb")
    i = wait_sw(lambda i: i["exit"] == "through", "through B once more")
    assert i["epoch"] == 5, i
    out = in_placed(SW, "vmswb", "socat -T10 - TCP:10.99.0.1:8080")
    assert "peer=10.99.0.3" in out, out
    machine.sleep(4)
    assert len(logged("nofb-", "10.99.0.3")) == nofb, logged("nofb-", "10.99.0.3")
    assert not logged("nofb-", "10.99.0.2")
    events = journal_of(SW)
    assert any(e["event"] == "reattach" and e.get("epoch") == "5" for e in events), events

with subtest("switch: the keeper killed in the middle — the instance and its programs gone"):
    alice(
        "systemd-run --user --collect --unit=swcli2 "
        f"cellward container set {SW} network vmfake --yes"
    )
    machine.wait_until_succeeds("[ $(grep -c '^asked' /tmp/vmfake.log) -ge 2 ]", timeout=60)
    keeper = alice(
        f"systemctl --user show -p MainPID --value vpn-zone-container@{SW}.service"
    ).strip()
    assert keeper and keeper != "0", keeper
    machine.succeed(f"kill -9 {keeper}")
    # The driver runs every command under `set -o pipefail`: a pipe into
    # `grep -vqx active` failed with is-active's own non-zero exit and the
    # wait never ended (red once in CI, 2026-09-28). is-active answers
    # non-zero for every state but active — waited for directly.
    machine.wait_until_fails(
        "su -l alice -c "
        + shlex.quote(
            "XDG_RUNTIME_DIR=/run/user/1000 "
            f"systemctl --user is-active vpn-zone-container@{SW}.service"
        ),
        timeout=60,
    )
    machine.wait_until_succeeds("grep -qx 'hung up' /tmp/vmfake.log", timeout=60)
    for unit in ["swkeep", "swuudp", "swreuse", "swv6", "swping", "swnofb"]:
        machine.wait_until_fails(
            "su -l alice -c "
            + shlex.quote(f"XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active {unit}"),
            timeout=60,
        )
    machine.fail("pgrep -f 'swhelper.py (udp|reuse)'")
    assert sw() is None, sw()
    # Nothing attached: the stand-in refused the first request only.
    assert machine.succeed("grep -cx refused /tmp/vmfake.log").strip() == "1"

with subtest("switch: cleaned up"):
    alice("systemctl --user stop swfake || true")
    alice(f"rm -rf {STATE}/vmfake")
    machine.succeed("rm -f /tmp/vmfake-release")
    alice(f"cellward container rm {SW} || true")
    alice("cellward down vmswb || true")
    server.succeed("systemctl stop swtcp swudp swudp6 || true")
