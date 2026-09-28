"""tests/vm.nix, continued: a file moved between the two machines, with zones
and without (the owner, 2026-09-28: "проверить между двумя виртуалками
передачу файла с зонами, без зон"; docs/THREAT-MODEL.md N3 and N22, README
«Moving files between machines»).

Executed by the main test script with exec(), in its globals (machine,
server, alice, STATE, server_ip, server_ip6, cpub, PROBE, json, re, shlex;
vmreal down, its peer on the server made anew): the script is handed to the
driver's build in one environment variable, and the kernel takes 128 KiB
there (MAX_ARG_STRLEN). It runs after vmreal's own leak capture: a host
program's upload to the server is a LAN flow that capture rightly counts
(docs/GOTCHAS.md §13), so each zone here is brought up under a capture of
its own, and the host's transfers are made outside it.

A real file of a few megabytes, its sha256 on both ends:

- without zones (`cellward run unconfined`): up to the server and down from
  it by the LAN addresses, and the server sends one to a program of the host
  that listens; the host's LAN discovery (LocalSend's multicast, KDE
  Connect's broadcast) reaches the server;
- in a tunnel zone (vmreal) and in a hermetic one with a tunnel of its own
  (vmhreal: vmherm's config has a TEST-NET endpoint, no peer): up and down
  through the tunnel only — the server sees the tunnel's address, eth1
  carries the tunnel's UDP alone; nothing connects to a program listening in
  the zone, from the LAN or through the tunnel (inbound for a service in a
  zone is a ROADMAP item, not done); the zone's discovery reaches no LAN;
- two containers of the hermetic zone see neither each other's home nor
  /tmp, and meet in a directory granted to both;
- offline: nothing moves.
"""

import ipaddress
import tempfile

XF = "/home/alice/xfer"
XF_PY = PROBE["py"]
# The server's upload endpoint, and the port a program on the machine
# listens on (the machine's firewall opens it: a refusal is then the zone's,
# not the firewall's).
XF_PORT, XF_IN = 8093, 8094
XF_ROWS = []

# Test code only: an upload endpoint (PUT stores the body, GET sends a file
# back, both written down with the peer's address), a listener for the LAN's
# discovery on the server's eth1, and a program that announces itself the way
# LocalSend (multicast 224.0.0.167:53317) and KDE Connect (broadcast, UDP
# 1716) do, on every interface it has.
XF_HELPER = r'''
import hashlib, http.server, os, select, socket, socketserver, struct, sys, urllib.parse

GROUP4, GROUP6 = "224.0.0.167", "ff02::1"


def serve(port, root, log):
    os.makedirs(root, exist_ok=True)

    def note(line):
        with open(log, "a") as f:
            f.write(line + "\n")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def peer(self):
            host = self.client_address[0]
            return host[7:] if host.startswith("::ffff:") else host

        def answer(self, code, body):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_PUT(self):
            name = os.path.basename(urllib.parse.urlsplit(self.path).path)
            left = int(self.headers.get("Content-Length", "0"))
            digest = hashlib.sha256()
            with open(os.path.join(root, name), "wb") as f:
                while left:
                    chunk = self.rfile.read(min(left, 65536))
                    if not chunk:
                        break
                    f.write(chunk)
                    digest.update(chunk)
                    left -= len(chunk)
            note(f"PUT {self.path} {self.peer()} {digest.hexdigest()}")
            self.answer(201, f"peer={self.peer()} sha256={digest.hexdigest()}\n".encode())

        def do_GET(self):
            name = os.path.basename(urllib.parse.urlsplit(self.path).path)
            if name == "ping":
                body = b"pong\n"
            else:
                try:
                    with open(os.path.join(root, name), "rb") as f:
                        body = f.read()
                except OSError:
                    note(f"GET {self.path} {self.peer()} missing")
                    self.answer(404, b"no such file\n")
                    return
            note(f"GET {self.path} {self.peer()}")
            self.answer(200, body)

        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
        address_family = socket.AF_INET6
        daemon_threads = True
        allow_reuse_address = True

        def server_bind(self):
            # Both families on one socket; and no reverse lookup of the
            # address (HTTPServer's getfqdn), which would ask a resolver.
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            socketserver.TCPServer.server_bind(self)

    server = Server(("::", int(port)), Handler)
    note("ready")
    server.serve_forever()


def hear(log, ifname="eth1"):
    idx = socket.if_nametoindex(ifname)
    socks = []
    for fam, port in ((socket.AF_INET, 53317), (socket.AF_INET, 1716), (socket.AF_INET6, 53317)):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A LAN peer: what comes in through eth1, and nothing else.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind(("::", port))
        else:
            s.bind(("0.0.0.0", port))
            if port == 53317:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                             struct.pack("4s4si", socket.inet_aton(GROUP4), bytes(4), idx))
        socks.append(s)
    with open(log, "a", buffering=1) as f:
        f.write("ready\n")
        while True:
            for s in select.select(socks, [], [])[0]:
                data, addr = s.recvfrom(4096)
                f.write(f"{s.getsockname()[1]} {addr[0]} {data.decode(errors='replace')}\n")


def announce(tag, lan_broadcast):
    payload = f"cellward-discovery {tag}".encode()

    def send(what, fam, dst, *opts):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            for level, name, value in opts:
                s.setsockopt(level, name, value)
            s.sendto(payload, dst)
            print(f"{what}: sent")
        except OSError as e:
            print(f"{what}: {e.strerror or e}")
        finally:
            s.close()

    bcast = (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for idx, name in socket.if_nameindex():
        if name == "lo":
            continue
        send(f"{name} multicast {GROUP4}:53317", socket.AF_INET, (GROUP4, 53317),
             (socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("4s4si", bytes(4), bytes(4), idx)))
        send(f"{name} broadcast 255.255.255.255:1716", socket.AF_INET, ("255.255.255.255", 1716),
             bcast, (socket.SOL_SOCKET, socket.SO_BINDTODEVICE, name.encode()))
        send(f"{name} multicast [{GROUP6}]:53317", socket.AF_INET6, (GROUP6, 53317, 0, idx),
             (socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx))
    send(f"broadcast {lan_broadcast}:1716", socket.AF_INET, (lan_broadcast, 1716), bcast)


globals()[sys.argv[1]](*sys.argv[2:])
'''

with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
    f.write(XF_HELPER)
    xf_helper_host = f.name

GROUP4_TEXT = "224.0.0.167"
xf_first = "tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
XF_MIP = machine.succeed(f"ip -4 -o addr show eth1 | head -1 | {xf_first}").strip()
XF_MIP6 = machine.succeed(f"ip -6 -o addr show eth1 scope global | head -1 | {xf_first}").strip()
# The LAN's own broadcast address, from its prefix: the test network gives
# eth1 its address without one (`brd`).
XF_BCAST = str(ipaddress.ip_interface(machine.succeed(
    "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4"
).strip()).network.broadcast_address)
# What the machine's eth1 may carry while a zone moves files: towards the
# server, the tunnel's UDP alone; and no discovery datagram to anyone. The
# host's own neighbour discovery with the server is its link's upkeep, as ARP
# is (no zone has a link on eth1): the host's IPv6 push to the server leaves
# a neighbour entry that the kernel probes with a unicast solicitation five
# seconds later (red once in CI, inside the zone's window).
XF_FILTER = (
    f"(host {server_ip} or host {server_ip6} or (udp and (port 53317 or port 1716))) "
    "and not arp and not (udp and port 51820) "
    "and not (icmp6 and (ip6[40] == 135 or ip6[40] == 136))"
)


def xf_sha(node, path):
    return node.succeed(f"sha256sum {path}").split()[0]


def xf_log():
    """The server's endpoint's log: method, path, peer[, sha256]."""
    return [l.split() for l in server.succeed("cat /tmp/xfer.log").splitlines()]


def xf_peers(method, path):
    return [f[2] for f in xf_log() if f[:2] == [method, path]]


def xf_server_addrs():
    """The server's own addresses on the LAN, both families."""
    out = server.succeed("ip -o addr show dev eth1 scope global | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1")
    return {ipaddress.ip_address(a) for a in out.split()}


def xf_push(target, name):
    """The server sends a file to a program on the machine at `target`:
    (curl's code, what it said). Bounded."""
    return server.execute(
        f"curl -sS -g -m 20 --connect-timeout 5 --upload-file /srv/xfer/push.bin "
        f"http://{target}:{XF_IN}/{name}.bin </dev/null 2>&1"
    )


def xf_why(code):
    """curl's code, in words: 7 is a refusal (a reset, or no route), 28 a
    connection nobody answered in time."""
    return {7: "refused", 28: "timed out"}.get(code, "failed") + f" (curl {code})"


def xf_heard():
    """What the server's LAN side heard of discovery: port, sender, payload."""
    out = server.succeed("cat /tmp/xfer-hear.log")
    return [l.split(" ", 2) for l in out.splitlines() if l.count(" ") >= 2]


def xf_announce(prefix, tag):
    out = alice(f"{prefix} {XF_PY} {XF}/xfer.py announce {tag} {XF_BCAST}")
    print(f"discovery from {tag}:\n{out}")
    return out


def xf_heard_after(tag):
    """The host announces itself after `tag` did, and the server hears it:
    whatever `tag` sent over the LAN would have come before. A plain program
    of the host's: through `cellward run unconfined` the same interpreter
    running in a zone at that moment is the launch's conflict warning, which
    cancels it when its dialog cannot open (red once in CI)."""
    xf_announce("", f"after-{tag}")
    server.wait_until_succeeds(
        f"grep -qxF '1716 {XF_MIP} cellward-discovery after-{tag}' /tmp/xfer-hear.log",
        timeout=30,
    )
    return [h for h in xf_heard() if h[2] == f"cellward-discovery {tag}"]


def xf_watch(unit):
    machine.succeed(
        f"systemd-run --unit={unit} tcpdump -n --immediate-mode -U -i eth1 "
        f"-w /tmp/{unit}.pcap {shlex.quote(XF_FILTER)}"
    )
    machine.wait_until_succeeds(f"journalctl -u {unit} | grep -q 'listening on eth1'", timeout=60)


def xf_watched(unit):
    machine.succeed(f"systemctl stop {unit}")
    return machine.succeed(f"tcpdump -nr /tmp/{unit}.pcap 2>/dev/null").strip()


def xf_serve_on_machine(unit, prefix, tag):
    """A program on the machine that takes files on XF_IN, run as `prefix`
    runs it; waited for by the line it writes once it listens."""
    inbox = f"{XF}/in-{tag}"
    alice(f"rm -rf {inbox} {inbox}.log && mkdir -p {inbox}")
    alice(
        f"systemd-run --user --collect --unit={unit} -E PATH=\"$PATH\" "
        f"{prefix} {XF_PY} {XF}/xfer.py serve {XF_IN} {inbox} {inbox}.log"
    )
    machine.wait_until_succeeds(f"grep -qx ready {inbox}.log", timeout=90)
    return inbox


def xf_zone(zone, addr, addr6):
    """A program of `zone` (its tunnel's addresses `addr`, `addr6`) moves
    files: up to the server's LAN address and down from its tunnel address,
    through the tunnel only; the server cannot reach its listener; its
    discovery reaches no LAN."""
    run = f"cellward run {zone} --"
    inbox = xf_serve_on_machine(f"xfin-{zone}", run, zone)
    # It listens: its own container reaches it.
    out = alice(f"{run} curl -sS -g -m 10 http://127.0.0.1:{XF_IN}/ping </dev/null")
    assert "pong" in out, f"the zone's listener does not answer in its own container: {out}"

    xf_watch(f"xfw-{zone}")
    # Whether the zone's discovery even enters the tunnel: the server's side
    # of it, for the record.
    server.succeed(
        f"systemd-run --unit=xfwg-{zone} tcpdump -n --immediate-mode -U -i wg0 "
        f"-w /tmp/xfwg-{zone}.pcap 'udp and (port 53317 or port 1716)'"
    )
    server.wait_until_succeeds(f"journalctl -u xfwg-{zone} | grep -q 'listening on wg0'", timeout=60)

    # Up, by the same LAN address the host uses: into the tunnel with the
    # rest, and the server sees the tunnel's address.
    out = alice(
        f"{run} curl -sS -g -f -m 120 --upload-file {XF}/up.bin "
        f"http://{server_ip}:{XF_PORT}/{zone}-up.bin </dev/null"
    )
    assert f"peer={addr} sha256={XF_UP}" in out, f"{zone}: the upload: {out}"
    assert xf_peers("PUT", f"/{zone}-up.bin") == [addr], xf_log()
    assert xf_sha(server, f"/srv/xfer/{zone}-up.bin") == XF_UP
    XF_ROWS.append((f"{zone}: upload to the server's LAN address", "works", addr, "equal"))

    # Down, from the tunnel's own address of the server.
    alice(
        f"{run} curl -sS -g -f -m 120 -o {XF}/{zone}-down.bin "
        f"'http://10.99.0.1:{XF_PORT}/down.bin?from={zone}' </dev/null"
    )
    assert xf_sha(machine, f"{XF}/{zone}-down.bin") == XF_DOWN, f"{zone}: the download differs"
    assert xf_peers("GET", f"/down.bin?from={zone}") == [addr], xf_log()
    XF_ROWS.append((f"{zone}: download from 10.99.0.1", "works", addr, "equal"))

    # The server connects to the zone's program through the tunnel: the
    # zone's address ends in the zone's app namespace, where nothing listens
    # — the instance's passt takes nothing in.
    for target in (addr, f"[{addr6}]"):
        code, said = xf_push(target, f"{zone}-tunnel")
        print(f"server -> {target}:{XF_IN} through the tunnel: rc={code} {said.strip()}")
        assert code != 0, f"the server reached a program in {zone} through the tunnel: {said}"
        XF_ROWS.append((f"{zone}: the server connects to its program at {target}", xf_why(code), "-", "-"))

    # LAN discovery, as LocalSend and KDE Connect announce themselves.
    xf_announce(run, zone)

    leaked = xf_watched(f"xfw-{zone}")
    assert not leaked, f"{zone}: packets on eth1 around the tunnel:\n{leaked}"
    server.succeed(f"systemctl stop xfwg-{zone}")
    # What went into the tunnel is the tunnel's: the VPN server's to see, as
    # everything else a program sends, never the LAN's.
    tunnel = server.succeed(f"tcpdump -nr /tmp/xfwg-{zone}.pcap 2>/dev/null")
    print(f"{zone}'s discovery inside the tunnel, as the server's wg0 saw it:\n{tunnel}")
    # Multicast does not even go into the tunnel: an instance has an
    # unreachable route for it (zone.rs `instance_ground`, 2026-09-28).
    assert GROUP4_TEXT not in tunnel, f"{zone}'s multicast went into the tunnel:\n{tunnel}"

    # And from the LAN, by the host's addresses — with the capture off: a
    # LAN flow by nature. The firewall lets the port in (the host's own
    # program took files on it): nothing of the host's listens there.
    for target in (XF_MIP, f"[{XF_MIP6}]"):
        code, said = xf_push(target, f"{zone}-lan")
        print(f"server -> {target}:{XF_IN} over the LAN: rc={code} {said.strip()}")
        assert code != 0, f"the server reached a program in {zone} over the LAN: {said}"
        XF_ROWS.append((f"{zone}: the server connects to its program at {target}", xf_why(code), "-", "-"))
    got = machine.succeed(f"cat {inbox}.log")
    assert "PUT" not in got, f"a file came in to a program of {zone}:\n{got}"
    alice(f"systemctl --user stop xfin-{zone}")

    heard = xf_heard_after(zone)
    assert not heard, f"{zone}'s discovery reached the LAN: {heard}"
    carried = "into the tunnel: " + ", ".join(
        sorted(set(re.findall(r" > (\S+)\.(?:53317|1716):", tunnel)))
    ) if tunnel.strip() else "not even into the tunnel"
    XF_ROWS.append((f"{zone}: LAN discovery (multicast 53317, broadcast 1716)",
                    f"nothing on eth1, the LAN hears nothing; {carried}", "-", "-"))


def xf_without_zones():
    """Set up both sides, then move files as a program of the host does."""
    global XF_UP, XF_DOWN, XF_PUSH
    alice(f"mkdir -p {XF}/shared")
    machine.copy_from_host(xf_helper_host, f"{XF}/xfer.py")
    machine.succeed(f"chown alice {XF}/xfer.py && chmod 0644 {XF}/xfer.py")
    server.copy_from_host(xf_helper_host, "/root/xfer.py")
    # A few megabytes each way, random: a file, not a greeting.
    alice(f"head -c 4194304 /dev/urandom > {XF}/up.bin")
    XF_UP = xf_sha(machine, f"{XF}/up.bin")
    server.succeed(
        "mkdir -p /srv/xfer && head -c 3145728 /dev/urandom > /srv/xfer/down.bin "
        "&& head -c 2097152 /dev/urandom > /srv/xfer/push.bin"
    )
    XF_DOWN = xf_sha(server, "/srv/xfer/down.bin")
    XF_PUSH = xf_sha(server, "/srv/xfer/push.bin")
    # On every address, eth1 and the tunnel alike: who came is in the log.
    server.succeed(f"systemd-run --unit=xfer {XF_PY} /root/xfer.py serve {XF_PORT} /srv/xfer /tmp/xfer.log")
    server.succeed(f"systemd-run --unit=xferhear {XF_PY} /root/xfer.py hear /tmp/xfer-hear.log")
    server.wait_until_succeeds("grep -qx ready /tmp/xfer.log && grep -qx ready /tmp/xfer-hear.log", timeout=60)

    host = "cellward run unconfined --"
    out = alice(
        f"{host} curl -sS -g -f -m 120 --upload-file {XF}/up.bin "
        f"http://{server_ip}:{XF_PORT}/host-up.bin </dev/null"
    )
    assert f"peer={XF_MIP} sha256={XF_UP}" in out, f"the host's upload: {out}"
    assert xf_sha(server, "/srv/xfer/host-up.bin") == XF_UP
    XF_ROWS.append(("unconfined: upload machine -> server", "works", XF_MIP, "equal"))
    alice(
        f"{host} curl -sS -g -f -m 120 -o {XF}/host-down.bin "
        f"'http://{server_ip}:{XF_PORT}/down.bin?from=host' </dev/null"
    )
    assert xf_sha(machine, f"{XF}/host-down.bin") == XF_DOWN, "the host's download differs"
    assert xf_peers("GET", "/down.bin?from=host") == [XF_MIP], xf_log()
    XF_ROWS.append(("unconfined: download server -> machine", "works", XF_MIP, "equal"))

    # The server sends a file to a program of the host that listens: over
    # IPv4 and IPv6, the LAN's addresses.
    inbox = xf_serve_on_machine("xfin-host", host, "host")
    for target, source in ((XF_MIP, server_ip), (f"[{XF_MIP6}]", server_ip6)):
        code, said = xf_push(target, "push")
        assert code == 0, f"the server could not send to the host's program at {target}: {said}"
        peer = re.search(r"peer=(\S+) sha256=(\S+)", said)
        # The server's address of that family on the LAN: the one its kernel
        # chose, if it has more than one.
        assert peer and peer.group(2) == XF_PUSH, said
        seen = ipaddress.ip_address(peer.group(1))
        assert seen in xf_server_addrs() and seen.version == ipaddress.ip_address(source).version, said
        source = str(seen)
        assert xf_sha(machine, f"{inbox}/push.bin") == XF_PUSH
        machine.succeed(f"rm -f {inbox}/push.bin")
        XF_ROWS.append((f"unconfined: the server sends to a host program at {target}", "works", source, "equal"))
    alice("systemctl --user stop xfin-host")

    # LAN discovery from a program of the host: the server's LAN side hears
    # it, multicast and broadcast.
    xf_announce(host, "host")
    for port in ("53317", "1716"):
        server.wait_until_succeeds(
            f"grep -qxF '{port} {XF_MIP} cellward-discovery host' /tmp/xfer-hear.log", timeout=30
        )
    print("the server's LAN side heard:\n" + server.succeed("cat /tmp/xfer-hear.log"))
    XF_ROWS.append(("unconfined: LAN discovery (multicast 53317, broadcast 1716)", "heard by the server", XF_MIP, "-"))


def xf_tunnel_zone():
    alice("cellward up vmreal")
    xf_zone("vmreal", "10.99.0.2", "fd99::2")
    alice("cellward down vmreal")
    # The peer made anew, as after every stop of vmreal here: the server's
    # session would knock at the zone's last address into the next capture.
    server.succeed(
        f"wg set wg0 peer '{cpub}' remove && "
        f"wg set wg0 peer '{cpub}' allowed-ips 10.99.0.2/32,fd99::2/128"
    )


def xf_hermetic_zone():
    # vmherm's config names a TEST-NET endpoint with no peer behind it: a
    # hermetic zone with a real tunnel of its own, a third peer of the server.
    hpriv = machine.succeed("wg genkey").strip()
    hpub = machine.succeed(f"printf %s '{hpriv}' | wg pubkey").strip()
    spub = server.succeed("wg show wg0 public-key").strip()
    server.succeed(f"wg set wg0 peer '{hpub}' allowed-ips 10.99.0.4/32,fd99::4/128")
    alice(
        f"printf '[Interface]\\nPrivateKey = {hpriv}\\nAddress = 10.99.0.4/32, fd99::4/128\\n"
        f"DNS = 10.99.0.1, fd99::1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\\nEndpoint = {server_ip}:51820\\n' > /tmp/vmhreal.conf"
    )
    alice("cellward add vmhreal /tmp/vmhreal.conf")
    alice("cellward hermetic vmhreal on")
    zone = next(n for n in json.loads(alice("cellward status --json"))["networks"] if n["name"] == "vmhreal")
    assert zone["hermetic"]["value"] is True, zone
    alice("cellward up vmhreal")
    xf_zone("vmhreal", "10.99.0.4", "fd99::4")

    # Two containers of their own homes in it: A's home and /tmp are not
    # B's to see — nor the zone's main-home program's —, and a file passes
    # from one to the other through a directory granted to both.
    alice("cellward container create vmxa && cellward container create vmxb")
    alice(f"cellward container grant vmxa {XF}/shared && cellward container grant vmxb {XF}/shared")
    a_home = "/home/alice/.local/state/vpn-profiles/vmxa/home"
    alice(
        "systemd-run --user --collect --unit=xfa -E PATH=\"$PATH\" "
        "cellward run vmhreal --container vmxa -- sh -c "
        "'head -c 1048576 /dev/urandom > $HOME/a.bin && cp $HOME/a.bin /tmp/a.bin "
        "&& sha256sum $HOME/a.bin > $HOME/a.sha && exec sleep 600'"
    )
    machine.wait_until_succeeds(f"test -s {a_home}/a.sha", timeout=90)
    a_sha = machine.succeed(f"cat {a_home}/a.sha").split()[0]
    # A's own next launch shares its /tmp: the file is there.
    assert alice("cellward run vmhreal --container vmxa -- sha256sum /tmp/a.bin").split()[0] == a_sha
    out = alice(
        "cellward run vmhreal --container vmxb -- sh -c "
        "'test ! -e /tmp/a.bin && test ! -e $HOME/a.bin && echo apart'"
    )
    assert "apart" in out, f"B sees A's /tmp or home: {out}"
    out = alice(
        "cellward run vmhreal -- sh -c "
        f"'test ! -e /tmp/a.bin && ! cat {a_home}/a.bin > /dev/null 2>&1 && echo apart'"
    )
    assert "apart" in out, f"the zone's main-home program sees A's: {out}"
    alice(f"cellward run vmhreal --container vmxa -- sh -c 'cp $HOME/a.bin {XF}/shared/a.bin'")
    out = alice(f"cellward run vmhreal --container vmxb -- sha256sum {XF}/shared/a.bin")
    assert out.split()[0] == a_sha, f"B got another file through the granted directory: {out}"
    XF_ROWS.append(("vmhreal: container A -> container B", "only through a directory granted to both", "-", "equal"))
    alice("systemctl --user stop xfa || true")
    alice("cellward container rm vmxa || true")
    alice("cellward container rm vmxb || true")

    alice("cellward down vmhreal")
    server.succeed(f"wg set wg0 peer '{hpub}' remove")
    alice("cellward rm vmhreal || true")


def xf_offline():
    xf_watch("xfw-offline")
    probe = (
        f"curl -sS -g -m 20 --connect-timeout 5 --upload-file {XF}/up.bin "
        f"http://{server_ip}:{XF_PORT}/offline-up.bin </dev/null; echo up-lan=$?; "
        f"curl -sS -g -m 20 --connect-timeout 5 --upload-file {XF}/up.bin "
        f"http://10.99.0.1:{XF_PORT}/offline-up.bin </dev/null; echo up-tunnel=$?; "
        f"curl -sS -g -m 20 --connect-timeout 5 -o {XF}/offline-down.bin "
        f"'http://{server_ip}:{XF_PORT}/down.bin?from=offline' </dev/null; echo down=$?"
    )
    out = alice(f"cellward run offline -- sh -c {shlex.quote(probe)} 2>&1")
    print(f"offline:\n{out}")
    codes = dict(re.findall(r"^(up-lan|up-tunnel|down)=(\d+)$", out, re.M))
    assert sorted(codes) == ["down", "up-lan", "up-tunnel"], out
    assert all(c != "0" for c in codes.values()), f"a file moved offline: {codes}"
    for what, code in sorted(codes.items()):
        XF_ROWS.append((f"offline: {what}", xf_why(int(code)), "-", "-"))
    xf_announce("cellward run offline --", "offline")
    leaked = xf_watched("xfw-offline")
    assert not leaked, f"packets on eth1 from an offline program:\n{leaked}"
    assert not xf_heard_after("offline"), "offline's discovery reached the LAN"
    server.fail("test -e /srv/xfer/offline-up.bin")
    assert not xf_peers("GET", "/down.bin?from=offline"), xf_log()
    machine.fail(f"test -s {XF}/offline-down.bin")

    server.succeed("systemctl stop xfer xferhear")
    print("vm87, scenario | result | the address the other side saw | sha256")
    for row in XF_ROWS:
        print(" | ".join(row))


with subtest("file transfer without zones: both ways between the machines, from their LAN addresses"):
    xf_without_zones()

with subtest("file transfer in a tunnel zone: through the tunnel only, nothing comes in, no LAN discovery"):
    xf_tunnel_zone()

with subtest("file transfer in a hermetic zone: the same; two containers meet only in a granted directory"):
    xf_hermetic_zone()

with subtest("file transfer offline: nothing moves"):
    xf_offline()
