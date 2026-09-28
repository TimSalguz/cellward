# Exec'd by tests/vm.nix in the test script's globals (the script's
# 128 KiB limit, 2026-09-28): the AmneziaWG section, moved out as it was.
# It uses the script's helpers and the server set up before it.
# --- The obfuscated tunnel: AmneziaWG as a real user runs it ----------
# Everything so far was wire-compatible with plain WireGuard. This zone
# is the branch nothing else in the project touches: junk packets before
# the handshake (Jc/Jmin/Jmax), junk prefixes on the handshake packets
# (S1/S2) and non-standard message-type headers (H1..H4), carried from
# the config through `awg setconf` into the kernel on BOTH ends. A stock
# WireGuard peer cannot answer such a client at all — so the handshake
# below is itself the proof that the parameters arrived where they had
# to.
#
# The values: H1..H4 must be four non-overlapping ranges, and they must
# stay clear of the standard message types 1..4 or the traffic would be
# recognisable again; S1/S2 must not make an initiation packet the size
# of a response one (S2 == S1 + 56); Jmin < Jmax, and both well under
# the maximum message size. Written as printf escapes, shared verbatim
# by the server config and the zone config.
AWG_JUNK = (
    "Jc = 4\\nJmin = 40\\nJmax = 70\\nS1 = 30\\nS2 = 40\\n"
    "H1 = 1234567\\nH2 = 2345678\\nH3 = 3456789\\nH4 = 4567890\\n"
)

# vmreal is really down before the next capture is armed: its own tunnel
# UDP (port 51820) is not in the new filter's exception, and a straggler
# would read as a leak.
status = alice("systemctl --user is-active vpn-zone@vmreal.service || true").strip()
assert status in ("inactive", "failed"), status

with subtest("obfuscated peer: a second, amneziawg interface on the server VM"):
    server.succeed(
        "awg genkey > /root/awg.key && awg pubkey < /root/awg.key > /root/awg.pub"
    )
    apub = server.succeed("cat /root/awg.pub").strip()
    opriv = machine.succeed("wg genkey").strip()
    opub = machine.succeed(f"printf %s '{opriv}' | wg pubkey").strip()
    server.succeed(
        "printf '[Interface]\\nPrivateKey = %s\\nListenPort = 51821\\n"
        + AWG_JUNK
        + "\\n[Peer]\\nPublicKey = %s\\nAllowedIPs = 10.98.0.2/32\\n' "
        + f"\"$(cat /root/awg.key)\" '{opub}' > /root/awg1.conf"
    )
    server.succeed(
        "ip link add awg1 type amneziawg && "
        "awg setconf awg1 /root/awg1.conf && "
        "ip addr add 10.98.0.1/24 dev awg1 && "
        "ip link set awg1 up"
    )
    out = server.succeed("ip -d link show awg1")
    assert "amneziawg" in out, f"server awg1 is not an amneziawg link:\n{out}"
    # A separate responder on a separate subnet, so a packet that took
    # the wrong tunnel cannot pass for a right one.
    server.succeed(
        "systemd-run --unit=hello-awg socat "
        "TCP-LISTEN:8081,bind=10.98.0.1,fork,reuseaddr "
        "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
    )

with subtest("cellward add vmawg: a config with real obfuscation parameters"):
    alice(
        f"printf '[Interface]\\nPrivateKey = {opriv}\\nAddress = 10.98.0.2/32\\n"
        + AWG_JUNK
        + f"\\n[Peer]\\nPublicKey = {apub}\\nAllowedIPs = 0.0.0.0/0\\n"
        + f"Endpoint = {server_ip}:51821\\n' > /tmp/vmawg.conf"
    )
    alice("cellward add vmawg /tmp/vmawg.conf")

# Armed before the zone comes up, so the very first junk packet is under
# watch: towards the server, only the obfuscated tunnel's own UDP may
# ever appear on the wire. Not IGMP: the server's membership reports to
# 224.0.0.22 — its multicast listener of the file transfer test leaving —
# match `host`, and carry nothing (red once in CI, 2026-09-28).
with subtest("leak watch armed for the obfuscated tunnel"):
    machine.succeed(
        "systemd-run --unit=leakawg tcpdump -n --immediate-mode -i eth1 "
        f"-w /tmp/leak-awg.pcap 'host {server_ip} and not arp and not igmp "
        "and not (udp and port 51821)'"
    )
    machine.wait_until_succeeds(
        "journalctl -u leakawg | grep -q 'listening on eth1'"
    )

with subtest("cellward up vmawg: the obfuscated zone comes up"):
    alice("cellward up vmawg")
    alice("systemctl --user is-active vpn-zone@vmawg.service")
    machine.succeed(f"test -f {STATE}/vmawg/ready")

azpid = machine.succeed(f"cat {STATE}/vmawg/zone.pid").strip()

with subtest("the obfuscated zone rides amneziawg as well"):
    out = in_zone(azpid, "ip -d link show awg0")
    assert "amneziawg" in out, f"awg0 is not an amneziawg link:\n{out}"

# Traffic FIRST, handshake second — and not the other way round: nothing
# in the zone sends anything of its own, and WireGuard (AmneziaWG with
# it) only initiates a handshake when there is a packet to carry. Asking
# `cellward check` before any traffic waits forever on a tunnel that is
# perfectly fine, merely idle. The TCP connection is what starts it: the
# SYN queues behind the handshake and its retransmit gets through.
with subtest("real traffic through the obfuscated tunnel"):
    out = in_zone(azpid, "socat -T10 - TCP:10.98.0.1:8081")
    assert "peer=10.98.0.2" in out, f"server saw someone else: {out}"

with subtest("obfuscated handshake: cellward check reports a live tunnel"):
    # Same 5-second status mirror as above; give it a couple of cycles.
    machine.wait_until_succeeds(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        "cellward check vmawg'",
        timeout=60,
    )

with subtest("the obfuscated tunnel's leak capture is empty"):
    machine.succeed("systemctl stop leakawg")
    count = machine.succeed(
        "tcpdump -nr /tmp/leak-awg.pcap 2>/dev/null | wc -l"
    ).strip()
    if count != "0":
        escaped = machine.succeed("tcpdump -nr /tmp/leak-awg.pcap 2>/dev/null")
        raise AssertionError(
            f"packets escaped the obfuscated tunnel:\n{escaped}"
        )
    alice("cellward down vmawg")
