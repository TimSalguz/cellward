"""tests/vm.nix, continued: the host replaces its resolv.conf by rename while a
zone is up (docs/THREAT-MODEL.md D2).

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, STATE, server_ip; vmreal down, its peer on the server
made anew): the script is handed to the driver's build in one environment
variable, and the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import shlex

# NetworkManager and resolvconf write the host's file anew and rename it
# into place. The zone's own file is a bind mount, and a bind lives on the
# name it was made over: the host's rename takes it away in every other
# mount namespace (the kernel detaches mounts on a dentry renamed over).
# Two layouts: this VM's, where /etc/resolv.conf is a chain of links that
# ends in the zone's own tmpfs over resolved's directory, and the host
# renames the link itself away; and a plain file, where the zone's bind sits
# on /etc/resolv.conf and the rename detaches it. Either way the zone then
# reads the host's file — the host's resolvers, the host's options — and
# the tunnel's DNS is not asked until the zone restarts. What must hold is
# that a name still goes nowhere but into the tunnel: not to the host's
# resolver (which would answer 10.66.66.66), and not out by eth1.
with subtest("the host's resolv.conf replaced by rename: the zone's names go only into the tunnel"):
    first = "tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    machine_ip = machine.succeed(f"ip -4 -o addr show eth1 | head -1 | {first}").strip()
    link = machine.succeed("readlink /etc/resolv.conf").strip()
    assert link, "this VM's /etc/resolv.conf is expected to be a link (resolved)"
    # The host's resolver where a host's resolv.conf names one: its LAN
    # address and its loopback, port 53, writing down every name it is
    # asked.
    machine.succeed(
        "systemd-run --unit=hostdns53 dnsmasq -k --user=root --port=53 --bind-interfaces "
        f"--listen-address=127.0.0.1 --listen-address={machine_ip} --no-resolv "
        "--address=/leaktest.internal/10.66.66.66 --log-queries "
        "--log-facility=/tmp/hostdns53.log"
    )

    def host_asks(name):
        """The host's resolver answers, and has the name written down."""
        for server in (machine_ip, "127.0.0.1"):
            machine.wait_until_succeeds(
                f"dig +time=2 +tries=1 +short @{server} {name}.leaktest.internal "
                "| grep -qx 10.66.66.66"
            )
        machine.wait_until_succeeds(f"grep -q '{name}.leaktest.internal' /tmp/hostdns53.log")

    host_asks("host-d2")
    # Where the zone's names go: into the tunnel, seen on the server's
    # side of it; and nothing to port 53 on the wire outside it.
    server.succeed(
        "systemd-run --unit=d2watch tcpdump -n --immediate-mode -U -i wg0 "
        "-w /tmp/d2.pcap 'udp port 53'"
    )
    server.wait_until_succeeds("journalctl -u d2watch | grep -q 'listening on wg0'")
    machine.succeed(
        "systemd-run --unit=d2leak tcpdump -n --immediate-mode -U -i eth1 "
        "-w /tmp/d2-leak.pcap 'port 53'"
    )
    machine.wait_until_succeeds("journalctl -u d2leak | grep -q 'listening on eth1'")

    host_file = f"nameserver {machine_ip}\\nnameserver 127.0.0.1\\noptions timeout:2 attempts:1\\n"

    def host_renames():
        """The host's file written anew and renamed over /etc/resolv.conf."""
        machine.succeed(
            f"printf '{host_file}' > /etc/.resolv.conf.vz && "
            "mv -f /etc/.resolv.conf.vz /etc/resolv.conf"
        )
        machine.succeed("test -f /etc/resolv.conf && test ! -L /etc/resolv.conf")

    def zone_reads(zp):
        return in_zone(zp, "cat /etc/resolv.conf")

    def zone_asks(zp, name):
        return in_zone(zp, f"sh -c 'getent ahostsv4 {name}.leaktest.internal; echo rc=$?'")

    def bound(zp):
        """Mounts at /etc/resolv.conf in the zone."""
        out = in_zone(zp, "cat /proc/self/mountinfo")
        return sum(1 for l in out.splitlines() if l.split()[4:5] == ["/etc/resolv.conf"])

    # 1. This VM's layout: the zone's file at the end of the chain.
    alice("cellward up vmreal")
    zp = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
    assert "nameserver 10.99.0.1" in zone_reads(zp)
    out = zone_asks(zp, "before-d2a")
    assert "10.99.0.9" in out, f"the tunnel's DNS does not answer: {out}"
    host_renames()
    seen = zone_reads(zp)
    print(f"the host renamed a file over its link; the zone reads:\n{seen}")
    out = zone_asks(zp, "zone-d2a")
    print(f"a name looked up in the zone then: {out}")
    assert "10.66.66.66" not in out, f"DNS LEAK: the host's resolver answered the zone: {out}"

    # 2. A plain file (NetworkManager's, openresolv's): the zone made anew
    # binds over /etc/resolv.conf itself, and the host's rename detaches it.
    alice("cellward down vmreal")
    alice("cellward up vmreal")
    zp = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
    assert bound(zp) == 1, "the zone's resolv.conf is not bound over /etc/resolv.conf"
    assert "nameserver 10.99.0.1" in zone_reads(zp)
    out = zone_asks(zp, "before-d2b")
    assert "10.99.0.9" in out, f"the tunnel's DNS does not answer: {out}"
    host_renames()
    assert bound(zp) == 0, "the host's rename left the zone's bind in place"
    seen = zone_reads(zp)
    print(f"the host renamed a file over the bound one; the zone reads:\n{seen}")
    assert f"nameserver {machine_ip}" in seen, seen
    out = zone_asks(zp, "zone-d2b")
    print(f"a name looked up in the zone then: {out}")
    assert "10.66.66.66" not in out, f"DNS LEAK: the host's resolver answered the zone: {out}"

    # Nothing reached the host's resolver: a name it is asked after the
    # zone's is written down, and the zone's are not — it takes its queries
    # one at a time, so the zone's would have been written first.
    host_asks("host-after-d2")
    log = machine.succeed("cat /tmp/hostdns53.log")
    assert "zone-d2" not in log, f"DNS LEAK: the host's resolver was asked by the zone:\n{log}"
    # Where they went instead: into the tunnel, to the host's addresses as
    # the host's file names them, from the tunnel's address.
    server.succeed("systemctl stop d2watch")
    tunnel = server.succeed("tcpdump -nr /tmp/d2.pcap 2>/dev/null")
    print(f"port 53 inside the tunnel:\n{tunnel}")
    for name in ("zone-d2a", "zone-d2b"):
        asked = [l for l in tunnel.splitlines() if f"{name}.leaktest.internal" in l]
        assert asked, f"{name} never entered the tunnel:\n{tunnel}"
        for line in asked:
            assert f"10.99.0.2." in line and f"> {machine_ip}.53:" in line, line
    machine.succeed("systemctl stop d2leak")
    leaked = machine.succeed("tcpdump -nr /tmp/d2-leak.pcap 2>/dev/null")
    assert not leaked.strip(), f"DNS on eth1, around the tunnel:\n{leaked}"

    alice("cellward down vmreal")
    machine.succeed(f"ln -sfn {shlex.quote(link)} /etc/resolv.conf && test -L /etc/resolv.conf")
    machine.succeed("systemctl stop hostdns53 && rm -f /tmp/hostdns53.log /tmp/d2-leak.pcap")
