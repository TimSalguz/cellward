"""tests/vm.nix, continued: the host replaces its resolv.conf by rename while a
zone and a container's instance are up (docs/THREAT-MODEL.md D2).

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, in_zone_root, STATE, cpub, ikey, instance, in_placed,
in_placed_q; vmreal down, its peer on the server made anew): the script is
handed to the driver's build in one environment variable, and the kernel
takes 128 KiB there (MAX_ARG_STRLEN).
"""

import json
import shlex

# NetworkManager and resolvconf write the host's file anew and rename it
# into place, and the kernel detaches every mount on the old name in every
# other mount namespace. Until 2026-09-28 a zone's own resolv.conf went with
# it: the zone read the host's file — the host's resolvers, asked through
# the tunnel — until it restarted. Now a space's own file is bound over the
# name /etc/resolv.conf itself, not where its links lead, and the space
# watches /etc and lays its file there again when the host replaces the name
# (rust/src/rebind.rs); its /etc is shared with its launches, so a program
# launched before the rename gets the file laid again too. Two layouts: this
# VM's, where /etc/resolv.conf is a chain of links to resolved's stub and
# the host renames a plain file over the link; and a plain file from the
# start, renamed over by another. Either way the zone, a program launched
# before the rename and one launched after read their own file again and ask
# the tunnel's DNS; nothing reaches the host's resolver, which would answer
# 10.66.66.66, and nothing leaves by eth1.
D2 = "vmd2"
MARK = "4848"
HELD = f"pgrep -u alice -xf '(/[^ ]*/)?sleep {MARK}'"
FORWARDER = "nameserver 10.254.255.253"
first = "tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
machine_ip = machine.succeed(f"ip -4 -o addr show eth1 | head -1 | {first}").strip()
link = machine.succeed("readlink /etc/resolv.conf").strip()
nss_link = machine.succeed("readlink /etc/nsswitch.conf").strip()
host_file = f"nameserver {machine_ip}\\nnameserver 127.0.0.1\\noptions timeout:2 attempts:1\\n"
# Every name the spaces asked, for the leak checks at the end.
asked = []


def host_asks(name):
    """The host's resolver answers, and has the name written down."""
    for resolver in (machine_ip, "127.0.0.1"):
        machine.wait_until_succeeds(
            f"dig +time=2 +tries=1 +short @{resolver} {name}.leaktest.internal "
            "| grep -qx 10.66.66.66",
            timeout=60,
        )
    machine.wait_until_succeeds(
        f"grep -q '{name}.leaktest.internal' /tmp/hostdns53.log", timeout=30
    )


def host_renames():
    """The host's file written anew and renamed over /etc/resolv.conf."""
    machine.succeed(
        f"printf '{host_file}' > /etc/.resolv.conf.vz && "
        "mv -f /etc/.resolv.conf.vz /etc/resolv.conf"
    )
    machine.succeed("test -f /etc/resolv.conf && test ! -L /etc/resolv.conf")


def held_cmd(cmd):
    """A command in the mount namespace of the program launched before the
    host's rename — `sleep 4848`, the one that holds the instance up. In its
    pid namespace too: the `/proc` there is the instance's, where a process
    of the host's has no `/proc/self`."""
    return f"nsenter --preserve-credentials -U -m -n -p -t $({HELD}) -- {cmd}"


def in_held(cmd):
    return alice(held_cmd(cmd))


def held_q(cmd):
    return "su -l alice -c " + shlex.quote(
        "export XDG_RUNTIME_DIR=/run/user/1000; " + held_cmd(cmd)
    )


def mounts_at(read, point):
    """Mounts at `point` in the mount table `read` gives."""
    out = read("cat /proc/self/mountinfo")
    return sum(1 for l in out.splitlines() if l.split()[4:5] == [point])


def keep_instance():
    """The instance of vmd2 in vmreal, held up by `sleep 4848`."""
    alice(
        "systemd-run --user --collect --unit=d2keep "
        f"cellward run vmreal --container {D2} -- sleep {MARK}"
    )
    machine.wait_until_succeeds(HELD, timeout=60)
    machine.wait_until_succeeds(f"test -f {STATE}/.instances/{ikey(D2)}/ready", timeout=60)


def end_instance():
    alice("systemctl --user stop d2keep")
    machine.wait_until_fails(f"test -e {STATE}/.instances/{ikey(D2)}", timeout=60)


def own_everywhere(zp, tag):
    """The zone, the program launched before and one launched now: each
    reads its own file — laid again, once, on the name — and asks the
    tunnel's DNS, which answers 10.99.0.9."""
    in_zone_q = "su -l alice -c " + shlex.quote(
        "export XDG_RUNTIME_DIR=/run/user/1000; "
        f"nsenter --preserve-credentials -U -n -m -t {zp} -- "
        "grep -qx 'nameserver 10.99.0.1' /etc/resolv.conf"
    )
    # Laid again by an event, not a clock: waited for here only as a test
    # waits (a test's bound).
    machine.wait_until_succeeds(in_zone_q, timeout=30)
    machine.wait_until_succeeds(held_q(f"grep -qx '{FORWARDER}' /etc/resolv.conf"), timeout=30)
    zone_mounts = mounts_at(lambda c: in_zone(zp, c), "/etc/resolv.conf")
    assert zone_mounts == 1, f"the zone's resolv.conf laid {zone_mounts} times"
    held_mounts = mounts_at(in_held, "/etc/resolv.conf")
    assert held_mounts == 1, f"the held launch's resolv.conf laid {held_mounts} times"
    seen = in_held("cat /etc/resolv.conf")
    assert machine_ip not in seen, f"the host's file in the held launch:\n{seen}"
    assert FORWARDER in in_placed(D2, "vmreal", "cat /etc/resolv.conf")
    for where, run in (
        ("zone", lambda c: in_zone(zp, c)),
        ("held", in_held),
        ("new", lambda c: in_placed(D2, "vmreal", c)),
    ):
        name = f"{where}-{tag}"
        asked.append(name)
        out = run(f"sh -c 'getent ahostsv4 {name}.leaktest.internal; echo rc=$?'")
        print(f"{name}: {out}")
        assert "10.66.66.66" not in out, f"DNS LEAK: the host's resolver answered {where}: {out}"
        assert "10.99.0.9" in out, f"the tunnel's DNS does not answer {where}: {out}"


with subtest("the host's resolv.conf replaced by rename: its own laid again in the zone and the instance, names through the tunnel's DNS"):
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
    host_asks("host-d2")
    # Where the spaces' names go: into the tunnel, seen on the server's side
    # of it; and nothing to port 53 on the wire outside it.
    server.succeed(
        "systemd-run --unit=d2watch tcpdump -n --immediate-mode -U -i wg0 "
        "-w /tmp/d2.pcap 'udp port 53'"
    )
    server.wait_until_succeeds("journalctl -u d2watch | grep -q 'listening on wg0'", timeout=60)
    machine.succeed(
        "systemd-run --unit=d2leak tcpdump -n --immediate-mode -U -i eth1 "
        "-w /tmp/d2-leak.pcap 'port 53'"
    )
    machine.wait_until_succeeds("journalctl -u d2leak | grep -q 'listening on eth1'", timeout=60)

    # 1. This VM's layout: the link to resolved's stub, covered in the space.
    alice("cellward up vmreal")
    zp = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
    alice(f"cellward container create {D2} --home layer")
    keep_instance()
    # Bound on the name itself, not at the end of the chain.
    assert mounts_at(lambda c: in_zone(zp, c), "/etc/resolv.conf") == 1
    in_zone(zp, "test ! -L /etc/resolv.conf")
    own_everywhere(zp, "d2a")
    host_renames()
    print(f"the host renamed a file over its link; the zone reads:\n{in_zone(zp, 'cat /etc/resolv.conf')}")
    own_everywhere(zp, "d2b")
    # And again, a plain file over a plain file: the watch goes on.
    host_renames()
    own_everywhere(zp, "d2c")
    # nsswitch.conf the same way (NixOS replaces /etc/static with every
    # switch; a host may replace the name itself): hosts stays files dns.
    machine.succeed(
        "cp -L /etc/nsswitch.conf /etc/.nsswitch.conf.vz && "
        "mv -f /etc/.nsswitch.conf.vz /etc/nsswitch.conf"
    )
    for read in (lambda c: in_zone(zp, c), in_held):
        for _ in range(60):
            if "hosts: files dns" in read("cat /etc/nsswitch.conf"):
                break
            machine.sleep(0.5)
        nss = read("cat /etc/nsswitch.conf")
        assert "hosts: files dns" in nss, f"the host's nsswitch.conf in the space:\n{nss}"
    machine.succeed(
        f"ln -sfn {shlex.quote(nss_link)} /etc/nsswitch.conf && test -L /etc/nsswitch.conf"
    )

with subtest("the host's resolv.conf a plain file: bound on the name, laid again after the rename"):
    # 2. A plain file (NetworkManager's, openresolv's) from the start: the
    # zone and the instance made anew over it.
    end_instance()
    alice("cellward down vmreal")
    alice("cellward up vmreal")
    zp = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
    keep_instance()
    own_everywhere(zp, "d2d")
    host_renames()
    own_everywhere(zp, "d2e")

with subtest("doctor: the nameservers an instance sees are its own; the host's in their stead fail, with the way out"):
    def resolv_check():
        code, out = machine.execute(
            "su -l alice -c "
            + shlex.quote(f"export XDG_RUNTIME_DIR=/run/user/1000; cellward doctor {D2} --json")
        )
        checks = next(i for i in json.loads(out)["instances"] if i["id"] == D2)["checks"]
        return next(c for c in checks if c["id"] == "resolv")

    check = resolv_check()
    assert check["level"] == "ok" and "10.254.255.253" in check["detail"], check
    # Its own taken off in its space, as its root — which no watch lays
    # again: nothing was renamed. What its programs read now is the host's
    # file. (In its pid namespace: umount reads /proc/self/mountinfo.)
    ipid = str(instance(D2)["pid"])
    alice(f"nsenter -U -m -p -t {ipid} -- umount /etc/resolv.conf")
    check = resolv_check()
    assert check["level"] == "fail", check
    assert machine_ip in check["detail"] and "cellward container stop" in check["detail"], check
    # The host's next rename lays it again.
    host_renames()
    machine.wait_until_succeeds(held_q(f"grep -qx '{FORWARDER}' /etc/resolv.conf"), timeout=30)
    check = resolv_check()
    assert check["level"] == "ok", check

    # Nothing reached the host's resolver: a name it is asked after the
    # spaces' is written down, and theirs are not — it takes its queries one
    # at a time, so theirs would have been written first.
    host_asks("host-after-d2")
    asked_of_host = machine.succeed("cat /tmp/hostdns53.log")
    for name in asked:
        assert name not in asked_of_host, (
            f"DNS LEAK: the host's resolver was asked {name}:\n{asked_of_host}"
        )
    # Where they went instead: into the tunnel, to the tunnel's resolver —
    # the zone's own, and the instances' through their forwarder — and never
    # to the host's addresses the host's file names.
    server.succeed("systemctl stop d2watch")
    tunnel = server.succeed("tcpdump -nr /tmp/d2.pcap 2>/dev/null")
    print(f"port 53 inside the tunnel:\n{tunnel}")
    for name in asked:
        lines = [l for l in tunnel.splitlines() if f"{name}.leaktest.internal" in l]
        assert lines, f"{name} never entered the tunnel:\n{tunnel}"
        for line in lines:
            assert "10.99.0.2." in line and "> 10.99.0.1.53:" in line, line
    machine.succeed("systemctl stop d2leak")
    leaked = machine.succeed("tcpdump -nr /tmp/d2-leak.pcap 2>/dev/null")
    assert not leaked.strip(), f"DNS on eth1, around the tunnel:\n{leaked}"

    end_instance()
    alice("cellward down vmreal")
    machine.succeed(f"ln -sfn {shlex.quote(link)} /etc/resolv.conf && test -L /etc/resolv.conf")
    machine.succeed("systemctl stop hostdns53 && rm -f /tmp/hostdns53.log /tmp/d2-leak.pcap")
    # The peer made anew, as after the zone killed: a session the server
    # still holds would knock at the zone's last address, into the next
    # capture.
    server.succeed(
        f"wg set wg0 peer '{cpub}' remove && "
        f"wg set wg0 peer '{cpub}' allowed-ips 10.99.0.2/32,fd99::2/128"
    )
