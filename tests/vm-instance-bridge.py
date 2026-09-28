"""tests/vm.nix, continued: a zone carries a container's instance — stage 2
of the container design of 2026-09-27 (docs/CONTAINERS.md §3.3,
docs/LEAK-MODEL.md «Шлюзовая архитектура»).

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, in_zone_root, STATE, rzpid, json, re, shlex; vmreal up): the
script is handed to the driver's build in one environment variable, and the
kernel takes 128 KiB there (MAX_ARG_STRLEN).

An instance whose network is a zone has a network namespace of its own with
loopback and a tap; its only way out is a `passt --fd` its zone starts in
the zone's app namespace, which the instance's relay pumps. The zone's end
cuts it, and its programs live on with no way out; the zone back as it was
attaches it again, with new addresses; the zone back as another one leaves
it cut until the person says. Entered here as a launch enters it
(`vpn-zone-core container-enter`), the instance asked for as a launch asks
(the file beside its directory).
"""

import ipaddress

# ikey, instance, in_inst, in_inst_q, in_placed, in_placed_q:
# tests/vm-instance-helpers.py.


# The bridge's passt processes in vmreal's app namespace: told by what only
# they are given (bridge.rs `passt_argv`; the bracket keeps the pattern from
# matching itself) and by the namespace — another zone may carry an
# instance too. `ps -C passt` sees nothing: the binary is `passt.avx2` here
# (red once in CI), and pasta is passt as well.
ZONE_PASSTS = (
    f"zns=$(readlink /proc/$(cat {STATE}/vmreal/zone.pid)/ns/net); "
    "for p in $(pgrep -f -- '--map-guest-addr [n]one'); do "
    "[ \"$(readlink /proc/$p/ns/net 2>/dev/null)\" = \"$zns\" ] && echo $p || true; done"
)


def wait_exit(id_, exit_, why):
    """Until the instance's way out is `exit_` for `why` (a test's bound)."""
    for _ in range(240):
        i = instance(id_)
        if i and i["exit"] == exit_ and i["why"] == why:
            return i
        machine.sleep(0.5)
    raise AssertionError(f"{id_}: never {exit_}/{why}: {instance(id_)}")


# Changed on purpose in stage 4: entered as a launch from the desktop is,
# through the user's manager (`in_placed`), and not from a login session
# (`in_inst`). A zone that comes back makes the instance a new epoch now,
# and behind its wall a program the kernel did not let into the epoch has
# no way out (docs/GOTCHAS.md §18).
def in_i(cmd):
    return in_placed("vmbr", "vmreal", cmd)


def in_i_q(cmd):
    return in_placed_q("vmbr", "vmreal", cmd)


def a4_of():
    out = in_i("ip -4 -o addr show dev awg0")
    return re.search(r"inet (10\.254\.\d+\.\d+)/16", out).group(1)


alice("cellward container create vmbr --home layer")
# A launch into the zone, as a person makes one (stage 2c): its container's
# instance is started for it, asked for this network, and holds it up.
alice(
    "systemd-run --user --collect --unit=vmbr-keep "
    "cellward run vmreal --container vmbr -- sleep infinity"
)
machine.wait_until_succeeds(
    f"test -f {STATE}/.instances/{ikey('vmbr')}/ready", timeout=60
)

with subtest("a zone carries an instance: a namespace of its own, out through the zone"):
    i = wait_exit("vmbr", "through", None)
    assert (i["network"], i["container"]) == ("vmreal", "vmbr"), i
    links = in_i("ip -o link show")
    assert len(links.strip().splitlines()) == 2 and ": awg0" in links, links
    own = in_i("readlink /proc/self/ns/net").strip()
    zone_ns = machine.succeed(f"readlink /proc/{rzpid}/ns/net").strip()
    host_ns = machine.succeed("readlink /proc/1/ns/net").strip()
    assert len({own, zone_ns, host_ns}) == 3, (own, zone_ns, host_ns)
    first_a4 = a4_of()
    out = in_i("socat -T10 - TCP:10.99.0.1:8080")
    assert "peer=10.99.0.2" in out, f"the server saw someone else: {out}"
    resolv = in_i("cat /etc/resolv.conf")
    assert "nameserver 10.254.255.253" in resolv, resolv
    assert "nameserver fd63:656c:6c77::53" in resolv, resolv
    assert "10.99.0.1" not in resolv and "fd99::1" not in resolv, resolv
    out = in_i("getent ahostsv4 leaktest.internal")
    assert "10.99.0.9" in out and "10.66.66.66" not in out, f"names: {out}"
    out = in_i("ping -c1 -W5 10.99.0.1")
    assert " 0% packet loss" in out, out
    out = in_i("socat -T10 - TCP6:[fd99::1]:8081")
    seen = re.search(r"peer=\[?([0-9a-fA-F:]+)\]?", out)
    assert seen and ipaddress.ip_address(seen.group(1)) == ipaddress.ip_address(
        "fd99::2"
    ), f"over IPv6: {out}"
    # passt runs as the bridge's own subordinate id, not the zone's root.
    sub = int(machine.succeed("grep '^alice:' /etc/subuid | cut -d: -f2").strip())
    pids = machine.succeed(ZONE_PASSTS).split()
    assert pids, "no passt of the bridge's in the zone"
    uids = machine.succeed(f"ps -o uid= -p {','.join(pids)}").split()
    assert uids and all(int(u) == sub + 2 for u in uids), (uids, sub)

with subtest("an instance reaches nothing that listens in its zone"):
    for bind, port in [("10.99.0.2", 7791), ("127.0.0.1", 7792)]:
        alice(
            f"systemd-run --user --unit=zl{port} nsenter --preserve-credentials -U -n -m -t {rzpid} -- "
            f"socat TCP-LISTEN:{port},bind={bind},fork,reuseaddr OPEN:/tmp/zl-got,creat,append"
        )
        machine.wait_until_succeeds(
            "su -l alice -c "
            + shlex.quote(
                f"nsenter --preserve-credentials -U -n -m -t {rzpid} -- sh -c "
                f"'ss -ltn | grep -q {bind}:{port}'"
            ),
            timeout=30,
        )
        in_i(f"sh -c 'echo from-instance | timeout -s KILL 8 socat -u - TCP:{bind}:{port}; true'")
    machine.sleep(1)
    machine.fail("grep -q from-instance /tmp/zl-got")
    alice("systemctl --user stop zl7791 zl7792")
    machine.succeed("rm -f /tmp/zl-got")

with subtest("the zone's end cuts the instance: its programs live on, with no way out"):
    alice("cellward down vmreal")
    wait_exit("vmbr", "none", "zone-down")
    links = in_i("ip -o link show")
    assert len(links.strip().splitlines()) == 1 and ": lo:" in links, links
    out = in_i("ip -4 route show default")
    assert out.startswith("unreachable default"), out
    # At once, not after a wait for a route.
    in_i("sh -c '! timeout 5 socat -T3 - TCP:10.99.0.1:8080'")
    alice("systemctl --user is-active vmbr-keep")

with subtest("the zone back as it was: attached again, with new addresses"):
    alice("cellward up vmreal")
    wait_exit("vmbr", "through", None)
    assert a4_of() != first_a4, first_a4
    machine.wait_until_succeeds(
        in_i_q("socat -T5 - TCP:10.99.0.1:8080 | grep -q peer=10.99.0.2"), timeout=60
    )
    # Stage 4 (O3 of the design): attached again as a new epoch — every
    # socket of before behind the wall, as in a switch to the same network.
    assert instance("vmbr")["epoch"] == 2, instance("vmbr")

# Stage 2's rule, through stage 4 too (review 2026-09-28): a zone that comes
# back as another one attaches nothing by itself. For a while stage 4
# attached an instance that could make a new epoch whatever the zone came
# back as, and this subtest tested the rule only for one that could not (a
# program of it launched from a login session, outside its epoch); now the
# instance as it runs from the desktop — a new epoch can be made — makes
# one, stays cut in it, and only the person's word attaches it.
with subtest("the zone back as another one: cut until the person says"):
    for _ in range(120):
        if instance("vmbr")["live_switch"]["available"]:
            break
        machine.sleep(0.5)
    else:
        raise AssertionError(f"no new epoch can be made: {instance('vmbr')}")
    alice("cellward down vmreal")
    wait_exit("vmbr", "none", "zone-down")
    alice(f"printf '# another config\\n' >> {STATE}/vmreal/config.conf")
    alice("cellward up vmreal")
    wait_exit("vmbr", "none", "zone-changed")
    links = in_i("ip -o link show")
    assert len(links.strip().splitlines()) == 1, links
    in_i("sh -c '! timeout 5 socat -T3 - TCP:10.99.0.1:8080'")
    # Its new epoch was made (the zone's answer that told the fingerprint
    # comes with the attach, and no attach before a new epoch's wall).
    assert instance("vmbr")["epoch"] == 3, instance("vmbr")
    out = alice("cellward container reattach vmbr")
    assert "vmbr" in out, out
    wait_exit("vmbr", "through", None)
    assert instance("vmbr")["epoch"] == 4, instance("vmbr")
    machine.wait_until_succeeds(
        in_i_q("socat -T5 - TCP:10.99.0.1:8080 | grep -q peer=10.99.0.2"), timeout=60
    )
    events = [
        e for e in json.loads(alice("cellward journal --json"))["events"]
        if e.get("instance") == "vmbr"
    ]
    kinds = [(e["event"], e.get("why")) for e in events]
    assert ("cut", "zone-down") in kinds and ("cut", "zone-changed") in kinds, kinds
    assert ("reattach", None) in kinds and ("attach", None) in kinds, kinds
    epochs = {e.get("epoch") for e in events if e["event"] == "reattach"}
    assert {"2", "4"} <= epochs and "3" not in epochs, events

with subtest("a launch into the zone runs in its container's instance, not in the zone"):
    # The main home's, `main:vmreal`: its own network namespace, the tap,
    # the forwarder; the zone's is the zone's alone.
    ns = alice("cellward run vmreal -- readlink /proc/self/ns/net").strip()
    zone_ns = machine.succeed(
        f"readlink /proc/$(cat {STATE}/vmreal/zone.pid)/ns/net"
    ).strip()
    assert ns != zone_ns, (ns, zone_ns)
    out = alice("cellward run vmreal -- ip -4 -o addr show dev awg0")
    assert "inet 10.254." in out, out
    out = alice("cellward run vmreal -- socat -T10 - TCP:10.99.0.1:8080")
    assert "peer=10.99.0.2" in out, out
    events = json.loads(alice("cellward journal --json"))["events"]
    assert any(
        e["event"] == "instance-start" and e.get("instance") == "main:vmreal"
        for e in events
    ), events
    # Another network for a container that runs in this one: refused.
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; "
            "cellward run offline --container vmbr -- true 2>&1"
        )
    )
    assert code != 0 and "двух сетях" in out, out
    status = json.loads(alice("cellward status --json"))
    net = next(n for n in status["networks"] if n["name"] == "vmreal")
    assert net["bridge"] is True and "vmbr" in net["attached"], net
    c = next(c for c in status["containers"] if c["name"] == "vmbr")
    assert any(r["instance"] == "vmbr" and r["network"] == "vmreal" for r in c["running"]), c

with subtest("the instance ends with its program, and its zone's passt with it"):
    alice("systemctl --user stop vmbr-keep")
    machine.wait_until_fails(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward status --json' "
        "| grep -q '\"id\":\"vmbr\"'",
        timeout=60,
    )
    machine.wait_until_fails(f'test -n "$({ZONE_PASSTS})"', timeout=30)
    alice("cellward container rm vmbr")

with subtest("a zone of a previous build (no bridge): refused, and the person told its restart"):
    # Stage 5 of the container design (2026-09-28): nothing is launched into
    # a zone's own namespaces. Until then this launch went there, into the
    # zone's own network namespace, with a notice (stage 2, and this
    # subtest said so); now it is refused, and the refusal names the way
    # out — the zone's restart.
    alice(f"rm {STATE}/vmreal/bridge.sock")
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; "
            "cellward run vmreal -- readlink /proc/self/ns/net 2>&1"
        )
    )
    assert code != 0 and "не везёт контейнеры" in out, out
    assert "cellward down vmreal; cellward up vmreal" in out, out
    zone_ns = machine.succeed(
        f"readlink /proc/$(cat {STATE}/vmreal/zone.pid)/ns/net"
    ).strip()
    assert zone_ns not in out, (zone_ns, out)
    status = json.loads(alice("cellward status --json"))
    net = next(n for n in status["networks"] if n["name"] == "vmreal")
    assert net["bridge"] is False, net

with subtest("doctor: no program in a zone's own namespaces, and one put there is named"):
    def zone_programs():
        out = json.loads(alice("cellward doctor vmreal --json"))
        zone = next(z for z in out["zones"] if z["name"] == "vmreal")
        return next(c for c in zone["checks"] if c["id"] == "programs")

    found = zone_programs()
    assert found["level"] == "ok", found
    # One there as a previous build's launch put it — or a person's nsenter:
    # in the zone's app namespace, no descendant of the zone's process.
    zp = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
    alice(
        "systemd-run --user --unit=vmlegacy nsenter --preserve-credentials "
        f"-U -n -m -t {zp} -- sleep 3600"
    )
    machine.wait_until_succeeds(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward doctor vmreal --json' "
        "| grep -q '\"id\":\"programs\",\"level\":\"warn\"'",
        timeout=60,
    )
    found = zone_programs()
    assert "Закрой их" in found["detail"], found
    legacy = alice("systemctl --user show -p MainPID --value vmlegacy").strip()
    assert f"({legacy})" in found["detail"], (legacy, found)
    alice("systemctl --user stop vmlegacy")
    machine.wait_until_succeeds(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward doctor vmreal --json' "
        "| grep -q '\"id\":\"programs\",\"level\":\"ok\"'",
        timeout=60,
    )

with subtest("the zone of a previous build restarted: it carries instances again"):
    # Restarted, it carries instances again — and a launch goes out through
    # it, which is also the tunnel's first handshake since the restart (the
    # checks after this file want one: WireGuard makes none with nothing
    # to send; red once in CI).
    alice("cellward down vmreal")
    alice("cellward up vmreal")
    machine.succeed(f"test -S {STATE}/vmreal/bridge.sock")
    machine.wait_until_succeeds(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; "
            "cellward run vmreal -- ping -c1 -W5 10.99.0.1"
        ),
        timeout=60,
    )

# The zone was restarted: its app namespace is another process now.
rzpid = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()

# The tunnel quiet before the next file kills the zone. The echo's reply was
# the last data: the zone owes the server a keepalive, and until it has sent
# it the server waits for one, then knocks with a handshake — at a port
# nobody holds once the zone is killed, and the host's "port unreachable"
# lands in the leak capture (red once in CI). Its keepalive sent, neither
# side owes the other anything: waited for as that, by the tunnel's count
# of what it sent. The zone's tunnel is an amneziawg link, which `wg` does
# not speak to (red once in CI): the zone's own `awg`, from its unit.
AWG = re.search(r"--awg (\S+)", alice("systemctl --user cat vpn-zone@vmreal.service")).group(1)


def tunnel_sent():
    return int(in_zone_root(rzpid, f"{AWG} show awg0 transfer").split()[2])


sent = tunnel_sent()
for _ in range(120):
    if tunnel_sent() > sent:
        break
    machine.sleep(0.5)
else:
    raise AssertionError(f"the zone's tunnel sent no keepalive (it sent {sent} bytes)")
