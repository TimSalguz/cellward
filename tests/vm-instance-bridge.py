"""tests/vm.nix, continued: a zone carries a container's instance — stage 2
of the container design of 2026-09-27 (docs/CONTAINERS.md §3.3,
docs/LEAK-MODEL.md «Шлюзовая архитектура»).

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, STATE, rzpid, json, re, shlex; vmreal up): the
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

# ikey, instance, in_inst, in_inst_q, CORE: tests/vm-instance-helpers.py.


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


def in_i(cmd):
    return in_inst("vmbr", "vmreal", cmd)


def in_i_q(cmd):
    return in_inst_q("vmbr", "vmreal", cmd)


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

with subtest("the zone back as another one: cut until the person says"):
    alice("cellward down vmreal")
    wait_exit("vmbr", "none", "zone-down")
    alice(f"printf '# another config\\n' >> {STATE}/vmreal/config.conf")
    alice("cellward up vmreal")
    wait_exit("vmbr", "none", "zone-changed")
    links = in_i("ip -o link show")
    assert len(links.strip().splitlines()) == 1, links
    out = alice("cellward container reattach vmbr")
    assert "vmbr" in out, out
    wait_exit("vmbr", "through", None)
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

with subtest("a zone of a previous build (no bridge): entered as before, and the person told"):
    alice(f"rm {STATE}/vmreal/bridge.sock")
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; "
            "cellward run vmreal -- readlink /proc/self/ns/net 2>&1"
        )
    )
    assert code == 0 and "прошлой сборкой" in out, out
    zone_ns = machine.succeed(
        f"readlink /proc/$(cat {STATE}/vmreal/zone.pid)/ns/net"
    ).strip()
    assert zone_ns in out, (zone_ns, out)
    status = json.loads(alice("cellward status --json"))
    net = next(n for n in status["networks"] if n["name"] == "vmreal")
    assert net["bridge"] is False, net
    # Restarted, it carries instances again.
    alice("cellward down vmreal")
    alice("cellward up vmreal")
    machine.succeed(f"test -S {STATE}/vmreal/bridge.sock")

# The zone was restarted: its app namespace is another process now.
rzpid = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
