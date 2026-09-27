"""tests/vm.nix, continued: containers' instances with no network — stage 1
of the container design of 2026-09-27 (docs/CONTAINERS.md §3.6,
docs/LEAK-MODEL.md «Экземпляр контейнера»).

Executed by the main test script with exec(), in its globals (machine,
alice, STATE, json, shlex): the script is handed to the driver's build in
one environment variable, and the kernel takes 128 KiB there
(MAX_ARG_STRLEN).

Every launch whose network is `offline` runs in its container's instance,
`vpn-zone-container@<id>.service`: namespaces of the container's own, the
covers of a zone, no way out — and the `offline` zone is never started for
it. An instance ends with its last program, and ends its programs when it
is stopped.
"""


def instance(id_):
    """The running instance `id_` as `cellward status --json` says it, or None."""
    out = json.loads(alice("cellward status --json"))
    return next((i for i in out["instances"] if i["id"] == id_), None)


def in_c(c, cmd):
    """A launch into container `c`'s instance, as a person makes one."""
    return alice(f"cellward run offline --container {c} -- {cmd}")


def keep(c, unit):
    """A program that keeps `c`'s instance up (an instance ends with its last
    program), and the instance up."""
    alice(
        f"systemd-run --user --collect --unit={unit} "
        f"cellward run offline --container {c} -- sleep infinity"
    )
    machine.wait_until_succeeds(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward status --json' "
        f"| grep -q '\"id\":\"{c}\"'",
        timeout=60,
    )


def none_left_in(netns):
    """Wait until no process is in the network namespace `netns` — the
    waiters of the launches (`container-enter`) end right after their
    programs."""
    machine.wait_until_succeeds(
        "for p in /proc/[0-9]*; do "
        f"[ \"$(readlink $p/ns/net 2>/dev/null)\" = '{netns}' ] && exit 1; "
        "done; exit 0",
        timeout=30,
    )


def zone_offline_not_started():
    state = alice("systemctl --user is-active vpn-zone@offline.service || true").strip()
    assert state != "active", f"the offline zone was started for a launch: {state}"


# Hermetic, as `offline` is by default (not in this VM, whose default is
# declared off): a /tmp of its own, no `systemd --user`, the broker. Frozen
# as each instance comes up — none is up now.
alice(f"mkdir -p {STATE}/offline && touch {STATE}/offline/offline")
alice("cellward hermetic offline on")
alice("cellward container create vmia --home layer")
alice("cellward container create vmib --home layer")
keep("vmia", "vmia-keep")
keep("vmib", "vmib-keep")

with subtest("an offline launch runs in its container's instance: loopback only, apart"):
    a, b = instance("vmia"), instance("vmib")
    assert a and b, (a, b)
    assert (a["network"], a["exit"], a["why"], a["container"]) == (
        "offline",
        "none",
        "offline",
        "vmia",
    ), a
    # A pid namespace of its own since stage 3 (tests/vm-promise-pidns.py).
    # Changed on purpose in stage 4: a live switch can be made — its keeper
    # found its unit's cgroup, nft's `socket cgroupv2` and SOCK_DESTROY, and
    # its one program (started through the user's manager, `keep`) is in its
    # first epoch — where stage 3 had none at all.
    assert a["pid_namespace"] is True and a["live_switch"]["available"] is True, a
    assert a["epoch"] == 1, a
    out = in_c("vmia", "ip -o link show")
    lines = [l for l in out.strip().splitlines() if ": " in l]
    assert len(lines) == 1 and ": lo:" in lines[0], f"an instance with more than lo: {out}"
    ns_a = in_c("vmia", "readlink /proc/self/ns/net").strip()
    ns_b = in_c("vmib", "readlink /proc/self/ns/net").strip()
    host = alice("readlink /proc/self/ns/net").strip()
    assert len({ns_a, ns_b, host}) == 3, (ns_a, ns_b, host)
    zone_offline_not_started()
    status = json.loads(alice("cellward status --json"))
    offline = next(n for n in status["networks"] if n["name"] == "offline")
    assert sorted(offline["attached"]) == ["vmia", "vmib"], offline
    c = next(c for c in status["containers"] if c["name"] == "vmia")
    assert c["instances"] == ["vmia"], c
    assert any(r["instance"] == "vmia" for r in c["running"]), c

def live_switch_is(id_, available, reason):
    """Until the instance's keeper notes this (a test's bound)."""
    for _ in range(120):
        i = instance(id_)
        if i and (i["live_switch"]["available"], i["live_switch"]["reason"]) == (available, reason):
            return
        machine.sleep(0.5)
    raise AssertionError(f"{id_}: never {available}/{reason}: {instance(id_)}")


# Stage 4 (docs/LEAK-MODEL.md «Смена сети на ходу»): a launch through the
# user's manager is put into the instance's epoch — the cgroup a live switch
# moves, whose sockets alone the rules let out after one; a launch from a
# login session (su here) the kernel does not let move, and while it runs
# the instance cannot be switched live.
with subtest("an instance's programs are in its epoch; one from a login session holds the switch"):
    cg = alice(
        "systemctl --user show -p ControlGroup --value vpn-zone-container@vmia.service"
    ).strip()
    assert cg.endswith("/vpn-zone-container@vmia.service"), cg
    # The unit's slice has `\x2d` in its name: quoted for the shell.
    unit_cg = shlex.quote(f"/sys/fs/cgroup{cg}")
    procs = machine.succeed(f"cat {unit_cg}/e1/cgroup.procs").split()
    comms = [machine.succeed(f"cat /proc/{p}/comm").strip() for p in procs]
    assert "sleep" in comms, (procs, comms)
    keeper = machine.succeed(f"cat {unit_cg}/infra/cgroup.procs").split()
    assert keeper and not set(keeper) & set(procs), (keeper, procs)
    machine.succeed(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; setsid cellward run offline --container "
            "vmia -- sleep 4343 </dev/null >/dev/null 2>&1 &"
        )
    )
    live_switch_is("vmia", False, "outside")
    outsider = machine.succeed("pgrep -xf 'sleep 4343'").strip()
    assert f"{cg}/e1" not in machine.succeed(f"cat /proc/{outsider}/cgroup"), outsider
    machine.succeed("pkill -xf 'sleep 4343'")
    live_switch_is("vmia", True, None)

with subtest("two containers' instances share no /tmp, no abstract socket, no System V IPC"):
    in_c("vmia", "sh -c 'echo a > /tmp/vmia-mark'")
    in_c("vmia", "test -e /tmp/vmia-mark")
    in_c("vmib", "test ! -e /tmp/vmia-mark")
    machine.fail("test -e /tmp/vmia-mark")
    alice(
        "systemd-run --user --collect --unit=vmia-abs cellward run offline --container vmia "
        "-- socat ABSTRACT-LISTEN:vmia-abs,fork /dev/null"
    )
    machine.wait_until_succeeds(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; cellward run offline --container vmia "
            "-- socat -u /dev/null ABSTRACT-CONNECT:vmia-abs"
        ),
        timeout=60,
    )
    in_c("vmib", "sh -c '! socat -u /dev/null ABSTRACT-CONNECT:vmia-abs'")
    out = in_c("vmia", "sh -c 'ipcmk -M 4242 >/dev/null && ipcs -m'")
    assert "4242" in out, out
    assert "4242" not in in_c("vmib", "ipcs -m")
    assert "4242" not in alice("ipcs -m")

with subtest("the broker: the same container starts, another one is a person's to say"):
    in_c("vmia", "cellward run offline --container vmia -- sh -c 'echo in-a > /tmp/broker-a'")
    machine.wait_until_succeeds(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; cellward run offline --container vmia "
            "-- grep -q in-a /tmp/broker-a"
        ),
        timeout=60,
    )
    # Into another container: a crossing — and nobody to ask here.
    machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; cellward run offline --container vmia "
            "-- cellward run offline --container vmib -- true"
        )
    )
    lines = [
        l
        for l in alice("cellward journal --json").splitlines()
        if '"event":"broker"' in l and '"origin":"offline/vmia"' in l
    ]
    assert any('"decision":"started"' in l for l in lines), lines
    assert any('"decision":"refused"' in l for l in lines), lines

with subtest("an instance's own processes: the fourth subordinate id, out of its programs' reach"):
    pid = instance("vmia")["pid"]
    sub = int(machine.succeed("grep '^alice:' /etc/subuid | cut -d: -f2").strip())
    holder = machine.succeed(f"awk '/^PPid:/ {{print $2}}' /proc/{pid}/status").strip()
    for p in [str(pid), holder]:
        uid = machine.succeed(f"awk '/^Uid:/ {{print $2}}' /proc/{p}/status").strip()
        assert int(uid) == sub + 3, f"{p}: uid {uid}, subuid {sub}"
    # Since stage 3 the instance's process is its pid 1, and a program sees
    # it as that, /proc/1 — the holder not at all: it is not in the
    # instance's pid namespace (tests/vm-promise-pidns.py). Out of its reach
    # as before.
    in_c("vmia", "sh -c 'grep -q container-holder /proc/1/cmdline && ! cat /proc/1/environ'")
    # Nor the registry, nor the host's cgroups.
    in_c("vmia", f"test ! -e {STATE}/.running")
    out = in_c("vmia", "ls -A /sys/fs/cgroup")
    assert out.strip() == "", f"the host's cgroups in an instance: {out}"
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; cellward doctor vmia --json")
    )
    checks = next(i for i in json.loads(out)["instances"] if i["id"] == "vmia")["checks"]
    by_id = {c["id"]: c for c in checks}
    assert by_id["instance-root"]["level"] == "ok", checks
    assert "probe" not in by_id, checks
    assert by_id["links"]["level"] == "ok", checks

with subtest("cellward container kill ends every program of the container at once"):
    alice(
        "systemd-run --user --collect --unit=vmib-more cellward run offline --container vmib "
        "-- sh -c 'sleep infinity & sleep infinity & wait'"
    )
    machine.wait_until_succeeds(
        f"test $(for p in $(pgrep -x sleep); do readlink /proc/$p/ns/net; done "
        f"| grep -cxF '{ns_b}') -ge 3",
        timeout=60,
    )
    out = alice("cellward container kill vmib")
    assert re.search(r"убито программ — [3-9]", out), out
    none_left_in(ns_b)
    assert instance("vmib") is None
    out = alice("cellward journal --json")
    assert '"event":"kill","container":"vmib"' in out, out
    zone_offline_not_started()

with subtest("an instance ends with its last program, by that event alone"):
    alice("systemctl --user stop vmia-keep vmia-abs")
    machine.wait_until_fails(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward status --json' "
        "| grep -q '\"id\":\"vmia\"'",
        timeout=60,
    )
    none_left_in(ns_a)
    out = alice("cellward journal --json")
    assert re.search(r'"event":"instance-stop","instance":"vmia","why":"idle"', out), out
    state = alice(
        "systemctl --user is-active 'vpn-zone-container@vmia.service' || true"
    ).strip()
    assert state != "active", state

with subtest("a throwaway container is erased when its instance ends"):
    before = set(alice(f"ls -A {STATE}/.throwaway 2>/dev/null || true").split())
    out = alice(
        "cellward run offline --tmp-profile -- sh -c 'echo x > ~/vmtmp-mark; ls -d ~/vmtmp-mark'"
    )
    assert "vmtmp-mark" in out, out
    # Not in the real home: in the layer, which goes with the instance.
    machine.fail("test -e /home/alice/vmtmp-mark")
    machine.wait_until_succeeds(
        f"test \"$(ls -A {STATE}/.throwaway 2>/dev/null | wc -l)\" -le {len(before)}",
        timeout=60,
    )
    after = set(alice(f"ls -A {STATE}/.throwaway 2>/dev/null || true").split())
    assert after <= before, (before, after)

alice("cellward container rm vmia")
alice("cellward container rm vmib")
alice("cellward hermetic offline default")
