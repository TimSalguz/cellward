"""tests/vm.nix, continued: a container's instance has a pid namespace of its
own — stage 3 of the container design of 2026-09-27 (docs/THREAT-MODEL.md
X4, docs/LEAK-MODEL.md §9, §16, rust/src/init.rs).

Executed by the main test script with exec(), in its globals (machine,
alice, instance, in_inst, in_inst_q, json, re): the script is handed to the
driver's build in one environment variable, and the kernel takes 128 KiB
there (MAX_ARG_STRLEN).

A program of an instance sees in /proc its own container's processes and
nobody else's: not the host's, not another container's. What is looked for
is a command line, never a number — a host pid means nobody, or somebody
else, in the instance's namespace. Each "not seen" is paired with the same
look on the host, where it is seen. Then the instance's pid namespace in
use: its stop ends its programs with no timeout reached, `cellward container
kill` ends one that ignores TERM, a daemon forked twice stays in its launch's
tree, and an orphan the instance's pid 1 adopted is reaped and counted.
"""

# Every command line in /proc, NUL-separated: a process that ends between the
# glob and the read is skipped.
SCAN = "sh -c 'cat /proc/[0-9]*/cmdline 2>/dev/null; true'"


def run_in(c, cmd):
    """A launch into container `c`'s instance, as a person makes one."""
    return alice(f"cellward run offline --container {c} -- {cmd}")


def marked(marker):
    """The host pids of the user's processes whose command line starts with
    `marker`."""
    return machine.succeed(f"pgrep -u alice -f '^{marker}' || true").split()


def keep(c, unit, marker):
    """A program of `c` named `marker` (its command line), keeping `c`'s
    instance up."""
    alice(
        f"systemd-run --user --collect --unit={unit} "
        f"cellward run offline --container {c} -- bash -c 'exec -a {marker} sleep 600'"
    )
    machine.wait_until_succeeds(f"pgrep -u alice -f '^{marker}'", timeout=60)


def events(kind, id_):
    return [
        e
        for e in json.loads(alice("cellward journal --json"))["events"]
        if e["event"] == kind and e.get("instance") == id_
    ]


for c in ["vmpa", "vmpb", "vmpc", "vmpd"]:
    alice(f"cellward container create {c} --home layer")
keep("vmpa", "vmpa-keep", "vmx4-a-marker")
keep("vmpb", "vmpb-keep", "vmx4-b-marker")
alice("systemd-run --user --unit=vmx4-host bash -c 'exec -a vmx4-host-marker sleep 600'")
machine.wait_until_succeeds("pgrep -u alice -f '^vmx4-host-marker'", timeout=30)
host_marker = marked("vmx4-host-marker")[0]

with subtest("an instance's program sees its own container's processes, no one else's"):
    host = alice(SCAN)
    for m in ["vmx4-a-marker", "vmx4-b-marker", "vmx4-host-marker", "container-enter"]:
        assert m in host, f"{m} not even on the host"
    inside = run_in("vmpa", SCAN)
    # The same container's other launch: seen.
    assert "vmx4-a-marker" in inside, inside
    # Another container's program, the host's, a launch's waiter (a host
    # process — this one's own is alive while it looks): not.
    for m in ["vmx4-b-marker", "vmx4-host-marker", "container-enter"]:
        assert m not in inside, f"{m} seen in an instance"
    # Its own pid namespace, not the host's nor another instance's.
    ns_a = run_in("vmpa", "readlink /proc/self/ns/pid").strip()
    ns_b = run_in("vmpb", "readlink /proc/self/ns/pid").strip()
    ns_host = machine.succeed("readlink /proc/1/ns/pid").strip()
    assert len({ns_a, ns_b, ns_host}) == 3, (ns_a, ns_b, ns_host)
    # Its pid 1 is the instance's own, its holder: not systemd.
    init = run_in("vmpa", "cat /proc/1/cmdline")
    assert "container-holder" in init, init
    i = instance("vmpa")
    assert i["pid_namespace"] is True, i
    # And the host's number of it names nothing of the host's there.
    run_in("vmpa", f"sh -c '! grep -qs vmx4-host-marker /proc/{host_marker}/cmdline'")

with subtest("a host process's /proc/<pid>/net is out of an instance's reach"):
    # /proc/<pid>/net is that process's network, and no ptrace check guards
    # it (LEAK-MODEL §16): the host's sockets, by any host process's number.
    alice(
        "systemd-run --user --unit=vmx4-listen "
        "socat TCP-LISTEN:47913,bind=127.0.0.1,fork,reuseaddr /dev/null"
    )
    port = ":BB29 "  # 47913, as /proc/net/tcp writes it
    machine.wait_until_succeeds(f"grep -q '{port}' /proc/{host_marker}/net/tcp", timeout=30)
    run_in("vmpa", f"sh -c '! grep -qs \"{port}\" /proc/{host_marker}/net/tcp'")
    run_in("vmpa", f"sh -c '! cat /proc/[0-9]*/net/tcp 2>/dev/null | grep -q \"{port}\"'")
    alice("systemctl --user stop vmx4-listen")

with subtest("stopping an instance ends its programs, and reaches no timeout"):
    b = instance("vmpb")
    assert b is not None
    # Well below systemd's own stop timeout (90 s): a hang would be caught.
    alice("timeout 60 systemctl --user stop vpn-zone-container@vmpb.service")
    machine.wait_until_fails("pgrep -u alice -f '^vmx4-b-marker'", timeout=30)
    assert instance("vmpb") is None
    assert any(e.get("why") == "stop" for e in events("instance-stop", "vmpb"))

with subtest("a program that ignores TERM ends on cellward container kill"):
    alice(
        "systemd-run --user --collect --unit=vmpa-stubborn "
        "cellward run offline --container vmpa -- "
        "bash -c 'trap \"\" TERM; exec -a vmx4-stubborn sleep 600'"
    )
    machine.wait_until_succeeds("pgrep -u alice -f '^vmx4-stubborn'", timeout=60)
    # It does ignore TERM: the kill below is not vacuous.
    machine.succeed("pkill -TERM -u alice -f '^vmx4-stubborn'")
    machine.sleep(1)
    stubborn = marked("vmx4-stubborn")
    assert stubborn, "TERM ended the program that ignores it"
    out = alice("cellward container kill vmpa")
    assert "убито программ" in out, out
    for pid in stubborn:
        machine.wait_until_fails(f"test -e /proc/{pid}", timeout=30)
    machine.wait_until_fails("pgrep -u alice -f '^vmx4-a-marker'", timeout=30)
    assert instance("vmpa") is None
    assert any(e.get("why") == "kill" for e in events("instance-stop", "vmpa"))

with subtest("a daemon forked twice stays in its launch's tree, under profile-run"):
    # The launch returns when its program does — the daemon lives on, its
    # output not held by anyone's pipe (profile-run's own is /dev/null).
    run_in(
        "vmpc",
        "bash -c '(exec -a vmx4-daemon sleep 600 </dev/null >/dev/null 2>&1 &)'",
    )
    machine.wait_until_succeeds("pgrep -u alice -f '^vmx4-daemon'", timeout=30)
    daemon = marked("vmx4-daemon")[0]
    parent = machine.succeed(f"awk '/^PPid:/ {{print $2}}' /proc/{daemon}/status").strip()
    line = machine.succeed(f"tr '\\0' ' ' < /proc/{parent}/cmdline")
    assert "profile-run" in line, f"the daemon's parent is {parent}: {line}"
    # The instance is up for it: it is a program of the container.
    assert instance("vmpc") is not None
    alice("cellward container stop vmpc")
    machine.wait_until_fails(f"test -e /proc/{daemon}", timeout=30)

with subtest("an orphan pid 1 adopts is reaped, and counted as a program"):
    keep("vmpd", "vmpd-keep", "vmx4-d-marker")
    # Entered with no profile-run: the orphan goes to the instance's pid 1.
    in_inst(
        "vmpd",
        "offline",
        "bash -c '(exec -a vmx4-orphan sleep 600 </dev/null >/dev/null 2>&1 &)'",
    )
    machine.wait_until_succeeds("pgrep -u alice -f '^vmx4-orphan'", timeout=30)
    orphan = marked("vmx4-orphan")[0]
    init = str(instance("vmpd")["pid"])
    parent = machine.succeed(f"awk '/^PPid:/ {{print $2}}' /proc/{orphan}/status").strip()
    assert parent == init, (parent, init)
    # Its keeper's launch gone, the orphan still keeps the instance up.
    alice("systemctl --user stop vmpd-keep")
    machine.wait_until_fails("pgrep -u alice -f '^vmx4-d-marker'", timeout=30)
    machine.sleep(2)
    assert instance("vmpd") is not None, "an orphan was not counted as a program"
    # Ended, it is reaped — no zombie — and the instance goes with it.
    machine.succeed(f"kill {orphan}")
    machine.wait_until_fails(f"test -e /proc/{orphan}", timeout=30)
    machine.wait_until_fails(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward status --json' "
        "| grep -q '\"id\":\"vmpd\"'",
        timeout=60,
    )

alice("systemctl --user stop vmx4-host")
for c in ["vmpa", "vmpb", "vmpc", "vmpd"]:
    alice(f"cellward container rm {c}")
