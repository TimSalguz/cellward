"""tests/vm.nix, continued: a zone's program cannot signal the host's
processes of the user (docs/THREAT-MODEL.md X5) — nor see them (X4).

Executed by the main test script with exec(), in its globals (machine, alice,
vmsmoke up): the script is handed to the driver's build in one environment
variable, and the kernel takes 128 KiB there.

Since stage 3 of the container design (2026-09-27) a launch into a zone runs
in its container's instance, and the instance has a pid namespace of its
own: a host process is not in its /proc at all, so "seen but not
reachable" (the X5 check as it was) is now asked of what an instance's
program still sees — another launch of its own container.
"""

# Every command line in /proc, NUL-separated: a process that ends between the
# glob and the read is skipped.
SCAN = "sh -c 'cat /proc/[0-9]*/cmdline 2>/dev/null; true'"

with subtest("a zone's program neither sees nor signals the host's processes of the user"):
    alice("systemd-run --user --unit=vmvictim bash -c 'exec -a vmx5-victim sleep 600'")
    machine.wait_until_succeeds("pgrep -u alice -f '^vmx5-victim'", timeout=30)
    victim = machine.succeed("pgrep -u alice -f '^vmx5-victim'").split()[0]
    # On the host it is there to be seen: the check below is not vacuous.
    assert "vmx5-victim" in alice(SCAN)
    # In the zone (its main home's instance, main:vmsmoke): not in /proc at
    # all (X4, stage 3) — by its command line, not by its number, which in
    # the instance's pid namespace is nobody's or somebody else's.
    out = alice(f"cellward run vmsmoke -- {SCAN}")
    assert "vmx5-victim" not in out, "a host process in an instance's /proc"
    # Nor by name: nothing there to signal.
    out = alice(
        "cellward run vmsmoke -- sh -c "
        "'pkill -TERM -f ^vmx5-victim && echo KILLED || echo NOT-FOUND'"
    )
    assert "NOT-FOUND" in out, out
    machine.succeed(f"kill -0 {victim}")
    alice("systemctl --user stop vmvictim")

with subtest("a program sees another launch of its container, and cannot signal it (X5)"):
    # kill(2) checks the user, not the launch: without a Landlock signal
    # scope a program would kill another launch's. Linux 6.12 and later.
    release = machine.succeed("uname -r").strip()
    if tuple(int(x) for x in release.split("-")[0].split(".")[:2]) >= (6, 12):
        alice(
            "systemd-run --user --unit=vmsibling "
            "cellward run vmsmoke -- bash -c 'exec -a vmx5-sibling sleep 600'"
        )
        machine.wait_until_succeeds("pgrep -u alice -f '^vmx5-sibling'", timeout=60)
        out = alice(
            "cellward run vmsmoke -- sh -c "
            "'p=$(pgrep -f ^vmx5-sibling) && echo SEEN; "
            "kill -TERM $p && echo KILLED || echo REFUSED'"
        )
        assert "SEEN" in out and "REFUSED" in out, out
        machine.succeed("pgrep -u alice -f '^vmx5-sibling'")
        # What it starts itself, it may signal.
        out = alice("cellward run vmsmoke -- sh -c 'sleep 60 & kill $! && echo OWN-OK'")
        assert "OWN-OK" in out, out
        alice("systemctl --user stop vmsibling")
    else:
        print(f"kernel {release}: no Landlock scopes, the signal check is skipped")
