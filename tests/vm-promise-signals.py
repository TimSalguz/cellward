"""tests/vm.nix, continued: a zone's program cannot signal the host's
processes of the user (docs/THREAT-MODEL.md X5).

Executed by the main test script with exec(), in its globals (machine, alice,
vmsmoke up): the script is handed to the driver's build in one environment
variable, and the kernel takes 128 KiB there.
"""

with subtest("a zone's program cannot signal the host's processes of the user"):
    # kill(2) checks the user, not the namespace: without a Landlock signal
    # scope a program of the zone kills the compositor. Linux 6.12 and later.
    release = machine.succeed("uname -r").strip()
    if tuple(int(x) for x in release.split("-")[0].split(".")[:2]) >= (6, 12):
        alice("systemd-run --user --unit=vmvictim sleep 600")
        victim = alice("systemctl --user show -p MainPID --value vmvictim").strip()
        assert victim and victim != "0", victim
        # Seen from the zone — there is no pid namespace — and not reachable.
        out = alice(
            "cellward run vmsmoke -- sh -c "
            f"'test -d /proc/{victim} && echo SEEN; kill -TERM {victim} && echo KILLED || echo REFUSED'"
        )
        assert "SEEN" in out and "REFUSED" in out, out
        machine.succeed(f"kill -0 {victim}")
        # What it starts itself, it may signal.
        out = alice("cellward run vmsmoke -- sh -c 'sleep 60 & kill $! && echo OWN-OK'")
        assert "OWN-OK" in out, out
        alice("systemctl --user stop vmvictim")
    else:
        print(f"kernel {release}: no Landlock scopes, the signal check is skipped")
