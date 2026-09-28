"""tests/vm.nix, continued: a container's launches share its /tmp in its
instance when that /tmp is the instance's own (`fs_sandbox::Layout::
share_tmp`), so that a single-instance program started again finds its
first copy — Electron and Chromium find it by a socket in /tmp (owner
2026-09-27: two Claude Desktops ran on one profile, each in a /tmp of its
own). The X server's sockets stay each launch's own, another container sees
none of it — and where the instance's /tmp is the host's (an ordinary
zone), a sandbox keeps a /tmp of its own, as before.

Executed by the main test script with exec(), in its globals (machine,
alice), with TMP_ZONE (the zone), TMP_SANDBOX (a named sandbox created
there) and TMP_SHARED (whether the zone's instances have a /tmp of their
own: a hermetic zone) set before.
"""

with subtest(f"a container's /tmp in zone {TMP_ZONE}: shared by its launches: {TMP_SHARED}"):
    run = f"cellward run {TMP_ZONE} --sandbox {TMP_SANDBOX} --"
    probe = f"/tmp/single-probe-{TMP_ZONE}"
    # The host's /tmp is never a sandbox's.
    machine.succeed(f"echo host > /tmp/host-probe-{TMP_ZONE}; chmod 644 /tmp/host-probe-{TMP_ZONE}")
    alice(f"{run} sh -c '! test -e /tmp/host-probe-{TMP_ZONE}'")
    alice(
        f"systemd-run --user --unit=tmpfirst-{TMP_ZONE} {run} "
        f"sh -c 'echo first > {probe}; exec sleep 600'"
    )
    alice(f"{run} sh -c 'test -d /tmp/.X11-unix'")
    if TMP_SHARED:
        # The second launch of the same container finds the first one's file.
        machine.wait_until_succeeds(
            "su -l alice -c "
            + shlex.quote(f"export XDG_RUNTIME_DIR=/run/user/1000; {run} grep -q first {probe}"),
            timeout=120,
        )
        # The X server's sockets: a directory of each launch's own.
        alice(f"{run} sh -c 'touch /tmp/.X11-unix/single'")
        alice(f"{run} sh -c '! test -e /tmp/.X11-unix/single'")
    else:
        # Once the first launch is surely up (its instance answers), the
        # second still sees nothing of its /tmp.
        machine.wait_until_succeeds(
            "su -l alice -c "
            + shlex.quote(f"export XDG_RUNTIME_DIR=/run/user/1000; systemctl --user is-active tmpfirst-{TMP_ZONE}"),
            timeout=60,
        )
        alice(f"{run} sh -c '! test -e {probe}'")
    # A throwaway sandbox, another container, sees none of it.
    alice(f"cellward run {TMP_ZONE} --fs-sandbox -- sh -c '! test -e {probe}'")
    alice(f"systemctl --user stop tmpfirst-{TMP_ZONE}")
