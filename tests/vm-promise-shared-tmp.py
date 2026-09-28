"""tests/vm.nix, continued: a container's launches share its /tmp in its
instance (`fs_sandbox::Layout::share_tmp`), so that a single-instance
program started again finds its first copy — Electron and Chromium find it
by a socket in /tmp (owner 2026-09-27: two Claude Desktops ran on one
profile, each in a /tmp of its own). The X server's sockets stay each
launch's own, and another container sees none of it.

Executed by the main test script with exec(), in its globals (machine,
alice, the zone vmreal up, the sandbox vmsb created).
"""

with subtest("a container's launches share its /tmp; its X sockets and other containers do not"):
    alice(
        "systemd-run --user --unit=vmsbfirst cellward run vmreal --sandbox vmsb -- "
        "sh -c 'echo first > /tmp/single-probe; exec sleep 600'"
    )
    # The second launch of the same container finds the first one's file.
    machine.wait_until_succeeds(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        "cellward run vmreal --sandbox vmsb -- grep -q first /tmp/single-probe'",
        timeout=120,
    )
    # A directory for the X server's sockets of its own, not the container's.
    alice("cellward run vmreal --sandbox vmsb -- sh -c 'test -d /tmp/.X11-unix && ! test -e /tmp/.X11-unix/single'")
    alice("cellward run vmreal --sandbox vmsb -- sh -c 'touch /tmp/.X11-unix/single'")
    alice("cellward run vmreal --sandbox vmsb -- sh -c '! test -e /tmp/.X11-unix/single'")
    # Another container, and a throwaway sandbox, see nothing of it.
    alice("cellward run vmreal --fs-sandbox -- sh -c '! test -e /tmp/single-probe'")
    alice("systemctl --user stop vmsbfirst")
