"""tests/vm.nix, continued: a compositor's or a shell's IPC that is not in the
list of the runtime directory's compositor sockets (docs/THREAT-MODEL.md W7).

Executed by the main test script with exec(), in its globals (machine,
alice, in_zone, `hp` of the hermetic zone up, FAKE_BUS_OWNER; vmsmoke down):
the script is handed to the driver's build in one environment variable, and
the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

# Three places such a door is kept, each a stand-in that writes down what
# reaches it: Wayfire's IPC socket in the host's /tmp (WAYFIRE_SOCKET), a
# shell's own directory in the runtime directory (quickshell's), and a
# compositor's name on the session bus — KWin's scripting, whose loadScript
# runs a script inside the compositor.
WAYFIRE = "/tmp/wayfire-wayland-1-.socket"
SHELL = "/run/user/1000/quickshell/by-id/vmtest/ipc.sock"
KWIN_GOT = "/home/alice/bus-got-kwin"
KWIN = "call org.kde.KWin /Scripting org.kde.kwin.Scripting loadScript s /tmp/vm.js"

alice(
    f"systemd-run --user --unit=fakewayfire socat UNIX-LISTEN:{WAYFIRE},fork "
    "OPEN:/tmp/wayfire-got,creat,append"
)
alice(
    "mkdir -p /run/user/1000/quickshell/by-id/vmtest && systemd-run --user "
    f"--unit=fakeshell socat UNIX-LISTEN:{SHELL},fork OPEN:/tmp/shell-got,creat,append"
)
alice(f"systemd-run --user --unit=fakekwin {FAKE_BUS_OWNER} {KWIN_GOT} org.kde.KWin")
machine.wait_until_succeeds(f"test -S {WAYFIRE} && test -S {SHELL}", timeout=30)
machine.wait_until_succeeds(
    "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
    "busctl --user --timeout=5 list' | grep -q org.kde.KWin",
    timeout=30,
)
# From the host every one of them is reached — otherwise the refusals below
# would prove nothing.
alice(f"echo from-host | socat -u - UNIX-CONNECT:{WAYFIRE}")
alice(f"echo from-host | socat -u - UNIX-CONNECT:{SHELL}")
alice(f"sh -c 'busctl --user --timeout=2 {KWIN} || true'")
machine.wait_until_succeeds(
    "grep -q from-host /tmp/wayfire-got && grep -q from-host /tmp/shell-got", timeout=30
)
machine.wait_until_succeeds(f"grep -q loadScript {KWIN_GOT}", timeout=10)
alice(f": > {KWIN_GOT}")

# The script a program runs: each door tried, and what came of it said.
# busctl's call to a stand-in that never answers ends in its two seconds
# either way: the stand-in's file says whether it arrived.
TRY = (
    f"'echo WF=$WAYFIRE_SOCKET; "
    f"echo from-$1 | socat -u - UNIX-CONNECT:{WAYFIRE} && echo WAYFIRE-REACHED; "
    f"echo from-$1 | socat -u - UNIX-CONNECT:{SHELL} && echo SHELL-REACHED; "
    f"busctl --user --timeout=2 {KWIN}; true'"
)

with subtest("hermetic zone: a shell's IPC in /tmp, in the runtime directory and on the bus is out of reach"):
    out = alice(f"WAYFIRE_SOCKET={WAYFIRE} cellward run vmherm -- sh -c {TRY} sh hermetic")
    print(out)
    assert "WAYFIRE-REACHED" not in out and "SHELL-REACHED" not in out, out
    in_zone(hp, f"test ! -e {WAYFIRE}")
    in_zone(hp, "test ! -e /run/user/1000/quickshell")
    machine.fail("grep -q from-hermetic /tmp/wayfire-got /tmp/shell-got")
    machine.fail(f"grep -q loadScript {KWIN_GOT}")

# The ordinary zone (2026-09-28): the two doors of W7 that are no business
# of an ordinary zone's are closed — the shell's directory in the runtime
# directory is out of its instance's, made before it came up or after, and
# a launch is not told where Wayfire listens (WAYFIRE_SOCKET, and the
# _WAYFIRE_SOCKET Wayfire is told, dropped). What stays, said by a test: an
# ordinary zone shares the host's /tmp (§9, §15), where Wayfire's socket
# still is by its path, and has the whole session bus (P1).
with subtest("ordinary zone: a shell's directory out of reach and WAYFIRE_SOCKET gone; /tmp and the bus still in reach"):
    out = alice(
        f"WAYFIRE_SOCKET={WAYFIRE} _WAYFIRE_SOCKET={WAYFIRE} "
        f"cellward run vmsmoke -- sh -c {TRY} sh ordinary"
    )
    print(out)
    assert "WF=" in out.splitlines(), f"a launch is told where Wayfire listens:\n{out}"
    assert "SHELL-REACHED" not in out, out
    machine.fail("grep -q from-ordinary /tmp/shell-got")
    alice(
        f"_WAYFIRE_SOCKET={WAYFIRE} cellward run vmsmoke -- "
        "sh -c 'test -z \"$_WAYFIRE_SOCKET\" && test ! -e /run/user/1000/quickshell'"
    )
    # A shell's directory made while the instance runs is not bound in by
    # its runtime watch either (Astal's, AGS's).
    alice(
        "systemd-run --user --collect --unit=w7keep cellward run vmsmoke -- sleep 5151"
    )
    machine.wait_until_succeeds("pgrep -u alice -xf '(/[^ ]*/)?sleep 5151'", timeout=60)
    alice(
        "mkdir -p /run/user/1000/astal && systemd-run --user --unit=fakeastal "
        "socat UNIX-LISTEN:/run/user/1000/astal/vmtest.sock,fork "
        "OPEN:/tmp/astal-got,creat,append"
    )
    machine.wait_until_succeeds("test -S /run/user/1000/astal/vmtest.sock", timeout=30)
    alice(
        "cellward run vmsmoke -- sh -c "
        "'test ! -e /run/user/1000/astal && test ! -e /run/user/1000/quickshell'"
    )
    alice("systemctl --user stop w7keep fakeastal")
    machine.fail("test -s /tmp/astal-got")
    # Still in reach, by design of an ordinary zone: Wayfire's socket by its
    # path in the shared /tmp, and KWin on the whole bus.
    assert "WAYFIRE-REACHED" in out, out
    machine.wait_until_succeeds("grep -q from-ordinary /tmp/wayfire-got")
    machine.wait_until_succeeds(f"grep -q loadScript {KWIN_GOT}", timeout=10)
    alice("cellward down vmsmoke")

alice("systemctl --user stop fakewayfire fakeshell fakekwin")
alice(f"rm -rf /run/user/1000/quickshell /run/user/1000/astal {KWIN_GOT}")
machine.succeed("rm -f /tmp/wayfire-got /tmp/shell-got /tmp/astal-got")
