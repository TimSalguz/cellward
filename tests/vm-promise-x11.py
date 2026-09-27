"""tests/vm.nix, continued: one launch's X server, seen from another launch of
the same zone and from another zone (docs/THREAT-MODEL.md W10).

Executed by the main test script with exec(), in its globals (machine,
alice, in_zone, in_inst_q, FAKE_BUS_OWNER, and of the sway subtest `display` and
`zp`, vmsmoke's zone): the script is handed to the driver's build in one
environment variable, and the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import shlex

# An X server takes no password: whoever reaches its socket sees what its
# clients show and type. x11-run binds the socket in the launch's own
# /tmp/.X11-unix and none in the abstract namespace; what is left to try is
# the path, the abstract name, and the path through the server's own
# process, /proc/<pid>/root — which the kernel's ptrace rules open to a
# process of the same user namespace, and which a launch's Landlock domain
# (X5, Linux 6.12) closes to another launch.
release = machine.succeed("uname -r").strip()
scopes = tuple(int(x) for x in release.split("-")[0].split(".")[:2]) >= (6, 12)
PYTHON = FAKE_BUS_OWNER.split()[0]
# Connects, sends an X connection setup without authorisation, and says
# whether a server answered: `ANSWERED`, or `REFUSED <why>`. `@name` is an
# abstract socket.
XPROBE = "/tmp/vmxprobe.py"
machine.succeed(
    "printf '%s' "
    + shlex.quote(
        "import socket, sys\n"
        "path = sys.argv[1]\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "s.settimeout(10)\n"
        "try:\n"
        "    s.connect('\\0' + path[1:] if path.startswith('@') else path)\n"
        "    s.sendall(b'l\\0\\x0b\\0' + bytes(8))\n"
        "    print(path, 'ANSWERED' if s.recv(1) else 'CLOSED')\n"
        "except OSError as e:\n"
        "    print(path, 'REFUSED', e.strerror)\n"
    )
    + f" > {XPROBE}"
)

with subtest("one launch's X server: out of reach of another launch and of another zone"):
    # Launch A: an X server of its own, and a client it starts only when
    # told — by then another launch has taken the display's abstract name.
    alice("cellward x11 vmsmoke on")
    alice(
        f"systemd-run --user --unit=vmxa --setenv=WAYLAND_DISPLAY={display} "
        "cellward run vmsmoke -- sh -c "
        "'echo $DISPLAY > $HOME/vmxa-display; "
        "while ! test -e /tmp/vmxa-go; do sleep 0.2; done; "
        "xdpyinfo > $HOME/vmxa-after 2>&1; echo rc=$? >> $HOME/vmxa-after; exec sleep 300'"
    )
    machine.wait_until_succeeds("test -s /home/alice/vmxa-display", timeout=120)
    # The other launches below get no X server of their own.
    alice("cellward x11 vmsmoke off")
    n = machine.succeed("cat /home/alice/vmxa-display").strip().lstrip(":")
    assert n.isdigit(), n
    sat = machine.succeed(f"pgrep -u alice -f '[x]wayland-satellite[^ ]* :{n} '").split()[0]
    paths = [
        f"/tmp/.X11-unix/X{n}",
        f"@/tmp/.X11-unix/X{n}",
        f"/proc/{sat}/root/tmp/.X11-unix/X{n}",
    ]
    tries = "; ".join(f"{PYTHON} {XPROBE} {p}" for p in paths)
    # From the host, through the satellite's process, the server answers:
    # the path is right, and a refusal below is the boundary's.
    out = alice(f"{PYTHON} {XPROBE} {paths[2]}")
    assert "ANSWERED" in out, out

    def reached(out):
        """The paths through which an X server answered."""
        return [l.split()[0] for l in out.splitlines() if l.endswith(" ANSWERED")]

    # Launch B, the same zone: not at the path (the zone's /tmp/.X11-unix
    # is not A's), not by the abstract name (none), and not through A's
    # process — on a kernel without Landlock scopes that one is open: the
    # programs of one zone are not walls to each other (§5).
    out = alice(f"cellward run vmsmoke -- sh -c {shlex.quote(tries)}")
    print(f"launch B, the same zone:\n{out}")
    got = reached(out)
    if not scopes:
        print(f"kernel {release}: no Landlock domain per launch, A's process is open to B")
        got = [p for p in got if not p.startswith("/proc/")]
    assert not got, f"another launch of the zone reached A's X server: {got}"

    # Launch C, another zone: its own /tmp/.X11-unix, network namespace
    # and user namespace.
    alice("cellward add vmx2 /tmp/vmsmoke.conf")
    out = alice(f"cellward run vmx2 -- sh -c {shlex.quote(tries)}")
    print(f"launch C, another zone:\n{out}")
    got = reached(out)
    assert not got, f"another zone reached A's X server: {got}"
    alice("cellward rm vmx2")

    # A's clients try the abstract name first (libxcb). Taken by another
    # launch of the zone after A chose its display, it must not become a
    # server in between: under A's Landlock scope the connection is
    # refused, and the display does not open rather than open there.
    if scopes:
        alice(
            "systemd-run --user --unit=vmxsquat cellward run vmsmoke -- "
            f"socat ABSTRACT-LISTEN:/tmp/.X11-unix/X{n},fork OPEN:/tmp/vmx-squat,creat,append"
        )
        # In the network namespace of the launches of vmsmoke: its main
        # home's instance since stage 2 of the container design.
        machine.wait_until_succeeds(
            in_inst_q("main:vmsmoke", "vmsmoke", f"grep -q @/tmp/.X11-unix/X{n} /proc/net/unix"),
            timeout=60,
        )
    machine.succeed("touch /tmp/vmxa-go")
    machine.wait_until_succeeds("grep -q '^rc=' /home/alice/vmxa-after", timeout=60)
    print(machine.succeed("cat /home/alice/vmxa-after"))
    if scopes:
        machine.fail("test -e /tmp/vmx-squat")
        alice("systemctl --user stop vmxsquat")
    alice("systemctl --user stop vmxa || true")
    alice("rm -f ~/vmxa-display ~/vmxa-after")
    machine.succeed(f"rm -f /tmp/vmxa-go /tmp/vmx-squat {XPROBE}")
