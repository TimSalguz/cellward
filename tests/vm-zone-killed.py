"""tests/vm.nix, continued: the zone killed hard under a running program.

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, in_zone_root, STATE and what the earlier subtests
defined): the script is handed to the driver's build in one environment
variable, and the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import ipaddress
import re
import shlex

# --- The holder dies hard while a program runs --------------------------
# (docs/THREAT-MODEL.md N9, the user tier's version.) The program keeps
# the app namespace alive; everything of the zone's own is killed. The
# tunnel's socket was in the uplink, which is gone: the program keeps
# an awg0 that sends nothing anywhere — and the capture above sees
# nothing either.
with subtest("the zone killed under a running program: it fails closed"):
    # Its own session and no pipe of ours: the driver would otherwise
    # wait for the sleep to close the output it inherited.
    alice(
        f"nsenter --preserve-credentials -U -n -m -t {rzpid} -- "
        "sh -c 'setsid -f sleep 600 </dev/null >/dev/null 2>&1'"
    )
    orphan = machine.succeed("pgrep -u alice -xn sleep").strip()
    alice("systemctl --user kill -s KILL vpn-zone@vmreal")
    machine.wait_until_fails(f"kill -0 {rzpid}", timeout=30)
    def in_orphan(cmd):
        return alice(
            f"nsenter --preserve-credentials -U -n -m -t {orphan} -- {cmd}"
        )
    out = in_orphan("ip -o link")
    assert "awg0" in out and len(out.strip().splitlines()) == 2, out
    machine.fail(
        "su -l alice -c "
        + shlex.quote(
            f"nsenter --preserve-credentials -U -n -m -t {orphan} -- "
            "timeout 8 socat -T5 - TCP:10.99.0.1:8080"
        )
    )
    machine.fail(
        "su -l alice -c "
        + shlex.quote(
            f"nsenter --preserve-credentials -U -n -m -t {orphan} -- "
            "ping -c1 -W3 10.99.0.1"
        )
    )
    machine.succeed(f"kill {orphan}")
    alice("systemctl --user reset-failed vpn-zone@vmreal || true")
    # The server's side of the dead session still has something for the
    # client and knocks at its last address with handshakes (148 bytes, every
    # 5 s) for a minute and a half, which the host answers "port
    # unreachable": nothing of the zone's, but noise in the next capture. The
    # peer made anew has no address to knock at.
    server.succeed(
        f"wg set wg0 peer '{cpub}' remove && "
        f"wg set wg0 peer '{cpub}' allowed-ips 10.99.0.2/32,fd99::2/128"
    )
