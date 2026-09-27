"""tests/vm.nix, continued: IPv6 through the real tunnel, and a zone's program against its network.

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, in_zone_root, STATE and what the earlier subtests
defined): the script is handed to the driver's build in one environment
variable, and the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import ipaddress
import re
import shlex

# --- IPv6 where the tunnel carries it: works, and only inside ----------
with subtest("IPv6 through the tunnel: the v6 default goes into awg0"):
    out = in_zone(rzpid, "ip -6 route show default")
    assert "dev awg0" in out and "unreachable" not in out, out
    # The server's REAL v6 address, on the network both VMs share, is
    # routed into the tunnel too: there is no second way to it.
    out = in_zone(rzpid, f"ip -6 route get {server_ip6}")
    assert "dev awg0" in out, f"a v6 route around the tunnel: {out}"

with subtest("IPv6 through the tunnel: TCP and ping, the server sees the tunnel's v6 address"):
    out = in_zone(rzpid, "socat -T10 - TCP6:[fd99::1]:8081")
    # socat writes the peer in full (`[fd99:0000:…:0002]`): compare
    # addresses, not spellings.
    seen = re.search(r"peer=\[?([0-9a-fA-F:]+)\]?", out)
    assert seen and ipaddress.ip_address(seen.group(1)) == ipaddress.ip_address(
        "fd99::2"
    ), f"server saw someone else over v6: {out}"
    out = in_zone(rzpid, "ping -6 -c1 -W5 fd99::1")
    assert " 0% packet loss" in out, out

with subtest("IPv6 through the tunnel: DNS over v6, from the config, answers inside"):
    out = in_zone(rzpid, "cat /etc/resolv.conf")
    assert "nameserver fd99::1" in out, out
    out = in_zone(rzpid, "dig +time=5 +tries=2 +short leaktest.internal @fd99::1")
    assert "10.99.0.9" in out, f"DNS over v6 through the tunnel failed: {out}"

with subtest("IPv6 aimed at the server's real address goes into the tunnel, not around it"):
    # Nothing listens there, so the connection is refused — by the
    # server, through the tunnel. Had it left by eth1, the capture holds it.
    in_zone(rzpid, f"sh -c 'socat -T3 - TCP6:[{server_ip6}]:9 </dev/null || true'")

# --- A zone's program cannot change the zone's network ---------------
# The user tier's version of what vm-system checks for system zones
# (docs/THREAT-MODEL.md N6): the program is the user's uid in the zone's
# user namespace, with no capabilities there — and a user namespace of
# its own gives it capabilities over new, empty namespaces only.
with subtest("a zone's program cannot touch the routes, the tunnel or the filter"):
    for cmd in [
        "ip -4 route replace default dev lo",
        "ip -6 route del default",
        "ip link set awg0 down",
        "ip link add dummy0 type dummy",
        "nft delete table inet vpnzone",
        "nft flush ruleset",
        "unshare -Ur ip link set awg0 down",
        "unshare -Ur nft flush ruleset",
    ]:
        machine.fail(
            "su -l alice -c "
            + shlex.quote(
                "export XDG_RUNTIME_DIR=/run/user/1000; "
                f"nsenter --preserve-credentials -U -n -m -t {rzpid} -- {cmd}"
            )
        )
    out = in_zone(rzpid, "ip -o link")
    assert "awg0" in out and "UP" in out and "dummy0" not in out, out
    out = in_zone(rzpid, "ip -4 route show default")
    assert "dev awg0" in out, out
    out = in_zone_root(rzpid, "nft list table inet vpnzone")
    assert "policy drop" in out, out
