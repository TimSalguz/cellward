"""tests/vm.nix, continued: networks through an interface of the host.

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, in_zone_root, STATE and what the earlier subtests
defined): the script is handed to the driver's build in one environment
variable, and the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import ipaddress
import re
import shlex

# --- A network through an interface of the host (CONTAINERS §3.3) -----
# No tunnel: pasta attached to the app namespace and bound to one host
# interface. The server must see the machine's own eth1 address, and a
# zone bound to eth0 must not reach the server at all — the binding, not
# the host's routing table, decides where packets go.
with subtest("host-interface zone: out through eth1 only"):
    server.succeed(
        "systemd-run --unit=hello-lan socat "
        f"TCP-LISTEN:8090,bind={server_ip},fork,reuseaddr "
        "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
    )
    alice("printf '[HostInterface]\\nInterface = eth1\\n' > /tmp/vmlan.conf")
    alice("cellward add vmlan /tmp/vmlan.conf")
    alice("cellward up vmlan")
    lpid = machine.succeed(f"cat {STATE}/vmlan/zone.pid").strip()
    links = in_zone(lpid, "ip -o link show")
    assert len(links.strip().splitlines()) == 2 and ": awg0" in links, links
    out = in_zone(lpid, "ip -4 route show default")
    assert "dev awg0" in out, out
    out = in_zone(lpid, f"socat -T10 - TCP:{server_ip}:8090")
    assert "peer=192.168.1.1" in out, f"server saw someone else: {out}"
    # The app namespace's filter holds here too.
    rules = in_zone_root(lpid, "nft list ruleset")
    assert 'oifname "awg0" accept' in rules and "policy drop" in rules, rules
    # And the host's own services are not the zone's way out (audit
    # 2026-09-27): pasta is in the host's network, and a connection to
    # the host's address would be delivered to whatever listens there,
    # to go on by the host's routes.
    machine.succeed(
        "systemd-run --unit=hostlocal socat TCP-LISTEN:8091,fork,reuseaddr 'SYSTEM:echo host-local'"
    )
    machine.wait_until_succeeds("ss -ltn | grep -q ':8091 '")
    machine.succeed("socat -T5 - TCP:192.168.1.1:8091 | grep -q host-local")
    in_zone(lpid, "sh -c '! timeout 10 socat -T5 - TCP:192.168.1.1:8091'")
    assert "192.168.1.1 reject" in rules, rules
    # A launch into it runs in its container's instance (stage 2c,
    # 2026-09-27): out through the zone's bridge, as the host — and the
    # host's own services are refused there as well (the bridge's own
    # rule: pasta put the host's address on the zone's awg0).
    out = alice(f"cellward run vmlan -- socat -T10 - TCP:{server_ip}:8090")
    assert "peer=192.168.1.1" in out, f"from the instance: {out}"
    out = alice(
        "cellward run vmlan -- sh -c "
        "'timeout -s KILL 10 socat -T5 - TCP:192.168.1.1:8091 </dev/null; true'"
    )
    assert "host-local" not in out, out
    machine.succeed("systemctl stop hostlocal")
    machine.wait_until_succeeds(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; cellward check vmlan'",
        timeout=30,
    )
    out = alice("cellward doctor vmlan --json")
    assert '"worst":"fail"' not in out, out
    alice("cellward down vmlan")

# IPv6 through the host's interface when it has usable IPv6 (a global
# address and a default route): bound to eth1 like IPv4, out as the
# host, and never to the host's own IPv6 addresses (2026-09-27; only
# IPv4 ones were refused). pasta gives the zone eth1's own v6 address,
# so a connection to THAT stays in the zone; the leak was the host's
# other addresses — a ULA on another interface here.
with subtest("host-interface zone: IPv6 bound to eth1, the host's other v6 addresses refused"):
    machine_ip6 = machine.succeed(
        "ip -6 -o addr show eth1 scope global | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    ).strip()
    machine.succeed(
        f"ip -6 route replace default via {server_ip6} dev eth1 && "
        "ip link add vmv6 type dummy && ip -6 addr add fd77::1/64 dev vmv6 nodad && "
        "ip link set vmv6 up"
    )
    server.succeed(
        "systemd-run --unit=hello-lan6 socat "
        f"TCP6-LISTEN:8095,bind=[{server_ip6}],fork,reuseaddr "
        "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
    )
    machine.succeed(
        "systemd-run --unit=hostlocal6 socat TCP6-LISTEN:8096,bind=[fd77::1],fork,reuseaddr "
        "'SYSTEM:echo host-local6'"
    )
    machine.wait_until_succeeds("ss -ltn | grep -q ':8096 '")
    machine.succeed("socat -T5 - TCP6:[fd77::1]:8096 | grep -q host-local6")
    alice("cellward up vmlan")
    lpid = machine.succeed(f"cat {STATE}/vmlan/zone.pid").strip()
    out = in_zone(lpid, "ip -6 route show default")
    assert "dev awg0" in out, out
    out = in_zone(lpid, f"socat -T10 - TCP6:[{server_ip6}]:8095")
    seen = re.search(r"peer=\[?([0-9a-fA-F:]+)\]?", out)
    assert seen and ipaddress.ip_address(seen.group(1)) == ipaddress.ip_address(
        machine_ip6
    ), f"the server saw someone else over v6: {out}"
    rules = in_zone_root(lpid, "nft list ruleset")
    assert "ip6 daddr fd77::1 reject" in rules, rules
    in_zone(lpid, "sh -c '! timeout 10 socat -T5 - TCP6:[fd77::1]:8096'")
    alice("cellward down vmlan")
    machine.succeed(
        "systemctl stop hostlocal6 && ip link del vmv6 && "
        f"ip -6 route del default via {server_ip6} dev eth1"
    )

# A dummy interface with an address and no way to the server: bound to
# it, the zone must not reach the server even though the host itself
# routes there through eth1.
with subtest("host-interface zone bound to another interface cannot reach eth1's network"):
    machine.succeed(
        "ip link add vmdummy type dummy && ip addr add 10.77.0.1/24 dev vmdummy "
        "&& ip link set vmdummy up"
    )
    alice("printf '[HostInterface]\\nInterface = vmdummy\\n' > /tmp/vmwan.conf")
    alice("cellward add vmwan /tmp/vmwan.conf")
    alice("cellward up vmwan")
    wpid = machine.succeed(f"cat {STATE}/vmwan/zone.pid").strip()
    in_zone(wpid, f"sh -c '! timeout 10 socat -T5 - TCP:{server_ip}:8090'")
    alice("cellward down vmwan")

# The interface deleted under a running zone: pasta binding a socket to
# an interface that is gone connects it UNBOUND (review 2026-09-24), so
# the holder watches the interface and takes the zone down at once.
with subtest("host-interface zone: its interface deleted, the zone goes down"):
    alice("cellward up vmwan")
    wpid = machine.succeed(f"cat {STATE}/vmwan/zone.pid").strip()
    machine.succeed("ip link del vmdummy")
    machine.wait_until_fails(f"test -e /proc/{wpid}", timeout=15)
    machine.fail(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        "systemctl --user is-active vpn-zone@vmwan'"
    )

with subtest("host-interface zone: a missing interface refuses to come up"):
    alice("printf '[HostInterface]\\nInterface = nosuchif0\\n' > /tmp/vmnone.conf")
    alice("cellward add vmnone /tmp/vmnone.conf")
    machine.fail(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; cellward up vmnone'"
    )
    machine.fail(f"test -f {STATE}/vmnone/ready")

# The host's own network (2e of PERMISSIONS §11.15): a zone made when it is
# first wanted, pasta by the host's routes, the host's resolver behind its
# gateway's address, and a container's instance in it as in any network.
with subtest("the host's network: made when wanted, the host's routes and resolver"):
    machine.fail(f"test -e {STATE}/host")
    out = alice("cellward status --json")
    assert '"name":"host","kind":"host-network"' in out, out
    out = alice(f"cellward run host -- socat -T10 - TCP:{server_ip}:8090")
    assert "peer=192.168.1.1" in out, f"from the instance: {out}"
    machine.succeed(f"grep -qx '\\[HostNetwork\\]' {STATE}/host/config.conf")
    hpid = machine.succeed(f"cat {STATE}/host/zone.pid").strip()
    out = in_zone(hpid, "cat /etc/resolv.conf")
    assert "nameserver 10.255.255.254" in out, out
    # The host's resolver answers there: the name only the host's dnsmasq
    # knows, which no VPN network may ever resolve (the leak test's).
    out = alice("cellward run host -- getent ahostsv4 leaktest.internal")
    assert "10.66.66.66" in out, out
    # The host's own services stay refused, as for an interface of the host.
    machine.succeed(
        "systemd-run --unit=hostlocal2 socat TCP-LISTEN:8092,fork,reuseaddr 'SYSTEM:echo host-local'"
    )
    machine.wait_until_succeeds("ss -ltn | grep -q ':8092 '")
    out = alice(
        "cellward run host -- sh -c "
        "'timeout -s KILL 10 socat -T5 - TCP:192.168.1.1:8092 </dev/null; true'"
    )
    assert "host-local" not in out, out
    machine.succeed("systemctl stop hostlocal2")
    alice("cellward down host")
