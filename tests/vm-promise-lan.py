"""tests/vm.nix, continued: the LAN and the host's own addresses, from a zone
with a kernel tunnel (docs/THREAT-MODEL.md N3).

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, STATE, server_ip, server_ip6; vmreal up, and the leak
capture on eth1 armed): the script is handed to the driver's build in one
environment variable, and the kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import shlex

# The app namespace has lo and the tunnel, and the uplink lets out the
# tunnel's transport alone: the host's own services, on any of its
# addresses, and the LAN around the server are not a program's to reach.
# The server stands for the LAN too — its LAN address answers the host, and
# must answer a zone only as the tunnel's far end.
with subtest("a tunnel zone reaches neither the LAN nor the host's own addresses"):
    first = "tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    machine_ip = machine.succeed(f"ip -4 -o addr show eth1 | head -1 | {first}").strip()
    machine_ip6 = machine.succeed(
        f"ip -6 -o addr show eth1 scope global | head -1 | {first}"
    ).strip()
    host_addrs = machine.succeed(f"ip -o addr show scope global | {first}").split()
    gateways = machine.succeed("ip -4 route show default | cut -d' ' -f3").split()
    assert machine_ip in host_addrs and machine_ip6 in host_addrs, host_addrs
    # Every one of them is routed into the tunnel, and none is the zone's own.
    targets = sorted(set(host_addrs + gateways + [server_ip, server_ip6, "192.168.1.254"]))
    routes = "; ".join(f"ip -o route get {a}" for a in targets)
    out = alice(f"cellward run vmreal -- sh -c {shlex.quote(routes)}")
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == len(targets), f"{targets}:\n{out}"
    for line in lines:
        assert " dev awg0 " in line and not line.startswith("local"), f"not into the tunnel: {line}"

    # A service of the host's on every address it has. From the host it
    # answers on its LAN address, v4 and v6.
    machine.succeed(
        "systemd-run --unit=n3host socat TCP6-LISTEN:8097,fork,reuseaddr "
        "OPEN:/tmp/n3-got,creat,append"
    )
    machine.wait_until_succeeds("ss -ltn | grep -q ':8097 '")
    machine.succeed(f"echo host-v4 | socat -u - TCP4:{machine_ip}:8097")
    machine.succeed(f"echo host-v6 | socat -u - TCP6:[{machine_ip6}]:8097")
    machine.wait_until_succeeds("grep -q host-v4 /tmp/n3-got && grep -q host-v6 /tmp/n3-got")
    # From the zone, the same: the tunnel takes the SYN to the server, which
    # routes nothing on; the attempt is bounded, and what decides is the
    # listener's file. The host's loopback is the zone's own: the host's
    # resolver (dnsmasq on 127.0.0.1:5353) is not there.
    probe = (
        f"echo zone-v4 | timeout -s KILL 8 socat -u - TCP4:{machine_ip}:8097 & "
        f"echo zone-v6 | timeout -s KILL 8 socat -u - TCP6:[{machine_ip6}]:8097 & "
        "wait; "
        "socat -u OPEN:/dev/null TCP4:127.0.0.1:5353 || echo LO-REFUSED"
    )
    machine.succeed("socat -u OPEN:/dev/null TCP4:127.0.0.1:5353")
    out = alice(f"cellward run vmreal -- sh -c {shlex.quote(probe)}")
    assert "LO-REFUSED" in out, f"the host's loopback resolver in the zone: {out}"
    got = machine.succeed("cat /tmp/n3-got")
    assert "zone-" not in got, f"the zone reached the host's own service: {got}"
    machine.succeed("systemctl stop n3host && rm -f /tmp/n3-got")

    # The LAN by the server's LAN address: the host is seen as itself, the
    # zone only as the tunnel's address.
    server.succeed(
        "systemd-run --unit=n3lan socat "
        f"TCP4-LISTEN:8090,bind={server_ip},fork,reuseaddr "
        "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
    )
    server.wait_until_succeeds("ss -ltn | grep -q ':8090 '")
    out = machine.succeed(f"socat -T5 - TCP4:{server_ip}:8090")
    assert f"peer={machine_ip}" in out, out
    out = alice(f"cellward run vmreal -- socat -T10 - TCP4:{server_ip}:8090")
    assert "peer=10.99.0.2" in out, f"the LAN saw the zone as someone else: {out}"
    server.succeed("systemctl stop n3lan")

    # The uplink's filter lets out the tunnel's transport and nothing else,
    # the same server included: a datagram anywhere else is refused as it
    # is sent (EPERM from the output hook), with no clock to wait on. The
    # tunnel's own port goes out (junk to WireGuard, which drops it).
    up = machine.succeed(f"cat {STATE}/vmreal/uplink.pid").strip()

    def uplink_sends(target):
        return machine.execute(
            "su -l alice -c "
            + shlex.quote(
                "export XDG_RUNTIME_DIR=/run/user/1000; "
                f"nsenter --preserve-credentials -U -n -m -t {up} -- "
                f"sh -c 'echo x | socat -u - UDP-SENDTO:{target} 2>&1'"
            )
        )

    code, out = uplink_sends(f"{server_ip}:51820")
    assert code == 0, f"the tunnel's transport refused: {out}"
    # pasta gives the uplink a copy of the host's address on its way out:
    # that one is the uplink's own, and a datagram to it never leaves.
    own = in_zone(up, f"ip -4 -o addr show | {first}").split()
    refused = [f"{server_ip}:53", f"{server_ip}:8090", "192.168.1.254:53"]
    refused += [f"{a}:5353" for a in host_addrs if ":" not in a and a not in own]
    refused += [f"{g}:53" for g in gateways]
    for target in refused:
        code, out = uplink_sends(target)
        assert code != 0 and "not permitted" in out, f"the uplink sent to {target}: {out}"
