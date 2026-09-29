"""tests/vm.nix, continued: a tunnel cut after its first kilobytes is told
(docs/PERMISSIONS.md §11.16, step 4). The server lets the first 16 KB of
the tunnel out and drops the rest — the censor's signature —; the zone's
programs go on sending; `cellward watch` says the network looks throttled:
after two looks, and once.

Executed by the main test script with exec(), in its globals (machine,
server, alice, in_zone, STATE; vmreal down, its peer on the server): the
script is handed to the driver's build in one environment variable, and the
kernel takes 128 KiB there (MAX_ARG_STRLEN).
"""

import json


def counters():
    """vmreal's tunnel counters, as its status mirror has them now."""
    status = json.loads(alice("cellward status --json"))
    net = next(n for n in status["networks"] if n["name"] == "vmreal")
    return net["rx_bytes"] or 0, net["tx_bytes"] or 0


def look():
    """One look of the watcher: vmreal's row."""
    out = json.loads(alice("cellward watch --json"))
    return next(z for z in out["zones"] if z["name"] == "vmreal")


def until(cond, what, tries=60):
    """`cond()` true within `tries` looks a second apart."""
    for _ in range(tries):
        if cond():
            return
        machine.sleep(1)
    raise AssertionError(f"never: {what}")


def push(zpid):
    """Programs of the zone sending into a tunnel that answers nothing, and
    the mirror showing it — more than keepalives."""
    _, tx = counters()
    in_zone(zpid, "ping -c 20 -i 0.2 -W 1 10.99.0.1 >/dev/null 2>&1 || true")
    until(lambda: counters()[1] > tx + 1024, "the pings in the mirror")


with subtest("a tunnel cut after its first kilobytes: watch says the network looks throttled"):
    # The timer's looks would interleave with these.
    alice("systemctl --user stop vpn-zone-watch.timer")
    # The cut: what the server sends into the tunnel stops at 16 KB, counted
    # from before the zone comes up.
    server.succeed(
        "nft add table inet cut && "
        "nft add chain inet cut out '{ type filter hook output priority 0; }' && "
        "nft add rule inet cut out udp sport 51820 quota over 16 kbytes drop"
    )
    server.succeed(
        "systemd-run --unit=big socat TCP-LISTEN:8097,bind=10.99.0.1,fork,reuseaddr "
        "'SYSTEM:head -c 200000 /dev/zero'"
    )
    alice("cellward up vmreal")
    zpid = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()
    # A download larger than the cut: its first kilobytes come, the rest never.
    in_zone(zpid, "socat -T5 - TCP:10.99.0.1:8097 >/dev/null 2>&1 || true")
    until(lambda: counters()[0] >= 10 * 1024, "the first kilobytes in the mirror")
    rx, _ = counters()
    assert rx <= 24 * 1024, f"more than the cut came through: {rx}"

    first = look()
    assert first["verdict"] == "unknown", first
    push(zpid)
    second = look()
    assert (second["verdict"], second["notified"]) == ("suspect", False), second
    push(zpid)
    third = look()
    assert (third["verdict"], third["notified"]) == ("throttled", True), third
    # Once: the next look keeps it and says nothing.
    push(zpid)
    fourth = look()
    assert (fourth["verdict"], fourth["notified"]) == ("throttled", False), fourth
    assert counters()[0] == rx, "the cut let something through after all"

    alice("cellward down vmreal")
    server.succeed("systemctl stop big")
    server.succeed("nft delete table inet cut")
    alice("systemctl --user start vpn-zone-watch.timer")
