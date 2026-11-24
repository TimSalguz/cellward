"""Single-instance GUI proof for focus::switch_targets under strict routes."""

import json

NAME = "uimain"


def instance():
    status = json.loads(alice("cellward status --json"))
    return next((i for i in status["instances"] if i["id"] == NAME), None)


def wait_instance(network, epoch):
    for _ in range(240):
        current = instance()
        if current is not None and (current["network"], current["epoch"]) == (network, epoch):
            return current
        machine.sleep(0.5)
    raise AssertionError(f"{NAME}: not in {network} epoch {epoch}: {instance()}")


def keeper_pid():
    pid = alice(
        f"systemctl --user show -p MainPID --value vpn-zone-container@{NAME}.service"
    ).strip()
    return pid


def app_node(tree, app_id):
    if tree.get("app_id") == app_id:
        return tree
    for child in tree.get("nodes", []) + tree.get("floating_nodes", []):
        found = app_node(child, app_id)
        if found is not None:
            return found
    return None


with subtest("main-home focus-only: a real WireGuard zone is the sole published VPN"):
    server.succeed("wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub")
    server_public = server.succeed("cat /root/wg.pub").strip()
    client_private = machine.succeed("wg genkey").strip()
    client_public = machine.succeed(f"printf %s '{client_private}' | wg pubkey").strip()
    server_ip = server.succeed(
        "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    ).strip()
    server.succeed(
        "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 && "
        "wg set wg0 listen-port 51820 private-key /root/wg.key "
        f"peer '{client_public}' allowed-ips 10.99.0.2/32 && ip link set wg0 up"
    )
    alice(
        f"printf '[Interface]\\nPrivateKey = {client_private}\\nAddress = 10.99.0.2/32\\n"
        f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {server_public}\\n"
        f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' > /tmp/vmreal.conf"
    )
    alice("cellward add vmreal /tmp/vmreal.conf")
    alice("cellward routes enable && cellward routes allow vmreal")
    assert alice(f"cat {STATE}/.routes").splitlines() == ["vmreal"]

with subtest("main-home focus-only: host is a live reverse target in the real menu"):
    alice(f"cellward container create {NAME} --home main")
    alice(f"cellward container set {NAME} network host")
    alice(
        "systemd-run --user --unit=main-home-sway "
        "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
        "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
        "sway -c /dev/null"
    )
    machine.wait_until_succeeds("ls /run/user/1000/sway-ipc.*.sock", timeout=60)
    swaysock = machine.succeed("ls /run/user/1000/sway-ipc.*.sock | head -1").strip()
    display = machine.succeed("ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | head -1").strip()
    alice(
        "systemd-run --user --collect --unit=main-home-foot "
        f"--setenv=WAYLAND_DISPLAY={display} -E PATH=\"$PATH\" "
        f"cellward run host --container {NAME} -- foot --app-id mainhome"
    )
    machine.wait_until_succeeds(
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' "
        "| grep -q '\"app_id\": *\"mainhome\"'",
        timeout=60,
    )
    original_keeper = keeper_pid()
    assert original_keeper and original_keeper != "0", original_keeper
    current = wait_instance("host", 1)
    assert current["live_switch"]["available"], current
    out = alice(f"cellward container set {NAME} network vmreal --yes")
    assert "эпоха 2" in out, out
    current = wait_instance("vmreal", 2)
    assert current["exit"] == "through" and current["live_switch"]["available"], current
    assert keeper_pid() == original_keeper

    tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
    foot = app_node(tree, "mainhome")
    assert foot is not None
    foot_pid = str(foot["pid"])
    alice(
        "systemd-run --user --collect --unit=main-home-menu "
        f"--setenv=WAYLAND_DISPLAY={display} "
        f"cellward window-menu --pid {foot_pid} --network"
    )
    machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
    machine.wait_until_succeeds(
        "journalctl --no-pager | grep -F "
        "'сеть контейнера «uimain» (vmreal) меняется на ходу'",
        timeout=30,
    )
    machine.sleep(2)
    alice(f"WAYLAND_DISPLAY={display} grim /tmp/main-home-focus-targets.png")
    machine.copy_from_vm("/tmp/main-home-focus-targets.png", "focus-targets.png")
    # With the fix: offline, host. Without it the second action is a restart.
    alice(f"WAYLAND_DISPLAY={display} wtype -s 400 2")
    alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Return")
    machine.sleep(2)
    alice(f"WAYLAND_DISPLAY={display} grim /tmp/main-home-focus-confirm.png")
    machine.copy_from_vm("/tmp/main-home-focus-confirm.png", "focus-confirm.png")
    alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
    machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=30)
    current = wait_instance("vmreal", 2)
    assert current["exit"] == "through" and current["switch"]["state"] == "idle", current
    assert keeper_pid() == original_keeper, (keeper_pid(), original_keeper)
    assert machine.succeed(f"test -e /proc/{foot_pid} && echo {foot_pid}").strip() == foot_pid
    alice("systemctl --user is-active --quiet main-home-foot")
    assert alice(f"cat {STATE}/.routes").splitlines() == ["vmreal"]
    alice("cellward status --json > /tmp/main-home-focus-status.json")
    alice("cellward journal --json > /tmp/main-home-focus-journal.json")
    machine.succeed("journalctl -b --no-pager > /tmp/main-home-focus-machine.journal")
    machine.copy_from_vm("/tmp/main-home-focus-status.json", "focus-status.json")
    machine.copy_from_vm("/tmp/main-home-focus-journal.json", "focus-journal.json")
    machine.copy_from_vm("/tmp/main-home-focus-machine.journal", "focus-machine.journal")
