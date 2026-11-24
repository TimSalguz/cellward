"""Focused VM proof: named home=main, initially network=host, switched live.

The long-running helper writes through its own $HOME after every transition.
UDP senders from old epochs keep running and must stay mute in every later
network. The only published VPN is vmreal; host is intentionally absent from
the strict route list, as it is for the frame's reverse-target regression.
"""

import json
import shlex

NAME = "mainhome"
PY = f"python3 {HELPER}"
UDP_LOG = "/tmp/main-home-udp.log"


def instance(id_=NAME):
    status = json.loads(alice("cellward status --json"))
    return next((i for i in status["instances"] if i["id"] == id_), None)


def wait_instance(id_=NAME, predicate=lambda i: True):
    for _ in range(240):
        current = instance(id_)
        if current is not None and predicate(current):
            return current
        machine.sleep(0.5)
    raise AssertionError(f"{id_}: required state not reached: {instance(id_)}")


def keeper_pid(name=NAME):
    pid = alice(
        f"systemctl --user show -p MainPID --value vpn-zone-container@{name}.service"
    ).strip()
    assert pid and pid != "0", pid
    return pid


def helper_pid():
    return machine.succeed(f"pgrep -u alice -n -f '{HELPER} keep$'").strip()


def assert_same_process(pid, keeper):
    assert helper_pid() == pid, (helper_pid(), pid)
    assert keeper_pid() == keeper, (keeper_pid(), keeper)
    alice("systemctl --user is-active --quiet main-home-keep")


def mark(tag):
    alice(f"mkdir -p /home/alice/main-home-requests && touch /home/alice/main-home-requests/{tag}")
    machine.wait_until_succeeds(
        f"grep -q '^{tag} [0-9][0-9]*$' /home/alice/main-home-markers.log", timeout=30
    )


def request(tag, command):
    temporary = f"/home/alice/main-home-requests/.{tag}.tmp"
    final = f"/home/alice/main-home-requests/{tag}"
    alice(
        "mkdir -p /home/alice/main-home-requests && "
        f"printf %s {shlex.quote(command)} > {temporary} && mv {temporary} {final}"
    )
    machine.wait_until_succeeds(
        f"grep -q '^{tag} [0-9][0-9]*$' /home/alice/main-home-markers.log", timeout=30
    )


def tcp(tag, destination, port, expected):
    request(tag, f"tcp {destination} {port}")
    machine.wait_until_succeeds(
        f"grep -q '^{tag} ' /home/alice/main-home-results.log", timeout=15
    )
    answer = alice(f"grep '^{tag} ' /home/alice/main-home-results.log").strip()
    if expected is None:
        assert "peer=" not in answer, answer
    else:
        assert f"peer={expected}" in answer, answer


def launch(unit, network, command):
    alice(
        f"systemd-run --user --collect --unit={unit} -E PATH=\"$PATH\" "
        f"cellward run {network} --container {NAME} -- {command}"
    )


def sender(destination, tag):
    request(f"sender-{tag}", f"udp {destination} 7300 {tag}")


def logged(tag=None, source=None):
    lines = server.succeed(f"cat {UDP_LOG} 2>/dev/null || true").splitlines()
    return [
        line
        for line in lines
        if (tag is None or f" {tag}-" in line or line.endswith(f" {tag}"))
        and (source is None or line.startswith(source + " "))
    ]


def quiet_count(tag, source, seconds=4):
    previous = len(logged(tag, source))
    quiet = 0
    for _ in range(45):
        machine.sleep(1)
        current = len(logged(tag, source))
        quiet = quiet + 1 if current == previous else 0
        if quiet >= seconds:
            return current
        previous = current
    raise AssertionError(f"{tag} from {source}: did not become quiet")


def switch(network, epoch):
    out = alice(f"cellward container set {NAME} network {network} --yes")
    assert f"эпоха {epoch}" in out, out
    current = wait_instance()
    assert (current["network"], current["epoch"], current["exit"]) == (
        network,
        epoch,
        "through" if network != "offline" else "none",
    ), current
    assert current["live_switch"]["available"], current
    assert current["switch"]["state"] == "idle", current
    return current


def run(network, command):
    return alice(f"cellward run {network} --container {NAME} -- {command}")


def failed_set(container, network):
    return machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; "
            f"cellward container set {container} network {network} --yes 2>&1"
        )
    )


def ikey(id_):
    value = 0xCBF29CE484222325
    for byte in id_.encode():
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"i-{value:016x}"


with subtest("main-home switch: real WireGuard peer and source-logging UDP responder"):
    server.succeed("wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub")
    server_public = server.succeed("cat /root/wg.pub").strip()
    client_private = machine.succeed("wg genkey").strip()
    client_public = machine.succeed(f"printf %s '{client_private}' | wg pubkey").strip()
    server_ip = server.succeed(
        "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    ).strip()
    machine_ip = machine.succeed(
        "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    ).strip()
    assert server_ip and machine_ip
    server.succeed(
        "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 && "
        "wg set wg0 listen-port 51820 private-key /root/wg.key "
        f"peer '{client_public}' allowed-ips 10.99.0.2/32 && ip link set wg0 up"
    )
    server.succeed(
        "systemd-run --unit=main-home-udp "
        f"{PY} listen 7300 {UDP_LOG}"
    )
    server.succeed(
        "systemd-run --unit=main-home-lan socat "
        f"TCP-LISTEN:8090,bind={server_ip},fork,reuseaddr 'SYSTEM:echo peer=$SOCAT_PEERADDR'"
    )
    server.succeed(
        "systemd-run --unit=main-home-vpn socat "
        "TCP-LISTEN:8080,bind=10.99.0.1,fork,reuseaddr 'SYSTEM:echo peer=$SOCAT_PEERADDR'"
    )
    server.wait_until_succeeds(f"ss -ltn | grep -q '{server_ip}:8090'", timeout=30)
    alice(
        f"printf '[Interface]\\nPrivateKey = {client_private}\\nAddress = 10.99.0.2/32\\n"
        f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {server_public}\\n"
        f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' > /tmp/vmreal.conf"
    )
    alice("cellward add vmreal /tmp/vmreal.conf")
    alice("cellward routes enable && cellward routes allow vmreal")
    assert alice(f"cat {STATE}/.routes").splitlines() == ["vmreal"]

with subtest("main-home switch: named main+host has id=name, real home and live switch"):
    alice(f"cellward container create {NAME} --home main")
    alice(f"cellward container set {NAME} network host")
    launch("main-home-keep", "host", f"{PY} keep")
    current = wait_instance(predicate=lambda i: i["exit"] == "through" and i["live_switch"]["available"])
    assert current["id"] == NAME and ":" not in current["id"], current
    assert (current["network"], current["epoch"]) == ("host", 1), current
    original_pid = helper_pid()
    original_keeper = keeper_pid()
    mark("host-initial")
    host_home = machine.succeed("stat -c '%d:%i' /home/alice").strip()
    container_home = run("host", "stat -c '%d:%i' /home/alice").strip()
    assert container_home == host_home, (container_home, host_home)
    sender(server_ip, "h0")
    server.wait_until_succeeds(f"grep -q '^{machine_ip} h0-' {UDP_LOG}", timeout=60)
    out = run("host", f"socat -T10 - TCP:{server_ip}:8090")
    assert f"peer={machine_ip}" in out, out

with subtest("main-home switch: host → offline → host, no old socket resumes"):
    switch("offline", 2)
    assert_same_process(original_pid, original_keeper)
    mark("offline")
    h0_count = quiet_count("h0", machine_ip)
    sender(server_ip, "off")
    request("offline-once", f"udp_once {server_ip} 7300 offline-once")
    request("offline-vpn-once", "udp_once 10.99.0.1 7300 offline-vpn-once")
    current = instance()
    links = machine.succeed(f"nsenter -t {current['pid']} -n ip -o link show")
    assert len(links.strip().splitlines()) == 1 and ": lo:" in links, links
    routes = machine.succeed(f"nsenter -t {current['pid']} -n ip -4 route show")
    assert routes.startswith("unreachable default"), routes
    machine.sleep(2)
    assert not logged("off") and not logged("offline-once") and not logged("offline-vpn-once")

    switch("host", 3)
    assert_same_process(original_pid, original_keeper)
    mark("host-after-offline")
    machine.sleep(2)
    assert len(logged("h0", machine_ip)) == h0_count
    assert not logged("off") and not logged("offline-once")
    sender(server_ip, "h1")
    server.wait_until_succeeds(f"grep -q '^{machine_ip} h1-' {UDP_LOG}", timeout=60)

with subtest("main-home switch: host → VPN → host, route policy stays strict"):
    switch("vmreal", 4)
    assert_same_process(original_pid, original_keeper)
    mark("vpn")
    h1_count = quiet_count("h1", machine_ip)
    tcp("vpn-tcp", "10.99.0.1", 8080, "10.99.0.2")
    tcp("vpn-direct-tcp", server_ip, 8090, "10.99.0.2")
    sender("10.99.0.1", "v1")
    server.wait_until_succeeds(f"grep -q '^10.99.0.2 v1-' {UDP_LOG}", timeout=60)

    switch("host", 5)
    assert_same_process(original_pid, original_keeper)
    mark("host-after-vpn")
    v1_count = quiet_count("v1", "10.99.0.2")
    machine.sleep(2)
    assert len(logged("h1", machine_ip)) == h1_count
    tcp("host-vpn-tcp", "10.99.0.1", 8080, None)
    sender(server_ip, "h2")
    server.wait_until_succeeds(f"grep -q '^{machine_ip} h2-' {UDP_LOG}", timeout=60)
    assert alice(f"cat {STATE}/.routes").splitlines() == ["vmreal"]

with subtest("main-home switch: unpublished VPN and unconfined cannot change the live instance"):
    alice(f"cp {STATE}/vmreal/config.conf /tmp/vmblocked.conf && cellward add vmblocked /tmp/vmblocked.conf")
    code, out = failed_set(NAME, "vmblocked")
    assert code != 0, out
    current = instance()
    assert (current["network"], current["epoch"]) == ("host", 5), current
    assert_same_process(original_pid, original_keeper)
    code, out = failed_set(NAME, "unconfined")
    assert code != 0 and "--restart" in out, out
    assert (instance()["network"], instance()["epoch"]) == ("host", 5)
    assert_same_process(original_pid, original_keeper)
    mark("refusals-unchanged")

with subtest("main-home switch: main+ask keeps a per-network, non-switchable instance"):
    alice("cellward container create mainask --home main")
    alice("cellward container set mainask network ask")
    alice(
        "systemd-run --user --collect --unit=main-home-ask -E PATH=\"$PATH\" "
        "cellward run host --container mainask -- sleep infinity"
    )
    asked = wait_instance("mainask:host")
    assert asked["epoch"] == 1 and not asked["live_switch"]["available"], asked
    assert asked["live_switch"]["reason"] == "kind", asked
    control = f"{STATE}/.instances/{ikey('mainask:host')}/control"
    out = alice(f"printf 'SWITCH offline\\n' | socat - UNIX-CONNECT:{control}")
    assert out.startswith("REFUSED kind"), out
    assert (instance("mainask:host")["network"], instance("mainask:host")["epoch"]) == ("host", 1)
    assert instance("mainask") is None
    alice("systemctl --user is-active --quiet main-home-ask")

with subtest("main-home switch: unconfined has no instance and no live switch"):
    alice("cellward container create mainfree --home main")
    alice("cellward container set mainfree network unconfined")
    alice(
        "systemd-run --user --collect --unit=main-home-free -E PATH=\"$PATH\" "
        "cellward run unconfined --container mainfree -- sleep infinity"
    )
    machine.wait_until_succeeds("pgrep -u alice -f '^sleep infinity$'", timeout=30)
    assert instance("mainfree") is None and instance("mainfree:unconfined") is None
    alice("systemctl --user is-active --quiet main-home-free")

with subtest("main-home switch: failed attach is fail-closed, never back on host"):
    alice(f"mkdir -p {STATE}/vmfail")
    alice(
        "systemd-run --user --collect --unit=main-home-fakezone "
        f"{PY} fakezone {STATE}/vmfail /tmp/main-home-release /tmp/main-home-fake.log"
    )
    machine.wait_until_succeeds("grep -qx up /tmp/main-home-fake.log", timeout=30)
    # The stand-in is a published test route; host is still deliberately absent.
    alice(f"printf 'vmreal\\nvmfail\\n' > {STATE}/.routes")
    alice(
        f"systemd-run --user --collect --unit=main-home-failcli -E PATH=\"$PATH\" "
        f"cellward container set {NAME} network vmfail --yes"
    )
    machine.wait_until_succeeds("grep -qx asked /tmp/main-home-fake.log", timeout=60)
    current = wait_instance(predicate=lambda i: i["switch"]["state"] == "attaching")
    assert (current["network"], current["exit"], current["why"]) == ("vmfail", "none", "switching"), current
    assert_same_process(original_pid, original_keeper)
    mark("attach-held-offline")
    links = machine.succeed(f"nsenter -t {current['pid']} -n ip -o link show")
    assert len(links.strip().splitlines()) == 1 and ": lo:" in links, links
    request("failed-attach-once", f"udp_once {server_ip} 7300 failed-attach-once")
    machine.succeed("touch /tmp/main-home-release")
    current = wait_instance(predicate=lambda i: i["switch"]["state"] == "failed")
    assert (current["network"], current["exit"], current["why"], current["epoch"]) == (
        "vmfail",
        "none",
        "attach-failed",
        6,
    ), current
    assert_same_process(original_pid, original_keeper)
    mark("attach-failed")
    machine.sleep(2)
    assert not logged("failed-attach-once")
    h2_count = quiet_count("h2", machine_ip)
    assert len(logged("h0", machine_ip)) == h0_count
    assert len(logged("h1", machine_ip)) == h1_count
    assert len(logged("v1", "10.99.0.2")) == v1_count
    events = json.loads(alice("cellward journal --json"))["events"]
    own = [event for event in events if event.get("instance") == NAME]
    for from_net, to_net, epoch in [
        ("host", "offline", "2"),
        ("offline", "host", "3"),
        ("host", "vmreal", "4"),
        ("vmreal", "host", "5"),
    ]:
        assert any(
            event["event"] == "switch"
            and event.get("from") == from_net
            and event.get("to") == to_net
            and event.get("epoch") == epoch
            for event in own
        ), own
    failed = [event for event in own if event["event"] == "switch-failed"][-1]
    assert failed["phase"] == "attach", failed

with subtest("main-home switch: host reattaches in a new epoch, old senders stay mute"):
    switch("host", 7)
    assert_same_process(original_pid, original_keeper)
    mark("host-final")
    machine.sleep(2)
    assert len(logged("h2", machine_ip)) == h2_count
    assert len(logged("h0", machine_ip)) == h0_count
    assert len(logged("h1", machine_ip)) == h1_count
    assert len(logged("v1", "10.99.0.2")) == v1_count
    sender(server_ip, "h3")
    server.wait_until_succeeds(f"grep -q '^{machine_ip} h3-' {UDP_LOG}", timeout=60)
    markers = machine.succeed("cat /home/alice/main-home-markers.log").splitlines()
    expected = [
        "host-initial",
        "offline",
        "host-after-offline",
        "vpn",
        "host-after-vpn",
        "refusals-unchanged",
        "attach-held-offline",
        "attach-failed",
        "host-final",
    ]
    assert [line.split()[0] for line in markers if line.split()[0] in expected] == expected, markers
    assert len({line.split()[1] for line in markers}) == 1, markers

with subtest("main-home switch: preserve evidence"):
    alice("cellward status --json > /tmp/main-home-status.json")
    alice("cellward journal --json > /tmp/main-home-journal.json")
    machine.succeed("journalctl -b --no-pager > /tmp/main-home-machine.journal")
    server.succeed("journalctl -b --no-pager > /tmp/main-home-server.journal")
    machine.copy_from_vm("/tmp/main-home-status.json", "status.json")
    machine.copy_from_vm("/tmp/main-home-journal.json", "journal.json")
    machine.copy_from_vm("/home/alice/main-home-markers.log", "markers.log")
    machine.copy_from_vm("/home/alice/main-home-results.log", "results.log")
    machine.copy_from_vm("/tmp/main-home-machine.journal", "machine.journal")
    server.copy_from_vm("/tmp/main-home-server.journal", "server.journal")
    server.copy_from_vm(UDP_LOG, "udp.log")
