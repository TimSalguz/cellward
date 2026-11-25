# Focused NixOS VM test of ordered route alternatives and fail-closed failover.
# All keys are generated in the VMs; no host VPN, network or firewall is touched.
#
# Run: nix-build tests/vm-route-pools.nix -A driver && ./result/bin/nixos-test-driver
{ system ? builtins.currentSystem }:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
  dnsAnswer = pkgs.writeText "cellward-pool-dns.py" ''
    import socket
    import sys

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Answer from the numeric address the connected client asked, not from the
    # tunnel interface's address selected by a wildcard socket's route.
    server.bind((sys.argv[1], 53))
    while True:
        query, peer = server.recvfrom(65535)
        if len(query) < 12:
            continue
        answer = bytearray(query)
        answer[2:4] = b"\x81\x80"
        answer[6:8] = b"\x00\x01"
        answer[8:12] = b"\x00\x00\x00\x00"
        answer += b"\xc0\x0c"
        answer += b"\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x01"
        server.sendto(answer, peer)
        with open("/tmp/pool-dns-answers", "a") as log:
            log.write(str(peer) + "\n")
  '';
in
pkgs.testers.runNixOSTest {
  name = "cellward-route-pools";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ "${pins.home-manager}/nixos" ];

      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        linger = true;
        subUidRanges = [ { startUid = 100000; count = 65536; } ];
        subGidRanges = [ { startGid = 100000; count = 65536; } ];
      };
      home-manager.useGlobalPkgs = true;
      home-manager.useUserPackages = true;
      home-manager.users.alice = {
        imports = [ ../module ];
        programs.cellward.enable = true;
        home.stateVersion = "26.05";
      };

      boot.extraModulePackages = [ config.boot.kernelPackages.amneziawg ];
      boot.kernelModules = [ "amneziawg" "wireguard" "tun" "nf_tables" ];
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.tcpdump ];
      virtualisation.vlans = [ 1 ];
      virtualisation.cores = 2;
      virtualisation.memorySize = 1536;
    };

  nodes.server =
    { pkgs, ... }:
    {
      virtualisation.vlans = [ 1 ];
      boot.kernelModules = [ "wireguard" ];
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.socat pkgs.python3 ];
      networking.firewall.allowedUDPPorts = [ 51821 51822 51823 ];
      networking.firewall.trustedInterfaces = [ "wg1" "wg2" "wg3" ];
      virtualisation.memorySize = 768;
    };

  testScript = ''
    import shlex

    STATE = "/home/alice/.local/state/vpn-zones"

    def alice(cmd):
        return machine.succeed(
            "su -l alice -c "
            + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
        )

    def active():
        return machine.succeed(f"cat {STATE}/pooled/.pool-active").strip()

    def only_server(number):
        for n in [1, 2, 3]:
            server.succeed(f"ip link set wg{n} down")
        if number is not None:
            server.succeed(f"ip link set wg{number} up")

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("home-manager-alice.service")
    machine.wait_for_unit("user@1000.service")
    server.wait_for_unit("multi-user.target")
    # The test invokes watch synchronously; the wall clock must not change the
    # alternative halfway through an assertion.
    alice("systemctl --user stop vpn-zone-watch.timer")

    with subtest("three synthetic nodes share one ordered route"):
        server_ip = server.succeed(
            "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
        ).strip()
        assert server_ip, "server has no VLAN address"
        for number, name in [(1, "first"), (2, "second"), (3, "third")]:
            server_private = server.succeed("wg genkey").strip()
            server_public = server.succeed(
                f"printf %s '{server_private}' | wg pubkey"
            ).strip()
            client_private = machine.succeed("wg genkey").strip()
            client_public = machine.succeed(
                f"printf %s '{client_private}' | wg pubkey"
            ).strip()
            server.succeed(f"printf %s '{server_private}' > /root/wg{number}.key")
            server.succeed(
                f"ip link add wg{number} type wireguard && "
                f"ip addr add 10.99.0.1/24 dev wg{number} && "
                f"wg set wg{number} listen-port {51820 + number} "
                f"private-key /root/wg{number}.key peer '{client_public}' "
                "allowed-ips 10.99.0.2/32"
            )
            alice(
                f"printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.99.0.2/32\\nDNS = {server_ip}\\n\\n"
                f"[Peer]\\nPublicKey = %s\\nAllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:{51820 + number}\\n' "
                f"'{client_private}' '{server_public}' > /tmp/{name}.conf"
            )
            alice(f"cellward node add {name} /tmp/{name}.conf")
        only_server(1)
        server.succeed(
            "systemd-run --unit=pool-dns ${pkgs.python3}/bin/python3 ${dnsAnswer} "
            + server_ip
        )
        server.succeed(
            f"systemd-run --unit=pool-egress socat TCP-LISTEN:8090,bind={server_ip},fork,reuseaddr SYSTEM:'cat >/dev/null'"
        )
        server.wait_until_succeeds("ss -lun | grep -q ':53 '")
        server.wait_until_succeeds("ss -ltn | grep -q ':8090 '")
        alice(f"mkdir -p {STATE}/pooled")
        alice(
            f"printf '[Node]\\nName = first, second, third\\n[Pool]\\nProbeDNS = probe.test\\nProbeEgress = {server_ip}:8090\\n' "
            f"> {STATE}/pooled/config.conf"
        )
        alice("cellward routes enable")
        alice("cellward routes allow pooled")

    with subtest("fresh start requires an actual DNS answer and numeric TCP connection"):
        code, output = machine.execute(
            "su -l alice -c "
            + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; cellward up pooled")
        )
        if code != 0:
            print(output)
            print(server.succeed("wg show all latest-handshakes"))
            print(server.succeed("cat /tmp/pool-dns-answers 2>/dev/null || true"))
            print(server.succeed("journalctl -u pool-dns --no-pager -n 20"))
        assert code == 0, output
        assert active() == "first"
        machine.succeed(f"grep -q '^healthy$' {STATE}/pooled/.pool-health")
        server.wait_until_succeeds("test -s /tmp/pool-dns-answers")
        alice("systemctl --user is-active vpn-zone@pooled.service")

    with subtest("failure restarts the same route with the second alternative"):
        only_server(2)
        alice("cellward watch")
        assert active() == "second"
        alice("systemctl --user is-active vpn-zone@pooled.service")
        machine.succeed(f"grep -q '^healthy$' {STATE}/pooled/.pool-health")

    with subtest("the selected alternative survives an automatic route restart"):
        alice("systemctl --user restart vpn-zone@pooled.service")
        assert active() == "second"
        alice("cellward watch")
        assert active() == "second"
        alice("systemctl --user is-active vpn-zone@pooled.service")

    with subtest("another failure advances to the third alternative"):
        only_server(3)
        alice("cellward watch")
        assert active() == "third"
        alice("systemctl --user is-active vpn-zone@pooled.service")

    with subtest("a fresh explicit restart resets preference order"):
        only_server(1)
        alice("cellward restart pooled")
        assert active() == "first"
        alice("systemctl --user is-active vpn-zone@pooled.service")

    with subtest("WG handshake alone is not health; exhaustion stops without direct fallback"):
        handshakes = server.succeed("wg show wg1 latest-handshakes").strip()
        assert handshakes and not handshakes.endswith("\t0"), handshakes
        server.succeed("systemctl stop pool-dns")
        machine.succeed(
            f"tcpdump -i eth1 -nn -c 1 -w /tmp/pool-direct.pcap "
            f"'host {server_ip} and (port 53 or port 8090)' >/dev/null 2>&1 & "
            "echo $! > /tmp/pool-capture.pid"
        )
        alice("cellward watch")
        code, output = machine.execute(
            "runuser -u alice -- env XDG_RUNTIME_DIR=/run/user/1000 "
            "systemctl --user is-active vpn-zone@pooled.service"
        )
        assert code != 0, output
        assert active() == "third"
        machine.succeed(f"grep -q '^exhausted$' {STATE}/pooled/.pool-health")
        machine.succeed("kill $(cat /tmp/pool-capture.pid) || true")
        leaks = machine.succeed("tcpdump -nn -r /tmp/pool-direct.pcap 2>/dev/null")
        assert not leaks.strip(), f"direct DNS/TCP fallback escaped the route: {leaks}"
  '';
}
