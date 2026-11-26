# End-to-end scoped proxy: real SOCKS5/HTTP CONNECT and DNS inside a synthetic zone.
{ system ? builtins.currentSystem }:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
  peerServer = pkgs.writeText "cellward-zone-proxy-peer.py" ''
    import http.server
    import sys

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.client_address[0].encode()
            with open(sys.argv[3], "a") as log:
                log.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass

    http.server.HTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "cellward-zone-proxy";

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
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.curl ];
      virtualisation.vlans = [ 1 ];
      virtualisation.cores = 2;
      virtualisation.memorySize = 1536;
    };

  nodes.server =
    { pkgs, ... }:
    {
      virtualisation.vlans = [ 1 ];
      boot.kernelModules = [ "wireguard" ];
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.python3 pkgs.dnsmasq ];
      networking.firewall.allowedUDPPorts = [ 53 51820 ];
      networking.firewall.allowedTCPPorts = [ 8090 8091 ];
      networking.firewall.trustedInterfaces = [ "wg0" ];
      virtualisation.memorySize = 768;
    };

  testScript = ''
    import shlex

    def alice(cmd):
        return machine.succeed(
            "su -l alice -c "
            + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
        )

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("home-manager-alice.service")
    machine.wait_for_unit("user@1000.service")
    server.wait_for_unit("multi-user.target")

    server_ip = server.succeed(
        "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    ).strip()
    assert server_ip, "server has no VLAN address"
    machine.succeed(f"printf 'nameserver {server_ip}\\n' > /etc/resolv.conf")
    machine_ip = machine.succeed(
        "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
    ).strip()
    assert machine_ip, "machine has no VLAN address"
    server_private = server.succeed("wg genkey").strip()
    server_public = server.succeed(f"printf %s '{server_private}' | wg pubkey").strip()
    client_private = machine.succeed("wg genkey").strip()
    client_public = machine.succeed(f"printf %s '{client_private}' | wg pubkey").strip()
    server.succeed(f"printf %s '{server_private}' > /root/wg0.key")
    server.succeed(
        "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 && "
        f"wg set wg0 listen-port 51820 private-key /root/wg0.key peer '{client_public}' "
        "allowed-ips 10.99.0.2/32 && ip link set wg0 up"
    )
    alice(
        f"printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.99.0.2/32\\nDNS = {server_ip}\\n\\n"
        f"[Peer]\\nPublicKey = %s\\nAllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' "
        f"'{client_private}' '{server_public}' > /tmp/proxied.conf"
    )
    alice("cellward add proxied /tmp/proxied.conf")
    server.succeed(
        f"systemd-run --unit=zone-proxy-dns dnsmasq -k --port=53 --bind-interfaces "
        f"--listen-address={server_ip} --no-resolv "
        "--address=/selected.test/10.99.0.1 "
        f"--address=/denied.test/{server_ip}"
    )
    server.succeed(
        "systemd-run --unit=peer-zone python3 ${peerServer} 10.99.0.1 8090 /tmp/zone-hits"
    )
    server.succeed(
        f"systemd-run --unit=peer-lan python3 ${peerServer} {server_ip} 8091 /tmp/lan-hits"
    )
    server.wait_for_open_port(53, server_ip)
    server.wait_for_open_port(8090, "10.99.0.1")
    server.wait_for_open_port(8091, server_ip)

    with subtest("default zone: SOCKS5 and HTTP CONNECT resolve and connect through the zone"):
        alice("cellward zone-proxy set proxied 1080 zone")
        alice("cellward up proxied")
        alice("systemctl --user is-active vpn-zone-proxy@proxied.service")
        for proxy_args in ["--socks5-hostname 127.0.0.1:1080", "--proxytunnel -x http://127.0.0.1:1080"]:
            out = alice(
                f"curl --max-time 15 {proxy_args} "
                "http://selected.test:8090"
            ).strip()
            assert out == "10.99.0.2", (proxy_args, out)
        alice("cellward down proxied")
        machine.fail(
            "runuser -u alice -- env XDG_RUNTIME_DIR=/run/user/1000 "
            "systemctl --user is-active vpn-zone-proxy@proxied.service"
        )
        alice("cellward up proxied")
        alice("systemctl --user is-active vpn-zone-proxy@proxied.service")

    with subtest("default deny rejects without a direct connection"):
        alice("cellward zone-proxy set proxied 1080 deny")
        machine.fail(
            "su -l alice -c "
            + shlex.quote(
                "export XDG_RUNTIME_DIR=/run/user/1000; "
                "curl --max-time 10 --proxytunnel -x http://127.0.0.1:1080 "
                "http://denied.test:8091"
            )
        )
        machine.succeed("test ! -e /tmp/lan-hits")

    with subtest("explicit host mode splits only unmatched traffic"):
        alice("cellward zone-proxy set proxied 1080 host selected.test")
        selected = alice(
            "curl --max-time 15 --proxytunnel -x http://127.0.0.1:1080 "
            "http://selected.test:8090"
        ).strip()
        assert selected == "10.99.0.2", selected
        direct = alice(
            "curl --max-time 15 --proxytunnel -x http://127.0.0.1:1080 "
            "http://denied.test:8091"
        ).strip()
        assert direct == machine_ip, direct
        assert direct != "10.99.0.2", direct

    with subtest("a missing zone fails closed even in host mode"):
        alice("cellward down proxied")
        machine.fail(
            "su -l alice -c "
            + shlex.quote(
                "export XDG_RUNTIME_DIR=/run/user/1000; "
                "curl --max-time 10 --proxytunnel -x http://127.0.0.1:1080 "
                "http://selected.test:8090"
            )
        )
  '';
}
