# Focused NixOS VM test of three user-owned VPN hops. Three WireGuard servers
# run in a second VM; the middle and inner endpoints are reachable only
# through the preceding tunnels. Also verifies publication and teardown.
#
# Run: nix-build tests/vm-user-chain.nix -A driver && ./result/bin/nixos-test-driver
{ system ? builtins.currentSystem }:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
in
pkgs.testers.runNixOSTest {
  name = "cellward-user-chain";

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ "${pins.home-manager}/nixos" ../module/nixos.nix ];

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

      # Only the namespace broker is needed: there are no system VPN zones,
      # and its directRoutes list permits none to dial from the host.
      services.cellward.system = {
        enable = true;
        users = [ "alice" ];
        directRoutes = [ ];
      };
      boot.extraModulePackages = [ config.boot.kernelPackages.amneziawg ];
      boot.kernelModules = [ "amneziawg" "wireguard" "tun" "nf_tables" ];
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.procps pkgs.iproute2 ];
      virtualisation.vlans = [ 1 ];
      virtualisation.cores = 2;
      virtualisation.memorySize = 1536;
    };

  nodes.server =
    { pkgs, ... }:
    {
      virtualisation.vlans = [ 1 ];
      boot.kernelModules = [ "wireguard" ];
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.iputils ];
      networking.firewall.allowedUDPPorts = [ 51821 ];
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

    def add_node(name, number, private, public, endpoint):
        alice(
            f"printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.99.{number}.2/32\\n\\n"
            f"[Peer]\\nPublicKey = %s\\nAllowedIPs = 0.0.0.0/0\\n"
            f"Endpoint = {endpoint}\\n' "
            f"'{private}' '{public}' > /tmp/{name}.conf"
        )
        alice(f"cellward node add {name} /tmp/{name}.conf")

    def pasta_in(inside, outside):
        outer_pid = machine.succeed(f"cat {STATE}/{outside}/zone.pid").strip()
        inner_uplink = machine.succeed(f"cat {STATE}/{inside}/uplink.pid").strip()
        pasta_pid = machine.succeed(
            f"pgrep -f '[p]asta.*--netns /proc/{inner_uplink}/ns/net' | head -1"
        ).strip()
        machine.succeed(
            f'test "$(readlink /proc/{pasta_pid}/ns/net)" = '
            f'"$(readlink /proc/{outer_pid}/ns/net)"'
        )

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("home-manager-alice.service")
    machine.wait_for_unit("user@1000.service")
    server.wait_for_unit("multi-user.target")

    with subtest("three nested WireGuard servers are reachable only over preceding hops"):
        server_ip = server.succeed(
            "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
        ).strip()
        assert server_ip, "server has no VLAN address"
        for name, number, endpoint in [
            ("outer", 1, f"{server_ip}:51821"),
            ("middle", 2, "10.99.1.1:51822"),
            ("inner", 3, "10.99.2.1:51823"),
        ]:
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
                f"ip addr add 10.99.{number}.1/24 dev wg{number} && "
                f"wg set wg{number} listen-port {51820 + number} "
                f"private-key /root/wg{number}.key peer '{client_public}' "
                f"allowed-ips 10.99.{number}.2/32 && ip link set wg{number} up"
            )
            add_node(name, number, client_private, server_public, endpoint)

    with subtest("all three routes have exact publication before any starts"):
        alice("cellward routes enable")
        alice("cellward route add outer outer")
        alice("cellward route add middle middle --via-user outer")
        alice("cellward route add inner inner --via-user middle")
        alice("cellward routes allow outer")
        alice("cellward routes allow middle")
        alice("cellward routes allow inner")
        routes = alice("cellward routes list")
        assert "outer >> middle >> inner" in routes, routes
        assert "outer >> middle" in routes, routes
        # The same pooled inner node must not be publishable directly.
        alice("cellward route add inner-direct inner")
        code, output = machine.execute(
            "su -l alice -c "
            + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; cellward routes allow inner-direct")
        )
        assert code != 0, output

    with subtest("starting the innermost route starts and wires every prefix"):
        alice("cellward up inner")
        for name in ["outer", "middle", "inner"]:
            machine.succeed(f"test -f {STATE}/{name}/ready")
        pasta_in("middle", "outer")
        pasta_in("inner", "middle")
        inner_pid = machine.succeed(f"cat {STATE}/inner/zone.pid").strip()
        machine.wait_until_succeeds(
            "su -l alice -c "
            + shlex.quote(
                f"export XDG_RUNTIME_DIR=/run/user/1000; "
                f"nsenter --preserve-credentials -U -n -m -t {inner_pid} -- "
                "ping -c1 -W2 10.99.3.1"
            ),
            timeout=60,
        )
        for number in [1, 2, 3]:
            handshakes = server.succeed(f"wg show wg{number} latest-handshakes")
            assert handshakes.strip() and not handshakes.strip().endswith("\t0"), handshakes

    with subtest("losing the outer VPN cuts both dependent hops"):
        alice("cellward down outer")
        for name in ["middle", "inner"]:
            machine.wait_until_succeeds(
                "! runuser -u alice -- env XDG_RUNTIME_DIR=/run/user/1000 "
                f"systemctl --user is-active vpn-zone@{name}.service >/dev/null 2>&1"
            )
  '';
}
