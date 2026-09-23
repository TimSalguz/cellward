# NixOS VM test of system zones that go out through one interface of the host
# (`zones.<name>.uplink`, docs/SYSTEM.md §4a): two providers, and each zone
# by its own.
#
# Two VMs on two of the test's VLANs, no internet and nothing from the host:
#   - `server`, on both networks, a WireGuard peer for two keys with a TCP
#     responder on its tunnel address and one on every address it has;
#   - `machine`, on both networks (eth1, eth2), with the NixOS module and the
#     strict egress policy: `t2` a tunnel zone through eth2, `t1` a tunnel zone
#     through eth1 whose endpoint is on the second network only, `p2` a plain
#     zone through eth2.
#
# Run:
#   nix-build tests/vm-uplink.nix -A driver && ./result/bin/nixos-test-driver
{
  system ? builtins.currentSystem,
}:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };

  test = pkgs.testers.runNixOSTest {
    name = "vpn-zones-vm-uplink";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [ ../module/nixos.nix ];
        virtualisation.vlans = [
          1
          2
        ];

        services.vpn-zones.system = {
          enable = true;
          # Not at boot: the configs only exist once the test has written them.
          zones.t2 = {
            autoStart = false;
            uplink = "eth2";
          };
          zones.t1 = {
            autoStart = false;
            uplink = "eth1";
          };
          zones.p2 = {
            kind = "plain";
            uplink = "eth2";
          };
          # Strict: the host itself has no way out but the local network, so
          # the uplinks' pasta has to be let out by its owner.
          host.nix = "p2";
          egress = {
            enable = true;
            mode = "strict";
          };
        };

        environment.systemPackages = [
          pkgs.wireguard-tools
          pkgs.socat
          pkgs.procps
        ];

        virtualisation.cores = 2;
        virtualisation.memorySize = 1024;
      };

    nodes.server =
      { pkgs, ... }:
      {
        virtualisation.vlans = [
          1
          2
        ];
        boot.kernelModules = [ "wireguard" ];
        environment.systemPackages = [
          pkgs.wireguard-tools
          pkgs.socat
        ];
        networking.firewall.allowedUDPPorts = [ 51820 ];
        networking.firewall.allowedTCPPorts = [ 8090 ];
        networking.firewall.trustedInterfaces = [ "wg0" ];
        virtualisation.memorySize = 768;
      };

    testScript = ''
      def addr(node, iface):
          return node.succeed(
              f"ip -4 -o addr show {iface} | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()

      # A refusal is checked as `sh -c '! timeout -s KILL …'` inside the
      # namespace: a SYN the uplink's filter drops leaves socat in connect(),
      # and there it said "exiting on signal 15" and never exited — the test
      # hung. SIGKILL cannot be caught.
      def links(out):
          return [l for l in out.strip().splitlines() if l.strip()]

      start_all()
      machine.wait_for_unit("multi-user.target")
      server.wait_for_unit("multi-user.target")

      with subtest("the server: WireGuard for two keys, on both networks"):
          server_ip1, server_ip2 = addr(server, "eth1"), addr(server, "eth2")
          machine_ip1, machine_ip2 = addr(machine, "eth1"), addr(machine, "eth2")
          server.succeed("wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub")
          spub = server.succeed("cat /root/wg.pub").strip()
          keys = {}
          for zone in ["t1", "t2"]:
              priv = machine.succeed("wg genkey").strip()
              keys[zone] = (priv, machine.succeed(f"printf %s '{priv}' | wg pubkey").strip())
          server.succeed(
              "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 && "
              "wg set wg0 listen-port 51820 private-key /root/wg.key "
              f"peer '{keys['t2'][1]}' allowed-ips 10.99.0.2/32 "
              f"peer '{keys['t1'][1]}' allowed-ips 10.99.0.3/32 && ip link set wg0 up"
          )
          server.succeed(
              "systemd-run --unit=hello socat TCP-LISTEN:8080,bind=10.99.0.1,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed(
              "systemd-run --unit=lan socat TCP-LISTEN:8090,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          # Both tunnels' endpoint is on the second network only.
          for zone, address in [("t2", "10.99.0.2"), ("t1", "10.99.0.3")]:
              machine.succeed(
                  f"mkdir -p /var/lib/vpn-zones/system/{zone} && "
                  f"printf '[Interface]\\nPrivateKey = {keys[zone][0]}\\nAddress = {address}/32\\n"
                  f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
                  f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip2}:51820\\n' "
                  f"> /var/lib/vpn-zones/system/{zone}/config.conf && "
                  f"chmod 600 /var/lib/vpn-zones/system/{zone}/config.conf"
              )

      with subtest("a tunnel zone through eth2: the tunnel leaves by eth2"):
          machine.succeed("systemctl start vpn-zone-system@t2")
          out = machine.succeed("ip netns exec vz-t2 socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
          # The server saw the tunnel come from the machine's second address.
          out = server.succeed("wg show wg0 endpoints")
          assert f"{keys['t2'][1]}\t{machine_ip2}:" in out, out
          out = machine.succeed("ip -n vz-t2 -o link show")
          assert len(links(out)) == 2 and ": awg0" in out, out
          # The uplink's pasta runs as the plain zones' user, not as root.
          machine.succeed("pgrep -u vpn-zones-plain -f 'netns /run/netns/vz[u]-t2'")
          # The uplink's filter: the tunnel's packets to the endpoint, nothing
          # else from there.
          machine.succeed(f"ip netns exec vzu-t2 sh -c '! timeout -s KILL 5 socat -T3 - TCP:{server_ip2}:8090'")

      with subtest("a tunnel zone through the wrong interface stays closed, never takes the other"):
          machine.succeed("systemctl start vpn-zone-system@t1")
          machine.succeed("ip netns exec vz-t1 sh -c '! timeout -s KILL 8 socat -T5 - TCP:10.99.0.1:8080'")
          out = server.succeed("wg show wg0 latest-handshakes")
          assert f"{keys['t1'][1]}\t0" in out, out

      with subtest("a plain zone through eth2: the second network, and not the first"):
          machine.wait_for_unit("vpn-zone-system@p2.service")
          out = machine.succeed(f"ip netns exec vz-p2 socat -T10 - TCP:{server_ip2}:8090")
          assert f"peer={machine_ip2}" in out, out
          machine.succeed(f"ip netns exec vz-p2 sh -c '! timeout -s KILL 5 socat -T3 - TCP:{server_ip1}:8090'")

      with subtest("the zone's uplink goes with it, and comes back with it"):
          machine.succeed("systemctl stop vpn-zone-system@t2")
          machine.fail("test -e /run/netns/vzu-t2")
          machine.fail("pgrep -f 'netns /run/netns/vz[u]-t2'")
          machine.succeed("ip netns exec vz-t2 sh -c '! timeout -s KILL 5 socat -T3 - TCP:10.99.0.1:8080'")
          machine.succeed("systemctl start vpn-zone-system@t2")
          out = machine.succeed("ip netns exec vz-t2 socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
