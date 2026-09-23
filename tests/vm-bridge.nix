# NixOS VM test of a user zone whose way out is a system zone (docs/SYSTEM.md
# §7b): one VPN, one tunnel, for the host's services and the user's programs.
#
# Two VMs on the test's private VLAN, no internet and nothing from the host:
#   - `server`, a real WireGuard peer with a TCP responder and a DNS server on
#     its tunnel address, and a second responder on its LAN address;
#   - `machine`, with both tiers: the NixOS module with the system zone `sz`
#     (config written at run time, keys generated inside the VMs) and the
#     egress policy enforced, and alice's user tier through home-manager. It
#     serves on its own LAN address too, which the user zone must never reach.
#
# Its own test rather than part of tests/vm-system.nix: that one runs its
# store from a read-only image (for a container's idmapped store), where
# home-manager cannot register its profile.
#
# Run:
#   nix-build tests/vm-bridge.nix -A driver && ./result/bin/nixos-test-driver
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
    name = "vpn-zones-vm-bridge";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [
          ../module/nixos.nix
          "${pins.home-manager}/nixos"
        ];

        services.vpn-zones.system = {
          enable = true;
          zones.sz = {
            # Not at boot: the config only exists once the test has written it.
            autoStart = false;
            users = [ "alice" ];
          };
          # A user outside every zone has no network: the user zone through
          # sz must not need any.
          egress = {
            enable = true;
            mode = "enforce";
          };
        };

        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          subUidRanges = [
            {
              startUid = 100000;
              count = 65536;
            }
          ];
          subGidRanges = [
            {
              startGid = 100000;
              count = 65536;
            }
          ];
          linger = true;
        };

        home-manager.useGlobalPkgs = true;
        home-manager.useUserPackages = true;
        home-manager.users.alice = {
          imports = [ ../module ];
          programs.vpn-zones.enable = true;
          home.stateVersion = "26.05";
        };

        environment.systemPackages = [
          pkgs.wireguard-tools
          pkgs.socat
          pkgs.procps
        ];

        virtualisation.cores = 2;
        virtualisation.memorySize = 1536;
      };

    nodes.server =
      { pkgs, ... }:
      {
        boot.kernelModules = [ "wireguard" ];
        environment.systemPackages = [
          pkgs.wireguard-tools
          pkgs.socat
          pkgs.dnsmasq
        ];
        networking.firewall.allowedUDPPorts = [ 51820 ];
        networking.firewall.allowedTCPPorts = [ 8090 ];
        networking.firewall.trustedInterfaces = [ "wg0" ];
        virtualisation.memorySize = 768;
      };

    testScript = ''
      import shlex

      def as_user(user, cmd):
          return f"su -l {user} -c {shlex.quote(cmd)}"

      def alice(cmd):
          return as_user("alice", f"export XDG_RUNTIME_DIR=/run/user/1000; {cmd}")

      def links(out):
          return [l for l in out.strip().splitlines() if l.strip()]

      # Every process in sz's namespace, with its owner: `ip netns pids`.
      def in_sz():
          return machine.succeed(
              "for p in $(ip netns pids vz-sz); do ps -o user=,comm= -p $p; done; true"
          )

      start_all()
      machine.wait_for_unit("multi-user.target")
      server.wait_for_unit("multi-user.target")

      with subtest("the system zone sz: a WireGuard tunnel to the server"):
          server.succeed("wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub")
          spub = server.succeed("cat /root/wg.pub").strip()
          cpriv = machine.succeed("wg genkey").strip()
          cpub = machine.succeed(f"printf %s '{cpriv}' | wg pubkey").strip()
          server_ip = server.succeed(
              "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()
          server.succeed(
              "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 && "
              "wg set wg0 listen-port 51820 private-key /root/wg.key "
              f"peer '{cpub}' allowed-ips 10.99.0.2/32 && ip link set wg0 up"
          )
          server.succeed(
              "systemd-run --unit=hello socat TCP-LISTEN:8080,bind=10.99.0.1,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed(
              f"systemd-run --unit=lan socat TCP-LISTEN:8090,bind={server_ip},fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed(
              "systemd-run --unit=dns dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=10.99.0.1 --no-resolv "
              "--address=/leaktest.internal/10.99.0.9"
          )
          machine.succeed(
              "mkdir -p /var/lib/vpn-zones/system/sz && "
              f"printf '[Interface]\\nPrivateKey = {cpriv}\\nAddress = 10.99.0.2/32\\n"
              f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
              f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' "
              "> /var/lib/vpn-zones/system/sz/config.conf && "
              "chmod 600 /var/lib/vpn-zones/system/sz/config.conf"
          )
          machine.succeed("systemctl start vpn-zone-system@sz")
          machine_ip = machine.succeed(
              "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()
          machine.succeed(
              f"systemd-run --unit=local socat TCP-LISTEN:8092,bind={machine_ip},fork,reuseaddr "
              "'SYSTEM:echo local'"
          )

      with subtest("a user zone through the system zone: one tunnel for both tiers"):
          machine.wait_for_unit("user@1000.service")
          # alice outside every zone: no network (the policy is enforced).
          machine.fail(alice(f"timeout 10 socat -T5 - TCP:{server_ip}:8090"))
          out = machine.succeed(alice("vpn-zone add mz --system sz"))
          assert "sz" in out, out
          # No key of its own: the config names the system zone, nothing else.
          machine.succeed("grep -q 'Name = sz' /home/alice/.local/state/vpn-zones/mz/config.conf")
          machine.fail("grep -q PrivateKey /home/alice/.local/state/vpn-zones/mz/config.conf")
          out = machine.succeed(alice("vpn-zone status --json"))
          assert '"name":"mz","kind":"system-zone"' in out and '"system_zone":"sz"' in out, out
          machine.succeed(alice("vpn-zone up mz"))
          # The server sees the system zone's tunnel address: the same tunnel.
          out = machine.succeed(alice("vpn-zone run mz -- socat -T10 - TCP:10.99.0.1:8080"))
          assert "peer=10.99.0.2" in out, out
          # lo and pasta's awg0, nothing else; the tunnel's resolver.
          out = machine.succeed(alice("vpn-zone run mz -- ip -o link show"))
          assert len(links(out)) == 2 and ": awg0" in out, out
          out = machine.succeed(alice("vpn-zone run mz -- getent ahostsv4 leaktest.internal"))
          assert "10.99.0.9" in out, out
          # Not the host: the only way out is sz's tunnel.
          machine.fail(alice(f"vpn-zone run mz -- timeout 5 socat -T3 - TCP:{machine_ip}:8092"))
          # pasta runs in the system zone's namespace, as alice — not as root.
          # (`ps` names it by the binary: pasta is passt, `passt.avx2` here.)
          def pastas(owner):
              return [
                  l for l in out.splitlines()
                  if l.split()[:1] == [owner] and l.split()[-1].startswith("pas")
              ]
          out = in_sz()
          assert pastas("alice") and not pastas("root"), out
          # Its liveness is the system zone's handshake.
          machine.wait_until_succeeds(alice("vpn-zone check mz"), timeout=60)

      with subtest("the system zone's key in a user zone: through the system zone, not twice"):
          machine.succeed(
              "install -o alice -m 600 /var/lib/vpn-zones/system/sz/config.conf /home/alice/sz.conf"
          )
          out = machine.succeed(alice("vpn-zone add mz2 /home/alice/sz.conf"))
          assert "sz" in out, out
          machine.succeed("grep -q 'Name = sz' /home/alice/.local/state/vpn-zones/mz2/config.conf")
          machine.fail("grep -q PrivateKey /home/alice/.local/state/vpn-zones/mz2/config.conf")
          machine.succeed("rm /home/alice/sz.conf")

      with subtest("it fails closed with the tunnel, and lets go of its pasta when down"):
          machine.succeed("systemctl stop vpn-zone-system@sz")
          machine.fail(alice("vpn-zone run mz -- timeout 5 socat -T3 - TCP:10.99.0.1:8080"))
          machine.fail(alice(f"vpn-zone run mz -- timeout 5 socat -T3 - TCP:{machine_ip}:8092"))
          machine.succeed("systemctl start vpn-zone-system@sz")
          machine.wait_until_succeeds(
              alice("vpn-zone run mz -- socat -T5 - TCP:10.99.0.1:8080 | grep peer=10.99.0.2"),
              timeout=60,
          )
          machine.succeed(alice("vpn-zone down mz"))
          machine.wait_until_succeeds(
              "test -z \"$(for p in $(ip netns pids vz-sz); do ps -o user= -p $p; done | grep alice)\"",
              timeout=30,
          )
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
