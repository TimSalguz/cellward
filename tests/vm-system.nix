# NixOS VM test of the system tier (ROADMAP M10, docs/SYSTEM.md): a zone held by
# systemd from boot, a service and a NixOS container in it.
#
# Two VMs on the test's private VLAN, no internet and nothing from the host:
#   - `server`, a real WireGuard peer with a TCP responder and a DNS server
#     bound to its tunnel address, and a second responder on its LAN address;
#   - `machine`, with the NixOS module, the zone `sz` (config written at run
#     time, keys generated inside the VMs), a service `probe` and a container
#     `box` attached to it, and a resolver of its own (resolved + nscd) that
#     answers the test name differently from the tunnel's — so one lookup says
#     who answered it.
#
# Run:
#   nix-build tests/vm-system.nix -A driver && ./result/bin/nixos-test-driver
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
    name = "vpn-zones-vm-system";

    nodes.machine =
      { config, pkgs, ... }:
      {
        imports = [ ../module/nixos.nix ];

        services.vpn-zones.system = {
          enable = true;
          # Not at boot: the config only exists once the test has written it.
          zones.sz.autoStart = false;
          services.probe.zone = "sz";
          containers.box.zone = "sz";
        };

        # A service to look at the zone from: it only has to stay alive.
        systemd.services.probe = {
          serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          path = [ ];
        };

        containers.box = {
          config =
            { pkgs, ... }:
            {
              environment.systemPackages = [
                pkgs.socat
                pkgs.iproute2
                pkgs.dnsutils
              ];
              system.stateVersion = "26.05";
            };
        };

        # The host's own resolver, the one no consumer of the zone may reach:
        # resolved in front (varlink socket, stub resolv.conf) and nscd, which
        # NixOS runs by default and glibc asks before anything else.
        services.resolved = {
          enable = true;
          settings.Resolve = {
            DNS = [ "127.0.0.1:5353" ];
            FallbackDNS = [ ];
            Domains = [ "~." ];
          };
        };

        environment.systemPackages = [
          pkgs.wireguard-tools
          pkgs.socat
          pkgs.dnsmasq
          pkgs.nftables
          pkgs.tcpdump
        ];

        # The store from a disk image, not the host's over 9p: with
        # `privateUsers = "pick"` nixpkgs binds /nix/store into the container
        # with `idmap`, and 9p has no idmapped mounts ("Failed to clone
        # /nix/store: Invalid argument"). A real machine's ext4 or btrfs has.
        virtualisation.useNixStoreImage = true;
        # That image is read-only, so register-nix-paths can't fill the Nix
        # database at boot and /nix/var/nix/db is never made — and nixpkgs
        # binds it into every container. Empty is enough: the container only
        # reads it, and nothing here asks Nix anything.
        systemd.tmpfiles.rules = [ "d /nix/var/nix/db 0755 root root -" ];

        # Sized to run next to other VMs on a 16 GiB desktop: the zone, a
        # service and one small container fit in 1.5 GiB.
        virtualisation.cores = 2;
        virtualisation.memorySize = 1536;
      };

    nodes.server =
      { config, pkgs, ... }:
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
        # WireGuard, socat and dnsmasq only.
        virtualisation.memorySize = 768;
      };

    testScript = ''
      def links(out):
          return [l for l in out.strip().splitlines() if l.strip()]

      def netns_inode():
          return machine.succeed("stat -L -c %i /run/netns/vz-sz").strip()

      def in_probe(cmd):
          pid = machine.succeed("systemctl show -p MainPID --value probe").strip()
          return machine.succeed(f"nsenter -t {pid} -n -m -- {cmd}")

      def in_box(cmd):
          return machine.succeed(f"nixos-container run box -- {cmd}")

      start_all()
      machine.wait_for_unit("multi-user.target")
      server.wait_for_unit("multi-user.target")

      with subtest("the host has a resolver of its own, and it answers"):
          machine.succeed(
              "systemd-run --unit=hostdns dnsmasq -k --port=5353 --bind-interfaces "
              "--listen-address=127.0.0.1 --no-resolv "
              "--address=/leaktest.internal/10.66.66.66"
          )
          machine.succeed("systemctl restart systemd-resolved")
          machine.wait_until_succeeds(
              "getent ahostsv4 leaktest.internal | grep -q 10.66.66.66"
          )
          machine.succeed("test -S /run/nscd/socket")

      with subtest("server: a WireGuard peer, services on the tunnel and on the LAN"):
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

      with subtest("the namespace comes up alone: lo, the ruleset, an empty resolv.conf"):
          machine.succeed("systemctl start vpn-zone-system-ns-sz")
          out = machine.succeed("ip -n vz-sz -o link show")
          assert len(links(out)) == 1 and ": lo" in out, out
          rules = machine.succeed("ip netns exec vz-sz nft list ruleset")
          assert 'oifname "awg0" accept' in rules and "policy drop" in rules, rules
          machine.succeed("test -f /etc/netns/vz-sz/resolv.conf")
          machine.succeed("test \"$(stat -c %a:%G /run/vpn-zones/system/sz)\" = 2750:vpn-zones")

      with subtest("the zone comes up: config written, holder started"):
          machine.succeed(
              f"printf '[Interface]\\nPrivateKey = {cpriv}\\nAddress = 10.99.0.2/32\\n"
              f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
              f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' "
              "> /var/lib/vpn-zones/system/sz/config.conf && "
              "chmod 600 /var/lib/vpn-zones/system/sz/config.conf"
          )
          # Type=notify: `start` returns once the zone is up.
          machine.succeed("systemctl start vpn-zone-system-sz")
          machine.succeed("test -f /run/vpn-zones/system/sz/ready")

      with subtest("inside: exactly lo and awg0, nothing left in the host's namespace"):
          out = machine.succeed("ip -n vz-sz -o link show")
          assert len(links(out)) == 2 and ": awg0" in out and ": lo" in out, out
          machine.fail("ip link show vz-sz")
          out = machine.succeed("ip -n vz-sz -4 route show default")
          assert "dev awg0" in out, out
          out = machine.succeed("cat /etc/netns/vz-sz/resolv.conf")
          assert "nameserver 10.99.0.1" in out, out

      with subtest("the leak watch is armed on the physical interface"):
          machine.succeed(
              "systemd-run --unit=leakwatch tcpdump -n --immediate-mode -i eth1 "
              f"-w /tmp/leak.pcap 'host {server_ip} and not arp "
              "and not (udp and port 51820)'"
          )
          machine.wait_until_succeeds("journalctl -u leakwatch | grep -q 'listening on eth1'")

      with subtest("the tunnel carries traffic, and its state is readable by the group"):
          out = machine.succeed("ip netns exec vz-sz socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
          # The server's LAN address too goes through the tunnel, never around it.
          out = machine.succeed(f"ip netns exec vz-sz socat -T10 - TCP:{server_ip}:8090")
          assert "peer=10.99.0.2" in out, out
          machine.wait_until_succeeds(
              "grep -q 'latest handshake' /run/vpn-zones/system/sz/status", timeout=30
          )

      with subtest("a service in the zone: the tunnel's network and the tunnel's names"):
          machine.succeed("systemctl start probe")
          out = in_probe("socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
          out = in_probe("cat /etc/resolv.conf")
          assert "nameserver 10.99.0.1" in out, out
          # The host answers 10.66.66.66 through nscd or resolved; only the
          # tunnel's server answers 10.99.0.9.
          out = in_probe("getent ahostsv4 leaktest.internal")
          assert "10.99.0.9" in out and "10.66.66.66" not in out, out
          in_probe(
              "sh -c '! socat -u OPEN:/dev/null UNIX-CONNECT:/run/nscd/socket'"
          )
          in_probe(
              "sh -c '! socat -u OPEN:/dev/null "
              "UNIX-CONNECT:/run/systemd/resolve/io.systemd.Resolve'"
          )

      with subtest("a NixOS container in the zone: the same network, no way to change it"):
          machine.succeed("systemctl start container@box")
          machine.wait_until_succeeds("nixos-container run box -- true", timeout=120)
          out = in_box("ip -o link show")
          assert len(links(out)) == 2 and ": awg0" in out, out
          out = in_box("socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
          out = in_box("getent ahostsv4 leaktest.internal")
          assert "10.99.0.9" in out and "10.66.66.66" not in out, out
          # Its root has no capability over the zone's namespace.
          machine.fail("nixos-container run box -- ip link add vzx type dummy")
          machine.fail("nixos-container run box -- ip route add 10.1.0.0/16 dev awg0")
          # The host's Nix daemon is out of reach.
          machine.fail("nixos-container run box -- test -S /nix/var/nix/daemon-socket/socket")

      with subtest("nothing but the tunnel's UDP left eth1 towards the server"):
          machine.succeed("systemctl stop leakwatch")
          out = machine.succeed("tcpdump -n -r /tmp/leak.pcap 2>/dev/null | wc -l").strip()
          assert out == "0", machine.succeed("tcpdump -n -r /tmp/leak.pcap")

      with subtest("the tunnel stops: lo alone, the consumers keep running and reach nothing"):
          machine.succeed("systemctl stop vpn-zone-system-sz")
          out = machine.succeed("ip -n vz-sz -o link show")
          assert len(links(out)) == 1, out
          machine.succeed("systemctl is-active probe")
          machine.succeed("systemctl is-active container@box")
          in_probe("sh -c '! timeout 5 socat -T3 - TCP:10.99.0.1:8080'")
          machine.fail("nixos-container run box -- timeout 5 socat -T3 - TCP:10.99.0.1:8080")
          machine.succeed("systemctl start vpn-zone-system-sz")
          out = in_probe("socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out

      # Inode numbers of namespaces are reused as soon as one is freed, so
      # "a different inode" proves nothing. A per-namespace sysctl marks the
      # old one instead: the new namespace has the default, and so must the
      # namespace the service ends up in.
      with subtest("the namespace restarts: its consumers restart into the new one"):
          machine.succeed("ip netns exec vz-sz sysctl -qw net.ipv4.ip_default_ttl=63")
          assert in_probe("cat /proc/sys/net/ipv4/ip_default_ttl").strip() == "63"
          machine.succeed("systemctl restart vpn-zone-system-ns-sz")
          machine.succeed("systemctl start vpn-zone-system-sz probe container@box")
          out = machine.succeed("ip netns exec vz-sz cat /proc/sys/net/ipv4/ip_default_ttl").strip()
          assert out == "64", f"the namespace was not recreated: ttl {out}"
          assert in_probe("cat /proc/sys/net/ipv4/ip_default_ttl").strip() == "64"
          pid = machine.succeed("systemctl show -p MainPID --value probe").strip()
          ns = machine.succeed(f"readlink /proc/{pid}/ns/net").strip()
          assert ns == f"net:[{netns_inode()}]", f"probe is in {ns}"
          out = in_probe("socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
          machine.wait_until_succeeds("nixos-container run box -- true", timeout=120)
          out = in_box("socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
