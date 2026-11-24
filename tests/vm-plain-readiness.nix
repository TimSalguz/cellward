# A plain system zone must not become ready when pasta picked an interface
# before the real uplink had an address and a default route. The failed holder
# is restarted by systemd and the Nix daemon, already inside its namespace,
# gets working DNS and egress once the real route appears.
#
# Run:
#   nix-build tests/vm-plain-readiness.nix -A driver && ./result/bin/nixos-test-driver
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
    name = "cellward-vm-plain-readiness";

    nodes.machine =
      { lib, pkgs, ... }:
      {
        imports = [ ../module/nixos.nix ];

        networking.useDHCP = false;
        networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.168.1.2";
            prefixLength = 24;
          }
        ];
        networking.defaultGateway = "192.168.1.1";

        services.cellward.system = {
          enable = true;
          # This test uses none of the polkit-gated switches.
          switchGroup = null;
          zones.pl = {
            kind = "plain";
            autoStart = false;
            dns = [ "192.168.1.1" ];
          };
          host.nix = "pl";
          egress = {
            enable = true;
            mode = "strict";
            emergency.group = null;
          };
        };

        users.users.alice.isNormalUser = true;
        nix.settings.substituters = lib.mkForce [ ];
        environment.systemPackages = [
          pkgs.dnsutils
          pkgs.socat
        ];

        virtualisation.cores = 2;
        virtualisation.memorySize = 1024;
      };

    nodes.server =
      { lib, pkgs, ... }:
      {
        networking.useDHCP = false;
        networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.168.1.1";
            prefixLength = 24;
          }
          {
            address = "198.51.100.1";
            prefixLength = 24;
          }
        ];
        networking.firewall.allowedTCPPorts = [
          53
          8091
        ];
        networking.firewall.allowedUDPPorts = [ 53 ];
        environment.systemPackages = [
          pkgs.dnsmasq
          pkgs.python3
        ];
        virtualisation.memorySize = 768;
      };

    testScript = ''
      import shlex

      def as_user(user, cmd):
          return f"su -l {user} -c {shlex.quote(cmd)}"

      def netns_of(unit):
          pid = machine.succeed(f"systemctl show -p MainPID --value {unit}").strip()
          assert pid != "0", f"{unit} is not running"
          return machine.succeed(f"readlink /proc/{pid}/ns/net").strip()

      def zone_netns():
          return "net:[" + machine.succeed("stat -L -c %i /run/netns/vz-pl").strip() + "]"

      def in_daemon(cmd):
          pid = machine.succeed("systemctl show -p MainPID --value nix-daemon").strip()
          assert pid != "0", "nix-daemon is not running"
          return f"nsenter -t {pid} -n -m -- {cmd}"

      start_all()
      machine.wait_for_unit("multi-user.target")
      server.wait_for_unit("multi-user.target")

      with subtest("server: the real router and HTTP origin; DNS initially down"):
          server.succeed("mkdir -p /srv && printf 'plain-readiness\\n' > /srv/f")
          server.succeed(
              "systemd-run --unit=web python3 -m http.server 8091 "
              "--bind 198.51.100.1 --directory /srv"
          )
          server.wait_for_open_port(8091, "198.51.100.1")
          server.fail("nc -z 192.168.1.1 53")

      with subtest("a routeless bridge is not readiness, and the holder retries"):
          # Recreate the NetworkManager race deterministically: virbr0 is the
          # only interface with an IPv4 address; eth1 gets its real address and
          # the default route only after pasta's first attempt has failed.
          machine.succeed(
              "systemctl stop nix-daemon.service vpn-zone-system@pl.service && "
              "ip route flush default && ip -4 addr flush dev eth1 && "
              "ip link add virbr0 type bridge && ip addr add 192.168.122.1/24 dev virbr0 && "
              "ip link set virbr0 up && systemctl start --no-block vpn-zone-system@pl.service"
          )
          machine.wait_until_succeeds(
              "journalctl -u vpn-zone-system@pl.service | "
              "grep -q 'pasta gave the zone no IPv4 default route'",
              timeout=30,
          )
          machine.wait_until_succeeds(
              "test \"$(systemctl show -p SubState --value vpn-zone-system@pl.service)\" = auto-restart",
              timeout=30,
          )
          restarts_before = int(machine.succeed(
              "systemctl show -p NRestarts --value vpn-zone-system@pl.service"
          ).strip())
          machine.fail("test -e /run/vpn-zones/system/pl/ready")
          machine.fail("test -e /run/vpn-zones/system/pl/status")
          machine.fail("pgrep -u vpn-zones-plain -x pasta")
          out = machine.succeed("ip -n vz-pl -4 route show default")
          assert not out.strip(), out

          # The daemon does not wait for the holder by design. It stays in the
          # same namespace, but has neither resolver nor egress while the zone
          # is not ready.
          machine.succeed("systemctl start nix-daemon.service")
          assert netns_of("nix-daemon") == zone_netns()
          machine.fail(in_daemon("timeout 5 getent ahostsv4 daemon.internal"))
          machine.fail(in_daemon("timeout 5 socat -T3 - TCP:198.51.100.1:8091"))

      with subtest("a default route with dead DNS/egress is still not readiness"):
          machine.succeed(
              "ip addr add 192.168.1.2/24 dev eth1 && ip link set eth1 up && "
              "ip route add default via 192.168.1.1 dev eth1"
          )
          machine.wait_until_succeeds(
              "journalctl -u vpn-zone-system@pl.service | "
              "grep -q 'no configured resolver answered through the plain zone'",
              timeout=45,
          )
          machine.wait_until_succeeds(
              "test \"$(systemctl show -p SubState --value vpn-zone-system@pl.service)\" = auto-restart",
              timeout=30,
          )
          restarts_before_recovery = int(machine.succeed(
              "systemctl show -p NRestarts --value vpn-zone-system@pl.service"
          ).strip())
          assert restarts_before_recovery > restarts_before
          machine.fail("test -e /run/vpn-zones/system/pl/ready")
          machine.fail("test -e /run/vpn-zones/system/pl/status")
          machine.fail("pgrep -u vpn-zones-plain -x pasta")
          out = machine.succeed("ip -4 route show default")
          assert "default via 192.168.1.1" in out and "dev eth1" in out, out

      with subtest("the retry with live resolver brings up daemon DNS and egress"):
          server.succeed(
              "systemd-run --unit=dns dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=192.168.1.1 --no-resolv "
              "--address=/daemon.internal/198.51.100.1"
          )
          server.wait_for_open_port(53, "192.168.1.1")
          machine.wait_for_unit("vpn-zone-system@pl.service", timeout=60)
          machine.wait_until_succeeds("test -e /run/vpn-zones/system/pl/ready", timeout=30)
          restarts_after = int(machine.succeed(
              "systemctl show -p NRestarts --value vpn-zone-system@pl.service"
          ).strip())
          assert restarts_after > restarts_before_recovery, (
              restarts_before_recovery, restarts_after
          )
          out = machine.succeed("ip -n vz-pl -4 route show default")
          assert "default" in out and "dev awg0" in out, out
          out = machine.succeed("ip -n vz-pl -4 addr show dev awg0")
          assert "192.168.1.2" in out, out
          machine.succeed("grep -q '^nameserver 192.168.1.1$' /etc/netns/vz-pl/resolv.conf")
          machine.wait_until_succeeds(
              "grep -q 'connected: yes' /run/vpn-zones/system/pl/status", timeout=30
          )

          # No daemon restart: its already-bound resolv.conf was updated in
          # place by the successful retry.
          assert netns_of("nix-daemon") == zone_netns()
          machine.wait_until_succeeds(
              in_daemon("getent ahostsv4 daemon.internal | grep -q 198.51.100.1"),
              timeout=30,
          )
          sha = machine.succeed("printf 'plain-readiness\\n' | sha256sum | cut -d' ' -f1").strip()
          expr = (
              'import <nix/fetchurl.nix> { url = "http://daemon.internal:8091/f"; '
              f'sha256 = "{sha}"; }}'
          )
          out = machine.succeed(as_user("alice", f"nix-build --no-out-link -E {shlex.quote(expr)}")).strip()
          assert machine.succeed(f"cat {out}") == "plain-readiness\n", out
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
