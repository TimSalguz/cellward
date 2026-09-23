# NixOS VM test of the strict host policy (docs/SYSTEM.md §9b): the host keeps
# its local network, root included, and its own services that need more go
# through a zone — the Nix daemon and the clock through a plain one.
#
# Two VMs on the test's private VLAN, no internet and nothing from the host:
#   - `server`, with a LAN address and a second one outside every private
#     range (198.51.100.1, TEST-NET-2) that stands for the internet: a TCP
#     responder on both, an HTTP file and an NTP server on the second;
#   - `machine`, with the NixOS module, `egress.mode = "strict"`, a plain zone
#     `pl`, and `host.nix` and `host.time` in it.
#
# Run:
#   nix-build tests/vm-host.nix -A driver && ./result/bin/nixos-test-driver
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
    name = "vpn-zones-vm-host";

    nodes.machine =
      { lib, pkgs, ... }:
      {
        imports = [ ../module/nixos.nix ];

        services.vpn-zones.system = {
          enable = true;
          zones.pl = {
            kind = "plain";
            users = [ "alice" ];
          };
          host = {
            nix = "pl";
            time = "pl";
          };
          egress = {
            enable = true;
            mode = "strict";
          };
        };

        users.users.alice.isNormalUser = true;

        # The way to the "internet", there from boot as on a real machine:
        # what starts early has to cope with the zone's way out coming later,
        # not with a route the test adds afterwards.
        networking.interfaces.eth1.ipv4.routes = [
          {
            address = "198.51.100.0";
            prefixLength = 24;
          }
        ];

        # The clock from the "internet" address, and nothing else to ask.
        services.timesyncd = {
          enable = lib.mkForce true;
          servers = [ "198.51.100.1" ];
          fallbackServers = [ ];
        };
        # No binary cache to wait for: the one download here is the test's.
        nix.settings.substituters = lib.mkForce [ ];

        environment.systemPackages = [
          pkgs.socat
          pkgs.nftables
        ];

        virtualisation.cores = 2;
        virtualisation.memorySize = 1024;
      };

    nodes.server =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.socat
          pkgs.python3
        ];
        networking.firewall.allowedTCPPorts = [
          8090
          8091
        ];
        networking.firewall.allowedUDPPorts = [ 123 ];
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "198.51.100.1";
            prefixLength = 24;
          }
        ];
        # An NTP server with no time source of its own: its clock is the
        # reference.
        services.chrony = {
          enable = true;
          servers = [ ];
          extraConfig = ''
            allow all
            local stratum 10
          '';
        };
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

      # A new configuration's first boot is where the order of early units
      # shows: systemd breaks a cycle by dropping a job and says so, once.
      # `grep -c` reads everything: no SIGPIPE for pipefail to see.
      def no_ordering_cycles():
          out = machine.succeed("journalctl -b | grep -c 'ordering cycle' || true").strip()
          assert out == "0", machine.succeed("journalctl -b | grep -B2 -A5 'ordering cycle'")

      def reboot():
          machine.shutdown()
          machine.start()
          machine.wait_for_unit("multi-user.target")
          no_ordering_cycles()

      def host_services_in_zone():
          machine.wait_for_unit("vpn-zone-system@pl.service")
          machine.wait_for_unit("systemd-timesyncd.service")
          assert netns_of("systemd-timesyncd") == zone_netns(), netns_of("systemd-timesyncd")
          machine.succeed(as_user("alice", "nix-store -q --hash /run/current-system"))
          assert netns_of("nix-daemon") == zone_netns(), netns_of("nix-daemon")
          # Started before the zone's way out, and synced once it came up:
          # the way out restarts it.
          machine.wait_until_succeeds(
              "journalctl -b -u systemd-timesyncd | grep -q 'Contacted time server 198.51.100.1'",
              timeout=60,
          )

      start_all()
      server.wait_for_unit("multi-user.target")
      machine.wait_for_unit("multi-user.target")

      with subtest("server: a LAN address, and one that stands for the internet"):
          server_ip = server.succeed(
              "ip -4 -o addr show eth1 | grep -v 198.51.100 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()
          machine.succeed("ip route show 198.51.100.0/24 | grep -q eth1")
          server.succeed(
              "systemd-run --unit=echo socat TCP-LISTEN:8090,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed("mkdir -p /srv && printf 'hello-strict\\n' > /srv/f")
          server.succeed(
              "systemd-run --unit=web python3 -m http.server 8091 "
              "--bind 198.51.100.1 --directory /srv"
          )
          server.wait_for_open_port(8091, "198.51.100.1")
          server.wait_for_unit("chronyd.service")

      with subtest("the first boot: the early units in order, no cycle"):
          no_ordering_cycles()
          machine.wait_for_unit("vpn-zone-system-ns@pl.service")

      with subtest("strict: root keeps the local network and nothing beyond"):
          machine.wait_for_unit("vpn-zones-egress.service")
          rules = machine.succeed("nft list table inet vpnzones_egress")
          assert "meta skuid < 1000 accept" not in rules, rules
          assert "ip daddr @local4 accept" in rules, rules
          out = machine.succeed(f"socat -T10 - TCP:{server_ip}:8090")
          assert "peer=" in out, out
          machine.fail("timeout 10 socat -T5 - TCP:198.51.100.1:8090")
          machine.wait_until_succeeds(
              "journalctl -k | grep -q 'vpn-zones-egress: .*DST=198.51.100.1.*UID=0'", timeout=30
          )
          # A user outside the zones: not even the local network, as under
          # `enforce`.
          machine.fail(as_user("alice", f"timeout 10 socat -T5 - TCP:{server_ip}:8090"))

      with subtest("the plain zone is the way out directly"):
          machine.wait_for_unit("vpn-zone-system@pl.service")
          out = machine.succeed(
              as_user("alice", "vpn-zone-sys pl -- socat -T10 - TCP:198.51.100.1:8090")
          )
          assert "peer=" in out, out

      with subtest("the Nix daemon downloads through its zone"):
          # alice's own program may not go out; her build's download is the
          # daemon's, in the daemon's network.
          machine.succeed(as_user("alice", "nix-store -q --hash /run/current-system"))
          assert netns_of("nix-daemon") == zone_netns(), netns_of("nix-daemon")
          sha = machine.succeed("printf 'hello-strict\\n' | sha256sum | cut -d' ' -f1").strip()
          expr = (
              'import <nix/fetchurl.nix> { url = "http://198.51.100.1:8091/f"; '
              f'sha256 = "{sha}"; }}'
          )
          out = machine.succeed(as_user("alice", f"nix-build --no-out-link -E {shlex.quote(expr)}")).strip()
          assert machine.succeed(f"cat {out}") == "hello-strict\n", out
          # Root's own Nix, without the daemon, is the host's: refused.
          machine.fail("timeout 60 nix-prefetch-url http://198.51.100.1:8091/f")

      with subtest("the clock through its zone"):
          machine.wait_for_unit("systemd-timesyncd.service")
          assert netns_of("systemd-timesyncd") == zone_netns(), netns_of("systemd-timesyncd")
          machine.wait_until_succeeds(
              "journalctl -b -u systemd-timesyncd | grep -q 'Contacted time server 198.51.100.1'",
              timeout=60,
          )

      with subtest("off: the host's own services back on the host's network"):
          host_ns = machine.succeed("readlink /proc/1/ns/net").strip()
          machine.succeed("systemctl start vpn-zones-off.service")
          assert netns_of("systemd-timesyncd") == host_ns
          machine.succeed("systemctl start vpn-zones-on.service")
          machine.wait_for_unit("vpn-zone-system@pl.service")
          assert netns_of("systemd-timesyncd") == zone_netns()
          machine.fail("timeout 10 socat -T5 - TCP:198.51.100.1:8090")

      with subtest("a reboot: all of it comes up again by itself"):
          reboot()
          machine.wait_for_unit("vpn-zones-egress.service")
          host_services_in_zone()
          machine.fail("timeout 10 socat -T5 - TCP:198.51.100.1:8090")
          out = machine.succeed(
              as_user("alice", "vpn-zone-sys pl -- socat -T10 - TCP:198.51.100.1:8090")
          )
          assert "peer=" in out, out

      with subtest("off survives a reboot, and on comes back after one"):
          machine.succeed("systemctl start vpn-zones-off.service")
          reboot()
          machine.succeed("test -e /var/lib/vpn-zones/off")
          machine.fail("nft list table inet vpnzones_egress")
          machine.fail("systemctl is-active vpn-zone-system-ns@pl.service")
          host_ns = machine.succeed("readlink /proc/1/ns/net").strip()
          machine.wait_for_unit("systemd-timesyncd.service")
          assert netns_of("systemd-timesyncd") == host_ns
          machine.succeed(as_user("alice", "nix-store -q --hash /run/current-system"))
          assert netns_of("nix-daemon") == host_ns
          out = machine.succeed("socat -T10 - TCP:198.51.100.1:8090")
          assert "peer=" in out, out
          machine.succeed("systemctl start vpn-zones-on.service")
          host_services_in_zone()
          machine.fail("timeout 10 socat -T5 - TCP:198.51.100.1:8090")
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
