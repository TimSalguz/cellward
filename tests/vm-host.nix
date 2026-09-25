# NixOS VM test of the strict host policy (docs/SYSTEM.md §9b): the host keeps
# its local network, root included, and its own services that need more go
# through a zone — the Nix daemon and the clock through a plain one.
#
# Two VMs on the test's private VLAN, no internet and nothing from the host:
#   - `server`, with a LAN address and a second one outside every private
#     range (198.51.100.1, TEST-NET-2) that stands for the internet: a TCP
#     responder on both, an HTTP file and an NTP server on the second;
#   - `machine`, with the NixOS module, `egress.mode = "strict"`, a plain zone
#     `pl`, and `host.nix`, `host.time` and `host.dns` in it;
#   - `nmhost`, a desktop's network: NetworkManager takes its address and its
#     resolver from the "router"'s DHCP, and `host.dns` is a plain zone that
#     has to ask the router — with nothing of it reaching resolved.
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
            # The "internet" resolver: public resolvers are out of reach here.
            dns = [ "198.51.100.1" ];
          };
          host = {
            nix = "pl";
            time = "pl";
            dns = "pl";
          };
          egress = {
            enable = true;
            mode = "strict";
          };
        };

        users.users.alice.isNormalUser = true;

        # The host's resolver, which host.dns points at the zone: resolved in
        # front and nscd, as NixOS runs them.
        services.resolved.enable = true;

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
          pkgs.dnsutils
        ];

        virtualisation.cores = 2;
        virtualisation.memorySize = 1024;
      };

    nodes.nmhost =
      { lib, pkgs, ... }:
      {
        imports = [ ../module/nixos.nix ];
        services.vpn-zones.system = {
          enable = true;
          zones.direct0.kind = "plain";
          host.dns = "direct0";
        };
        services.resolved.enable = true;
        networking.networkmanager = {
          enable = true;
          # QEMU's own user network: not the LAN under test.
          unmanaged = [ "eth0" ];
        };
        # The address comes from DHCP, as on a desktop, not from the test: none
        # of the test's addresses (an IPv6 one too — with any address on it
        # NetworkManager takes eth1 as configured by somebody else and never
        # asks DHCP).
        networking.interfaces = lib.mkForce { };
        networking.useDHCP = false;
        environment.systemPackages = [ pkgs.dnsutils ];
        virtualisation.memorySize = 768;
      };

    nodes.server =
      {
        config,
        lib,
        pkgs,
        ...
      }:
      {
        environment.systemPackages = [
          pkgs.socat
          pkgs.python3
          pkgs.dnsmasq
        ];
        networking.firewall.allowedTCPPorts = [
          8090
          8091
          53
        ];
        networking.firewall.allowedUDPPorts = [
          123
          53
          67
        ];
        # The router: a resolver on the LAN address that answers the test's
        # names its own way, and DHCP that names it as the resolver — what
        # NetworkManager on `nmhost` learns. Up from boot: NetworkManager asks
        # for its lease while booting.
        systemd.services.router = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          serviceConfig.RuntimeDirectory = "router";
          serviceConfig.ExecStart = lib.concatStringsSep " " [
            "${pkgs.dnsmasq}/bin/dnsmasq -k --port=53 --bind-interfaces"
            "--dhcp-leasefile=/run/router/leases"
            "--listen-address=${config.networking.primaryIPAddress}"
            "--no-resolv --address=/internal/10.66.0.1"
            "--dhcp-range=192.168.1.100,192.168.1.150,1h"
            "--dhcp-option=6,${config.networking.primaryIPAddress}"
            # No default route: nmhost needs the LAN only.
            "--dhcp-option=3"
          ];
        };
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
      import time

      def as_user(user, cmd):
          return f"su -l {user} -c {shlex.quote(cmd)}"

      def netns_of(unit):
          pid = machine.succeed(f"systemctl show -p MainPID --value {unit}").strip()
          assert pid != "0", f"{unit} is not running"
          return machine.succeed(f"readlink /proc/{pid}/ns/net").strip()

      def zone_netns():
          return "net:[" + machine.succeed("stat -L -c %i /run/netns/vz-pl").strip() + "]"

      # Every check asks a name of its own: resolved and nscd cache answers.
      def host_resolves(name):
          machine.wait_until_succeeds(
              f"getent ahostsv4 {name} | grep -q 10.77.0.1", timeout=60
          )
          out = machine.succeed(f"getent ahostsv4 {name}")
          assert "10.66." not in out, out

      # A new configuration's first boot is where the order of early units
      # shows: systemd breaks a cycle by dropping a job and says so, once.
      # `grep -c` reads everything: no SIGPIPE for pipefail to see.
      def no_ordering_cycles(m=None):
          m = m or machine
          out = m.succeed("journalctl -b | grep -c 'ordering cycle' || true").strip()
          assert out == "0", m.succeed("journalctl -b | grep -B2 -A5 'ordering cycle'")

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
          host_resolves("boot" + str(time.time_ns()) + ".internal")
          assert netns_of("vpn-zones-dns") == zone_netns(), netns_of("vpn-zones-dns")
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
          # Two resolvers that answer the same names differently: the
          # "internet" one, which the zone asks, and the "router" on the LAN,
          # which the host must not.
          server.succeed(
              "systemd-run --unit=dns-internet dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=198.51.100.1 --no-resolv --address=/internal/10.77.0.1"
          )
          server.wait_for_unit("router.service")
          server.wait_for_open_port(53, "198.51.100.1")
          server.wait_for_unit("chronyd.service")

      with subtest("NetworkManager: the router's resolvers reach the plain zone, not resolved"):
          nmhost.wait_for_unit("NetworkManager.service")
          no_ordering_cycles(nmhost)
          # NetworkManager's own copy: the router, from DHCP.
          nmhost.wait_until_succeeds(
              f"grep -q 'nameserver {server_ip}' /run/NetworkManager/resolv.conf", timeout=120
          )
          # …and nothing of it in resolved: the forwarder alone.
          out = nmhost.succeed("resolvectl dns")
          assert "127.0.0.60" in out and server_ip not in out, out
          assert all(l.rstrip().endswith(":") for l in out.splitlines() if l.startswith("Link")), out
          # The plain zone is "directly", and directly the router answers.
          nmhost.wait_until_succeeds(
              f"grep -q 'nameserver {server_ip}' /etc/netns/vz-direct0/resolv.conf", timeout=30
          )
          nmhost.wait_until_succeeds("getent ahostsv4 nm.internal | grep -q 10.66.0.1", timeout=60)
          out = nmhost.succeed("dig +short +tries=3 +time=5 @127.0.0.60 nmdig.internal").strip()
          assert out == "10.66.0.1", out

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

      with subtest("the host's names through its zone"):
          machine.succeed("grep -q 'nameserver 198.51.100.1' /etc/netns/vz-pl/resolv.conf")
          host_resolves("leaktest.internal")
          assert netns_of("vpn-zones-dns") == zone_netns(), netns_of("vpn-zones-dns")
          out = machine.succeed("dig +short +tries=3 +time=5 @127.0.0.60 udp.internal").strip()
          assert out == "10.77.0.1", out
          out = machine.succeed("dig +tcp +short @127.0.0.60 tcp.internal").strip()
          assert out == "10.77.0.1", out
          # resolved asks the forwarder and nothing else: no link has a
          # resolver of its own (dhcpcd's DHCP on eth0 would give one).
          out = machine.succeed("resolvectl dns")
          assert "127.0.0.60" in out and server_ip not in out, out
          assert all(l.rstrip().endswith(":") for l in out.splitlines() if l.startswith("Link")), out
          # A user outside the zones still gets an answer — through the zone,
          # not the host's network — and still no connection.
          machine.succeed(as_user("alice", "getent ahostsv4 user.internal"))

      with subtest("off: the host's own services back on the host's network"):
          host_ns = machine.succeed("readlink /proc/1/ns/net").strip()
          machine.succeed("systemctl start vpn-zones-off.service")
          assert netns_of("systemd-timesyncd") == host_ns
          # Off: the forwarder asks the zone's resolvers from the host's
          # network — names still work with vpn-zones off.
          host_resolves("off.internal")
          assert netns_of("vpn-zones-dns") == host_ns
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
          host_resolves("offboot.internal")
          assert netns_of("vpn-zones-dns") == host_ns
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
