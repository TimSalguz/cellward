# A resolver learnt after the Nix daemon is already running must serve its
# downloads too. The old resolver is stopped, so a cached resolver cannot pass.
#
# Run:
#   nix-build tests/vm-daemon-dns.nix -A driver && ./result/bin/nixos-test-driver
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
    name = "cellward-vm-daemon-dns";

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
        services.resolved.enable = true;

        systemd.tmpfiles.rules = [
          "d /run/NetworkManager 0755 root root -"
          "f /run/NetworkManager/resolv.conf 0644 root root - nameserver 192.168.1.1"
        ];

        services.cellward.system = {
          enable = true;
          switchGroup = null;
          zones.pl = {
            kind = "plain";
            autoStart = true;
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
        environment.systemPackages = [ pkgs.dnsutils ];

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

      def daemon_pid():
          pid = machine.succeed("systemctl show -p MainPID --value nix-daemon").strip()
          assert pid != "0", "nix-daemon is not running"
          return pid

      def in_daemon(cmd):
          return f"nsenter -t {daemon_pid()} -n -m -- {cmd}"

      def download(name):
          sha = machine.succeed(f"printf '{name}\\n' | sha256sum | cut -d' ' -f1").strip()
          expr = (
              f'import <nix/fetchurl.nix> {{ url = "http://{name}.internal:8091/{name}"; '
              f'sha256 = "{sha}"; }}'
          )
          out = machine.succeed(as_user("alice", f"nix-build --no-out-link -E {shlex.quote(expr)}")).strip()
          assert machine.succeed(f"cat {out}") == name + "\n", out

      start_all()
      machine.wait_for_unit("multi-user.target")
      server.wait_for_unit("multi-user.target")

      with subtest("the initial resolver serves a real daemon download"):
          server.succeed("mkdir -p /srv && printf 'before\\n' > /srv/before && printf 'after\\n' > /srv/after")
          server.succeed(
              "systemd-run --unit=web python3 -m http.server 8091 "
              "--bind 198.51.100.1 --directory /srv"
          )
          server.succeed(
              "systemd-run --unit=dns-before dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=192.168.1.1 --no-resolv "
              "--address=/internal/198.51.100.1"
          )
          server.wait_for_open_port(8091, "198.51.100.1")
          server.wait_for_open_port(53, "192.168.1.1")
          machine.wait_for_unit("vpn-zone-system@pl.service", timeout=60)
          machine.succeed(as_user("alice", "nix-store -q --hash /run/current-system"))
          machine.wait_for_unit("nix-daemon.service")
          machine.wait_until_succeeds(
              "grep -q '^nameserver 192.168.1.1$' /etc/netns/vz-pl/resolv.conf",
              timeout=30,
          )
          initial_pid = daemon_pid()
          machine.succeed(
              "test \"$(readlink -f /etc/resolv.conf)\" = /run/systemd/resolve/stub-resolv.conf"
          )
          machine.succeed(in_daemon("grep -q '^nameserver 192.168.1.1$' /etc/resolv.conf"))
          download("before")

      with subtest("a resolver replaced after readiness serves the same daemon"):
          server.succeed(
              "systemd-run --unit=dns-after dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=198.51.100.1 --no-resolv "
              "--address=/internal/198.51.100.1"
          )
          server.wait_for_open_port(53, "198.51.100.1")
          server.succeed("systemctl stop dns-before.service")
          machine.succeed(
              "printf 'nameserver 198.51.100.1\\n' > /run/NetworkManager/resolv.conf.new && "
              "mv /run/NetworkManager/resolv.conf.new /run/NetworkManager/resolv.conf"
          )
          machine.wait_until_succeeds(
              "journalctl -u vpn-zone-system@pl.service | "
              "grep -q 'resolvers now the router' && "
              "grep -q '^nameserver 198.51.100.1$' /etc/netns/vz-pl/resolv.conf",
              timeout=30,
          )
          # resolved replaces its stub by rename. systemd followed the
          # /etc/resolv.conf symlink when it made the daemon's bind mount, so
          # this is the event that used to detach that mount in the daemon's
          # mount namespace and expose the host's 127.0.0.53 stub instead.
          machine.succeed(
              "cp -L /etc/resolv.conf /run/systemd/resolve/stub-resolv.conf.new && "
              "mv /run/systemd/resolve/stub-resolv.conf.new /run/systemd/resolve/stub-resolv.conf"
          )
          assert daemon_pid() == initial_pid
          machine.succeed(in_daemon("test ! -L /etc/resolv.conf"))
          machine.succeed(in_daemon("grep -q '^nameserver 198.51.100.1$' /etc/resolv.conf"))
          download("after")
          assert daemon_pid() == initial_pid
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
