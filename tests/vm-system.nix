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
          # Who may add zones on the spot: alice, and nobody else — bob is in
          # the group through `other` and may not.
          users = [ "alice" ];
          zones.sz = {
            # Not at boot: the config only exists once the test has written it.
            autoStart = false;
            users = [ "alice" ];
          };
          # A plain zone: no tunnel, out through the host's network by pasta —
          # the TTY console's second step, and how a program goes out directly
          # once the host has no network of its own.
          zones.pl = {
            kind = "plain";
            autoStart = false;
            users = [ "alice" ];
          };
          # Only here to put bob into the group vpn-zones without letting him
          # into sz: the per-zone check has to refuse him on its own.
          zones.other = {
            autoStart = false;
            users = [ "bob" ];
          };
          services.probe.zone = "sz";
          containers.box.zone = "sz";
          # The TTY console: log in on tty1 and there is a network.
          console = {
            enable = true;
            zone = "sz";
            fallback = "pl";
          };
          # The host without a network for a user's program outside the
          # zones. Enforced from boot: nothing above runs as a user outside a
          # zone, so everything above has to keep working under it.
          egress = {
            enable = true;
            mode = "enforce";
          };
        };

        # The hard case for the policy's table: a firewall that flushes the
        # whole ruleset on every start and reload.
        networking.nftables = {
          enable = true;
          flushRuleset = true;
        };

        users.users = {
          alice = {
            isNormalUser = true;
            # For the emergency key: `wheel` may start and stop it.
            extraGroups = [ "wheel" ];
            # For logging in on tty1.
            initialPassword = "alice-console";
          };
          bob.isNormalUser = true;
          carol.isNormalUser = true;
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
      import shlex

      def as_user(user, cmd):
          return f"su -l {user} -c {shlex.quote(cmd)}"

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
          machine.succeed("systemctl start vpn-zone-system-ns@sz")
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
          machine.succeed("systemctl start vpn-zone-system@sz")
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
          # The class-wide insurance: no NSS module but the plain resolver.
          out = in_probe("grep ^hosts: /etc/nsswitch.conf").strip()
          assert out == "hosts: files dns", out

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

      with subtest("a user's program in the zone: as the user, without privileges"):
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- socat -T10 - TCP:10.99.0.1:8080"))
          assert "peer=10.99.0.2" in out, out
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- getent ahostsv4 leaktest.internal"))
          assert "10.99.0.9" in out and "10.66.66.66" not in out, out
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- id -un")).strip()
          assert out == "alice", out
          out = machine.succeed(
              as_user("alice", "vpn-zone-sys sz -- grep -E '^(NoNewPrivs|CapEff)' /proc/self/status")
          )
          assert "NoNewPrivs:\t1" in out and "CapEff:\t0000000000000000" in out, out
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- ip -o link show"))
          assert len(links(out)) == 2 and ": awg0" in out, out
          machine.fail(as_user("alice", "vpn-zone-sys sz -- ip link add vzx type dummy"))
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- grep ^hosts: /etc/nsswitch.conf"))
          assert out.strip() == "hosts: files dns", out
          # The exit code is the command's. (`execute`, not a shell's `$?`: the
          # driver runs commands under errexit.)
          status, _ = machine.execute(as_user("alice", "vpn-zone-sys sz -- sh -c 'exit 7'"))
          assert status == 7, f"exit code {status}, not 7"
          # With a terminal: the command gets a pty of its own as its terminal.
          out = machine.succeed(
              as_user("alice", "script -qec 'vpn-zone-sys sz -- tty' /dev/null")
          )
          assert "/dev/pts/" in out, out
          # Every launch is a unit of its own, and the journal names who ran what
          # (the program quoted: a line break in it cannot forge a line).
          machine.succeed("journalctl -u 'vpn-zone-sysrun@*' | grep -q 'alice runs .socat.'")
          # A command longer than the request's 5 s is not hung up (review: the
          # timeout stayed on the connection and ended every command at 5 s).
          machine.succeed(as_user("alice", "vpn-zone-sys sz -- sleep 8"))
          # What the command does not see: this service's socket (asking for
          # another zone), the host's /tmp, the Nix daemon.
          machine.succeed("touch /tmp/host-probe && chmod 644 /tmp/host-probe")
          machine.fail(as_user("alice", "vpn-zone-sys sz -- test -e /tmp/host-probe"))
          machine.fail(as_user("alice", "vpn-zone-sys sz -- test -e /run/vpn-zones/sysrun.sock"))
          machine.fail(
              as_user("alice", "vpn-zone-sys sz -- test -e /nix/var/nix/daemon-socket/socket")
          )
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- id -G")).split()
          vz = machine.succeed("getent group vpn-zones | cut -d: -f3").strip()
          assert vz not in out, f"the vpn-zones group {vz} is among {out}"

      with subtest("the session is out of reach through /proc, not only where it lies"):
          # A host process of alice's with a socket in her runtime directory — what
          # a compositor's IPC or the session bus is. The command's own tmpfs hides
          # the directory; the process holding the socket must not be a way around
          # it: /proc/<pid>/root is that process's view of the file system
          # (docs/LEAK-MODEL.md §16).
          uid = machine.succeed("id -u alice").strip()
          machine.succeed("loginctl enable-linger alice")
          machine.wait_until_succeeds(f"test -d /run/user/{uid}")
          machine.succeed(
              f"systemd-run --unit=session-sock -p User=alice "
              f"socat UNIX-LISTEN:/run/user/{uid}/probe.sock,fork SYSTEM:'echo session'"
          )
          machine.wait_until_succeeds(f"test -S /run/user/{uid}/probe.sock")
          pid = machine.succeed("systemctl show -p MainPID --value session-sock").strip()
          # On the host alice reaches it that way — otherwise the rest proves nothing.
          out = machine.succeed(
              as_user("alice", f"socat -T5 - UNIX-CONNECT:/proc/{pid}/root/run/user/{uid}/probe.sock")
          )
          assert "session" in out, out
          machine.fail(as_user("alice", f"vpn-zone-sys sz -- test -e /run/user/{uid}/probe.sock"))
          machine.fail(
              as_user("alice", f"vpn-zone-sys sz -- socat -T5 - UNIX-CONNECT:/proc/{pid}/root/run/user/{uid}/probe.sock")
          )
          machine.fail(as_user("alice", f"vpn-zone-sys sz -- ls /proc/{pid}/root/"))
          machine.fail(as_user("alice", f"vpn-zone-sys sz -- cat /proc/{pid}/environ"))
          # Still alice, still without privileges, still her files.
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- sh -c 'id -un; touch ~/in-zone && stat -c %U ~/in-zone'"))
          assert out.split() == ["alice", "alice"], out
          machine.succeed("systemctl stop session-sock")

      with subtest("the zone's list of users is the only way in"):
          out = machine.fail(as_user("bob", "vpn-zone-sys sz -- true") + " 2>&1")
          assert "may not run programs in the system zone sz" in out, out
          out = machine.fail(as_user("carol", "vpn-zone-sys sz -- true") + " 2>&1")
          assert "cannot reach" in out, out

      with subtest("nothing but the tunnel's UDP left eth1 towards the server"):
          machine.succeed("systemctl stop leakwatch")
          out = machine.succeed("tcpdump -n -r /tmp/leak.pcap 2>/dev/null | wc -l").strip()
          assert out == "0", machine.succeed("tcpdump -n -r /tmp/leak.pcap")

      # After the leak watch on purpose: from here on root talks to the
      # server's LAN address directly, which is allowed and would be "a leak"
      # to that capture.
      def direct(user):
          return as_user(user, f"timeout 10 socat -T5 - TCP:{server_ip}:8090")

      with subtest("the host has no network for a user's program outside the zones"):
          machine.succeed(
              "nft list table inet vpnzones_egress | grep -q 'reject with icmpx admin-prohibited'"
          )
          out = machine.succeed(f"socat -T10 - TCP:{server_ip}:8090")
          assert "peer=" in out, f"root lost the network: {out}"
          machine.fail(direct("alice"))
          machine.wait_until_succeeds(
              "journalctl -k | grep -q 'vpn-zones-egress: .*UID=1000'", timeout=30
          )
          # Through her zone: as before.
          out = machine.succeed(as_user("alice", "vpn-zone-sys sz -- socat -T10 - TCP:10.99.0.1:8080"))
          assert "peer=10.99.0.2" in out, out
          # A service with a dynamic user is the system's and goes out.
          out = machine.succeed(
              "systemd-run --wait --pipe -p DynamicUser=yes "
              f"$(command -v socat) -T10 - TCP:{server_ip}:8090"
          )
          assert "peer=" in out, out

      with subtest("a firewall that flushes everything does not take the policy with it"):
          machine.succeed("systemctl reload nftables")
          machine.wait_until_succeeds("nft list table inet vpnzones_egress", timeout=30)
          machine.fail(direct("alice"))
          machine.succeed("systemctl restart nftables")
          machine.wait_until_succeeds("nft list table inet vpnzones_egress", timeout=30)
          machine.fail(direct("alice"))

      with subtest("our binary failing leaves the host more closed, never open"):
          # The allowances are ours and are there: the uplinks of user zones.
          machine.succeed("nft list set inet vpnzones_egress users | grep -q 100000")
          rules = machine.succeed(
              "systemctl show -p ExecStart vpn-zones-egress "
              "| grep -o '/nix/store/[^ ;]*-vpn-zones-egress.nft' | head -1"
          ).strip()
          assert rules, "the policy is not loaded from a built file"
          # As if vpn-zone-core had crashed: the restriction alone, loaded by nft.
          machine.succeed("systemctl stop vpn-zones-egress")
          machine.succeed(f"nft -f {rules}")
          machine.fail(direct("alice"))
          out = machine.succeed("nft list set inet vpnzones_egress users")
          assert "100000" not in out, out
          machine.succeed("systemctl start vpn-zones-egress")
          machine.succeed("nft list set inet vpnzones_egress users | grep -q 100000")

      with subtest("the emergency key: not without a password from outside the seat"):
          # alice is in wheel, but `su` is no local, active session: from
          # here — as from ssh, cron or a zone's command with the system bus —
          # the key wants her password, and there is nobody to type it. At the
          # seat itself it turns without one (the TTY console subtest below).
          machine.fail(as_user("alice", "systemctl start vpn-zones-egress-open"))
          machine.fail(direct("alice"))
          # carol is not in the group: no key for her at all.
          machine.fail(as_user("carol", "systemctl start vpn-zones-egress-open"))
          machine.fail(direct("carol"))

      with subtest("a plain zone: its own namespace, out through the host, nothing of the host's"):
          machine.succeed("systemctl start vpn-zone-system@pl")
          out = machine.succeed("ip -n vz-pl -o link show")
          assert len(links(out)) == 2 and ": awg0" in out, out
          machine.succeed("pgrep -u vpn-zones-plain -x pasta || pgrep -u vpn-zones-plain -f pasta")
          # Out through the host's network: the server sees the machine itself.
          out = machine.succeed(f"ip netns exec vz-pl socat -T10 - TCP:{server_ip}:8090")
          assert "peer=" in out and "peer=10.99." not in out, out
          # The host's loopback is not the zone's, and the gateway does not
          # lead there either.
          machine.succeed(
              "systemd-run --unit=hostlocal socat TCP-LISTEN:7777,bind=127.0.0.1,fork,reuseaddr "
              "'SYSTEM:echo local'"
          )
          # Compared, not piped into `grep -q`: the driver runs under pipefail,
          # and socat killed by SIGPIPE would fail the pipeline forever.
          machine.wait_until_succeeds(
              'test "$(socat -T2 - TCP:127.0.0.1:7777 </dev/null)" = local', timeout=30
          )
          gw = machine.succeed(
              "ip -n vz-pl -4 route show default | grep -o 'via [0-9.]*' | cut -d' ' -f2"
          ).strip()
          assert gw, "the plain zone has no default route"
          machine.succeed(f"ip netns exec vz-pl sh -c '! timeout 5 socat -T3 - TCP:{gw}:7777'")
          machine.succeed("ip netns exec vz-pl sh -c '! timeout 5 socat -T3 - TCP:127.0.0.1:7777'")
          # "Directly" asks the router's resolvers, as the host knows them —
          # here QEMU's, which resolved has for eth0 — and never the host's
          # own stub on loopback.
          out = machine.succeed("cat /etc/netns/vz-pl/resolv.conf")
          zone_ns = [l.split()[1] for l in out.splitlines() if l.startswith("nameserver ")]
          host_ns = machine.succeed("cat /run/systemd/resolve/resolv.conf")
          assert zone_ns and not any(n.startswith("127.") for n in zone_ns), out
          assert all(f"nameserver {n}" in host_ns for n in zone_ns), f"{out} vs {host_ns}"
          machine.wait_until_succeeds(
              "grep -q 'connected: yes' /run/vpn-zones/system/pl/status", timeout=30
          )
          # Under the enforced policy, this is how alice goes out directly.
          machine.fail(direct("alice"))
          out = machine.succeed(
              as_user("alice", f"vpn-zone-sys pl -- socat -T10 - TCP:{server_ip}:8090")
          )
          assert "peer=" in out and "peer=10.99." not in out, out
          machine.succeed("systemctl stop vpn-zone-system@pl")
          out = machine.succeed("ip -n vz-pl -o link show")
          assert len(links(out)) == 1, f"pasta's interface outlived the zone: {out}"

      with subtest("a VPN added once, on the spot: a system zone for everything, no second tunnel"):
          # A second device on the server, for alice's own VPN.
          k2 = machine.succeed("wg genkey").strip()
          p2 = machine.succeed(f"printf %s '{k2}' | wg pubkey").strip()
          server.succeed(f"wg set wg0 peer '{p2}' allowed-ips 10.99.0.3/32")
          machine.succeed(
              f"printf '[Interface]\\nPrivateKey = {k2}\\nAddress = 10.99.0.3/32\\n"
              f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
              f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' > /tmp/nl2.conf && "
              "chown alice /tmp/nl2.conf && chmod 600 /tmp/nl2.conf"
          )
          out = machine.succeed(as_user("alice", "vpn-zone-sys --add nl2 /tmp/nl2.conf"))
          assert "nl2" in out, out
          machine.succeed("test \"$(stat -c %a /var/lib/vpn-zones/system/nl2/config.conf)\" = 600")
          out = machine.succeed(as_user("alice", "vpn-zone-sys nl2 -- socat -T10 - TCP:10.99.0.1:8080"))
          assert "peer=10.99.0.3" in out, out
          # The same config again — sz's own: not a second tunnel, but which zone it is.
          machine.succeed(
              "cp /var/lib/vpn-zones/system/sz/config.conf /tmp/sz-copy.conf && "
              "chown alice /tmp/sz-copy.conf"
          )
          out = machine.succeed(as_user("alice", "vpn-zone-sys --add nl3 /tmp/sz-copy.conf"))
          assert "sz" in out, out
          machine.fail("test -e /var/lib/vpn-zones/system/nl3")
          machine.fail("ip netns list | grep -q vz-nl3")
          # Somebody else's zone: neither used nor replaced.
          out = machine.fail(as_user("bob", "vpn-zone-sys nl2 -- true") + " 2>&1")
          assert "may not" in out, out
          out = machine.fail(as_user("bob", "vpn-zone-sys --add nl2 /dev/null") + " 2>&1")
          assert "may not add system zones" in out, out
          # alice may add zones, but not take one declared for somebody else…
          out = machine.fail(as_user("alice", "vpn-zone-sys --add other /tmp/nl2.conf") + " 2>&1")
          assert "not alice's" in out, out
          # …nor replace the tunnel of one the host's own services go through.
          out = machine.fail(as_user("alice", "vpn-zone-sys --add sz /tmp/nl2.conf") + " 2>&1")
          assert "carries the host's own services" in out, out
          # A plain zone added on the spot.
          machine.succeed(as_user("alice", "vpn-zone-sys --add pl2 --plain"))
          out = machine.succeed(as_user("alice", f"vpn-zone-sys pl2 -- socat -T10 - TCP:{server_ip}:8090"))
          assert "peer=" in out and "peer=10.99." not in out, out
          machine.succeed("systemctl stop vpn-zone-system@pl2 vpn-zone-system@nl2")

      with subtest("the tunnel stops: lo alone, the consumers keep running and reach nothing"):
          machine.succeed("systemctl stop vpn-zone-system@sz")
          out = machine.succeed("ip -n vz-sz -o link show")
          assert len(links(out)) == 1, out
          machine.succeed("systemctl is-active probe")
          machine.succeed("systemctl is-active container@box")
          in_probe("sh -c '! timeout 5 socat -T3 - TCP:10.99.0.1:8080'")
          machine.fail("nixos-container run box -- timeout 5 socat -T3 - TCP:10.99.0.1:8080")
          machine.succeed("systemctl start vpn-zone-system@sz")
          out = in_probe("socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out

      # Inode numbers of namespaces are reused as soon as one is freed, so
      # "a different inode" proves nothing. A per-namespace sysctl marks the
      # old one instead: the new namespace has the default, and so must the
      # namespace the service ends up in.
      with subtest("the namespace restarts: its consumers restart into the new one"):
          machine.succeed("ip netns exec vz-sz sysctl -qw net.ipv4.ip_default_ttl=63")
          assert in_probe("cat /proc/sys/net/ipv4/ip_default_ttl").strip() == "63"
          machine.succeed("systemctl restart vpn-zone-system-ns@sz")
          machine.succeed("systemctl start vpn-zone-system@sz probe container@box")
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
      # The console's text on the virtual terminal is read through /dev/vcs,
      # where Cyrillic does not survive: the checks look at the ASCII in it.
      # What a shell IN a zone writes goes to the home: a command in a system
      # zone has a /tmp of its own, which the host does not see.
      def tty_run(cmd):
          machine.send_chars(cmd + "\n")

      with subtest("the TTY console: log in, and there is a network already"):
          machine.wait_until_tty_matches("1", "login: ")
          machine.send_chars("alice\n")
          machine.wait_until_tty_matches("1", "Password: ")
          machine.send_chars("alice-console\n")
          machine.wait_until_tty_matches("1", "tunnel alive")
          machine.wait_until_tty_matches("1", r"\[Enter\].*zone sz")
          machine.send_chars("\n")
          # A login shell in the zone: the console did not come up again in it.
          machine.wait_until_succeeds("pgrep -u alice -f 'system-run sz'", timeout=30)
          tty_run("socat -T10 - TCP:10.99.0.1:8080 > /home/alice/console-zone 2>&1; echo $VPN_ZONE_CURRENT >> /home/alice/console-zone")
          machine.wait_until_succeeds("grep -q sys:sz /home/alice/console-zone", timeout=30)
          out = machine.succeed("cat /home/alice/console-zone")
          assert "peer=10.99.0.2" in out, out
          tty_run("exit")
          # Back in the menu once the zone's shell is gone.
          machine.wait_until_fails("pgrep -u alice -f 'system-run sz'", timeout=30)
          # The plain console: the host, which has no network for alice.
          machine.send_chars("q")
          tty_run(f"socat -T5 - TCP:{server_ip}:8090 > /tmp/console-host 2>&1; echo host-exit=$? >> /tmp/console-host")
          machine.wait_until_succeeds("grep -q host-exit= /tmp/console-host", timeout=30)
          out = machine.succeed("cat /tmp/console-host")
          assert "peer=" not in out and "host-exit=0" not in out, out
          # The emergency key, turned at the seat: a local, active session —
          # no password — and the host is open, then closed again.
          tty_run("systemctl start vpn-zones-egress-open; echo key=$? > /tmp/console-key")
          machine.wait_until_succeeds("grep -q key= /tmp/console-key", timeout=30)
          out = machine.succeed("cat /tmp/console-key")
          assert "key=0" in out, out
          out = machine.succeed(as_user("alice", f"socat -T10 - TCP:{server_ip}:8090"))
          assert "peer=" in out, out
          tty_run("systemctl stop vpn-zones-egress-open; echo unkey=$? > /tmp/console-unkey")
          machine.wait_until_succeeds("grep -q unkey=0 /tmp/console-unkey", timeout=30)
          machine.fail(direct("alice"))
          tty_run("exit")

      with subtest("the TTY console: no tunnel, and the plain zone is one key away"):
          # The VPN server stops answering; the zone comes up again without a
          # handshake.
          server.succeed("ip link set wg0 down")
          machine.succeed("systemctl restart vpn-zone-system@sz")
          machine.wait_until_tty_matches("1", "login: ")
          machine.send_chars("alice\n")
          machine.wait_until_tty_matches("1", "Password: ")
          machine.send_chars("alice-console\n")
          machine.wait_until_tty_matches("1", "no tunnel", timeout=60)
          machine.wait_until_tty_matches("1", r"\[p\].*zone pl")
          machine.send_chars("p")
          machine.wait_until_succeeds("pgrep -u alice -f 'system-run pl'", timeout=60)
          tty_run(f"socat -T10 - TCP:{server_ip}:8090 > /home/alice/console-plain 2>&1; echo $VPN_ZONE_CURRENT >> /home/alice/console-plain")
          machine.wait_until_succeeds("grep -q sys:pl /home/alice/console-plain", timeout=30)
          out = machine.succeed("cat /home/alice/console-plain")
          assert "peer=" in out and "peer=10.99." not in out, out
          tty_run("exit")
          machine.wait_until_fails("pgrep -u alice -f 'system-run pl'", timeout=30)
          machine.send_chars("q")
          tty_run("exit")
          server.succeed("ip link set wg0 up")

      with subtest("vpn-zones off without a rebuild, and on again"):
          # Services are attached by the generator, in /run — not in their units.
          machine.succeed("systemctl cat probe | grep -q NetworkNamespacePath")
          host_ns = machine.succeed("readlink /proc/1/ns/net").strip()
          # alice is in wheel: at the seat the switch needs no password —
          # logged in on tty1, the console's host shell ("q").
          machine.wait_until_tty_matches("1", "login: ")
          machine.send_chars("alice\n")
          machine.wait_until_tty_matches("1", "Password: ")
          machine.send_chars("alice-console\n")
          machine.wait_until_tty_matches("1", r"\[Enter\].*zone sz")
          machine.send_chars("q")
          # Judged by what it does: switching off restarts the console too, and
          # the shell that asked is gone before it could say anything.
          tty_run("vpn-zones-off")
          machine.wait_until_succeeds("test -e /var/lib/vpn-zones/off", timeout=60)
          machine.fail("nft list table inet vpnzones_egress")
          machine.fail("systemctl is-active vpn-zone-system@sz")
          machine.succeed("systemctl is-active probe")
          pid = machine.succeed("systemctl show -p MainPID --value probe").strip()
          ns = machine.succeed(f"readlink /proc/{pid}/ns/net").strip()
          assert ns == host_ns, f"probe stayed in {ns}"
          out = machine.succeed(as_user("alice", f"socat -T10 - TCP:{server_ip}:8090"))
          assert "peer=" in out, out
          # Zones do not come up behind the switch's back.
          out = machine.fail(as_user("alice", "vpn-zone-sys sz -- true") + " 2>&1")
          assert "vpn-zones are off" in out, out
          machine.fail("systemctl is-active vpn-zone-system@sz")
          # Off survives a reload, which is what a reboot does to generators.
          machine.succeed("systemctl daemon-reload")
          machine.fail("systemctl cat probe | grep -q NetworkNamespacePath")
          # carol is not in wheel; alice from outside the seat would need her
          # password, which nobody types here. Root turns it on.
          machine.fail(as_user("carol", "vpn-zones-on"))
          machine.fail(as_user("alice", "vpn-zones-on"))
          machine.succeed("systemctl start vpn-zones-on.service")
          machine.fail("test -e /var/lib/vpn-zones/off")
          machine.succeed("nft list table inet vpnzones_egress")
          machine.wait_until_succeeds("systemctl is-active vpn-zone-system@sz", timeout=60)
          pid = machine.succeed("systemctl show -p MainPID --value probe").strip()
          ns = machine.succeed(f"readlink /proc/{pid}/ns/net").strip()
          assert ns == f"net:[{netns_inode()}]", f"probe is not back in its zone: {ns}"
          machine.fail(direct("alice"))
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
