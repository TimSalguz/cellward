# NixOS VM test of `cellward scheme` (rust/src/scheme.rs): the network as
# places and flows, read on a machine with real zones and real traffic.
#
# Two VMs on the test's private VLAN, no internet:
#   - `server`, a WireGuard peer of two zones, with a TCP responder and a DNS
#     server on its tunnel address;
#   - `machine`, alice's user tier, two zones to that server: `nl`, its
#     server by a name (the address kept in the zone's directory) and its
#     resolver on the VPN's side; `pub`, its resolver a public address.
#
# A program of the main home connects, asks a name and pings in `nl`; curl
# is denied the network and tries; `pub` asks a name. The scheme says each:
# through the tunnel to the server, names answered on the VPN's side or in
# clear past the server, curl stopped at the gate. Its text and JSON are
# kept as the test's output (`scheme.txt`, `scheme.json`) — what the
# window's drawing is tried on.
#
#   nix-build tests/vm-scheme.nix -A driver -o vm-scheme-driver
#   ./vm-scheme-driver/bin/nixos-test-driver
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
    name = "cellward-vm-scheme";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [
          "${pins.home-manager}/nixos"
          ../module/nixos.nix
        ];
        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          linger = true;
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
        };
        programs.cellward.enable = true;
        # No screen to ask on: a program has the network without a question,
        # but for the one denied it.
        home-manager.users.alice.programs.cellward.defaults.permissions.network = "yes";
        home-manager.useGlobalPkgs = true;
        home-manager.useUserPackages = true;
        home-manager.users.alice.home.stateVersion = "26.05";
        environment.systemPackages = [
          pkgs.wireguard-tools
          pkgs.socat
          pkgs.curl
        ];
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
        networking.firewall.trustedInterfaces = [ "wg0" ];
        virtualisation.memorySize = 768;
      };

    testScript = ''
      import json
      import shlex

      STATE = "/home/alice/.local/state/vpn-zones"

      def alice(cmd):
          return machine.succeed(
              "su -l alice -c " + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )

      start_all()
      machine.wait_for_unit("multi-user.target")
      server.wait_for_unit("multi-user.target")
      machine.wait_for_unit("user@1000.service")

      with subtest("two zones to one server: nl by name, pub with a public resolver"):
          server.succeed("wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub")
          spub = server.succeed("cat /root/wg.pub").strip()
          server_ip = server.succeed(
              "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()
          keys = {}
          for zone in ("nl", "pub", "lan"):
              priv = machine.succeed("wg genkey").strip()
              keys[zone] = (priv, machine.succeed(f"printf %s '{priv}' | wg pubkey").strip())
          server.succeed(
              "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 && "
              "wg set wg0 listen-port 51820 private-key /root/wg.key "
              f"peer '{keys['nl'][1]}' allowed-ips 10.99.0.2/32 "
              f"peer '{keys['pub'][1]}' allowed-ips 10.99.0.3/32 "
              f"peer '{keys['lan'][1]}' allowed-ips 10.99.0.4/32 && ip link set wg0 up"
          )
          server.succeed(
              "systemd-run --unit=hello socat TCP-LISTEN:8080,bind=10.99.0.1,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed(
              "systemd-run --unit=dns dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=10.99.0.1 --no-resolv --address=/leaktest.internal/10.99.0.9"
          )
          for zone, addr, dns, endpoint in (
              ("nl", "10.99.0.2", "10.99.0.1", "vmvpn.test:51820"),
              ("pub", "10.99.0.3", "1.1.1.1", f"{server_ip}:51820"),
              # Its resolver at an address of the machine's own LAN — the
              # server's there, as a router's would be.
              ("lan", "10.99.0.4", server_ip, f"{server_ip}:51820"),
          ):
              alice(
                  f"printf '[Interface]\\nPrivateKey = {keys[zone][0]}\\nAddress = {addr}/32\\n"
                  f"DNS = {dns}\\n\\n[Peer]\\nPublicKey = {spub}\\n"
                  f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {endpoint}\\n' > /tmp/{zone}.conf"
              )
              alice(f"cellward add {zone} /tmp/{zone}.conf")
          # nl's server by a name no resolver here knows: its address kept.
          alice(f"printf 'vmvpn.test\\t{server_ip}\\n' > {STATE}/nl/endpoints")
          alice("cellward up nl && cellward up pub && cellward up lan")

      with subtest("traffic: a connection, a name, a ping; curl denied"):
          # An instance lives while a program of it does: one held in each
          # zone, as a browser left open is, keeps its table of flows.
          for zone in ("nl", "pub", "lan"):
              alice(f"systemd-run --user --unit=hold-{zone} cellward run {zone} -- sleep 3600")
              machine.wait_until_succeeds(
                  "su -l alice -c " + shlex.quote(
                      "export XDG_RUNTIME_DIR=/run/user/1000; "
                      f"cellward status --json | grep -q '\"network\":\"{zone}\"'"
                  ),
                  timeout=60,
              )
          out = alice("cellward run nl -- socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, out
          out = alice("cellward run nl -- getent ahostsv4 leaktest.internal")
          assert "10.99.0.9" in out, out
          # As from the desktop — through the user's manager, into its
          # launch's own cgroup —: ping's process, file capabilities and all,
          # is its launch's by its cgroup even where its descriptors are
          # closed to the user.
          alice(
              'systemd-run --user --pipe --wait --quiet --collect -E PATH="$PATH" -- '
              "cellward run nl -- ping -c1 -W5 10.99.0.1"
          )
          alice("cellward container net main deny curl")
          alice("! cellward run nl -- curl -sS -m 10 --connect-timeout 5 http://10.99.0.1:8080/")
          # A name of pub's: asked of 1.1.1.1 past the server, unanswered here.
          alice("cellward run pub -- getent ahostsv4 example.org || true")
          alice("cellward run lan -- getent ahostsv4 example.org || true")

      with subtest("the scheme says each flow where it ends"):
          text = alice("cellward scheme")
          print(text)
          raw = alice("cellward scheme --json")
          s = json.loads(raw)
          machine.succeed(f"cat > /tmp/scheme.json <<'EOF'\n{raw}\nEOF")
          machine.succeed(f"cat > /tmp/scheme.txt <<'EOF'\n{text}\nEOF")
          machine.copy_from_vm("/tmp/scheme.json")
          machine.copy_from_vm("/tmp/scheme.txt")
          places = {p["id"]: p for p in s["places"]}
          rows = s["rows"]
          def of(kind, net):
              """The rows of `kind` that go through zone `net`'s tunnel."""
              return [
                  r for r in rows
                  if r["kind"] == kind and any(h["to"] == f"tun:{net}" for h in r["hops"])
              ]
          # A connection: through nl's tunnel to its server, encrypted on the way.
          data = of("data", "nl")
          assert data and all(r["end"]["kind"] == "arrives" for r in data), data
          assert any(h["to"] == "vpn:nl" and h["sees"] == "nobody" for h in data[0]["hops"]), data
          # curl: at the gate.
          denied = [r for r in rows if r["kind"] == "denied" and r["name"].startswith("curl")]
          assert denied and denied[0]["end"]["kind"] == "denied", rows
          assert denied[0]["hops"][-1]["to"].startswith("relay:"), denied
          # nl's names, answered on the VPN's side; pub's, a stranger's past the server.
          nl_dns = of("dns", "nl")
          assert nl_dns and nl_dns[0]["end"]["kind"] == "answered", nl_dns
          pub_dns = of("dns", "pub")
          assert pub_dns and pub_dns[0]["hops"][-1]["to"] == "dns:1.1.1.1", pub_dns
          assert pub_dns[0]["hops"][-1]["sees"] == "stranger", pub_dns
          # Each zone's tunnel, and nl's server's name through the host.
          assert {r["id"] for r in rows if r["kind"] == "handshake"} == {"nl:handshake", "pub:handshake", "lan:handshake"}, rows
          assert any(r["kind"] == "server-name" and "vmvpn.test" in r["name"] for r in rows), rows
          # Every flow of a container's has its program: the ping too (its
          # socket, ping or raw); the kernel's own talk with passt is the
          # kernel's.
          unknown = [r for r in rows if r["name"] == "неизвестная программа"]
          assert not unknown, unknown
          assert any(r["kind"] == "ping" and r["name"] == "ping" for r in rows), rows
          assert all(r["name"] == "ядро контейнера" for r in rows if r["kind"] == "local"), rows
          # The zones' own routes, read in their app namespaces: through the
          # tunnel, every one — no leak anywhere.
          assert not [r for r in rows if r["end"]["kind"] == "leak"], rows
          # lan's resolver at the LAN's address: asked on the VPN's side,
          # and said so — not the person's router.
          lan_dns = of("dns", "lan")
          assert lan_dns and "не твой роутер" in lan_dns[0]["end"]["text"], lan_dns
          # The provider's network: a place, not known.
          assert any(p["unknown"] for p in places.values()), places
          assert "⚠→" in text, text
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
