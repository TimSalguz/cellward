# NixOS VM test: boots a real machine with the vpn-zones home-manager module
# and exercises exactly the paths the CI smoke test cannot reach — a runner
# has no systemd user session, so `vpn-zone up/down` (the vpn-zone@ template
# unit), the unit autostart inside `vpn-zone run`, and the picker's offline
# branch have no coverage there. Here they do, plus the same hermeticity
# asserts as the smoke test, checked through the systemd path this time.
#
# A second VM acts as a REAL WireGuard peer on the test's private VLAN, so
# the handshake, the traffic, the DNS= path and `vpn-zone check`'s "tunnel
# alive" branch are exercised for real — with a tcpdump on the client's
# physical interface asserting that nothing but the tunnel's own UDP ever
# leaves towards the server (a first cut of the ROADMAP leak tests). Keys
# are generated at runtime inside the VMs: no real VPN config is involved,
# and the test needs no internet and nothing from the host.
#
# Both VMs carry the out-of-tree amneziawg kernel module, so this is the ONLY
# place where the holder's ordinary branch — `ip link add awg0 type
# amneziawg`, configured by `awg` — is exercised at all, in both of its
# shapes: a plain WireGuard config carried by the awg module (wire-compatible
# with the stock `wireguard` peer on the server), and a genuinely obfuscated
# config (Jc/Jmin/Jmax, S1/S2, H1..H4) against a server interface that
# carries the same parameters. The holder's fallback to the in-tree
# `wireguard` module stays covered by the CI smoke test, whose runner has no
# amneziawg module — the two tests split the branch between them.
#
# The host stays untouched: everything happens inside a qemu VM whose state
# dirs are the VM's own; the only host side effect is /nix/store growth.
# Works without /dev/kvm too — qemu falls back to TCG emulation (an order of
# magnitude slower, but correct).
#
# Run:
#   nix-build tests/vm.nix -A driver && ./result/bin/nixos-test-driver
# Poke at the VM by hand (python REPL; `machine.shell_interact()`):
#   nix-build tests/vm.nix -A driverInteractive && ./result/bin/nixos-test-driver
#
# Unlike the smoke test, the second-echelon assert is STRICT here: the VM
# kernel loads nf_tables up front, so the "runner kernel has no nf_tables"
# degradation branch must not fire — rules are either present or it is a bug.
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

  # A CA and a server certificate made at build time, for the container that is
  # DECLARED to trust it (docs/CONTAINERS.md §8). Synthetic, and in the store of
  # this test only.
  declaredCa = pkgs.runCommand "vpn-zones-vm-declared-ca" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p "$out" && cd "$out"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=vpn-zones declared CA" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -keyout ca.key -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=declared.internal" -keyout srv.key -out srv.csr 2>/dev/null
    printf 'subjectAltName=DNS:declared.internal\n' > ext
    openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile ext -out srv.pem 2>/dev/null
  '';

  # A D-Bus-activatable program (docs/CONTAINERS.md §5.3): a launcher entry
  # with DBusActivatable=true and the session service file that starts it.
  # Started, it records the network it sees and exits — it never takes its
  # name, so the activation itself times out, which is fine.
  vmActivatableRun = pkgs.writeShellScript "vm-activatable" ''
    ${pkgs.iproute2}/bin/ip -o link show > /tmp/vmactivated
  '';
  vmActivatable = pkgs.runCommand "vpn-zones-vm-activatable" { } ''
    mkdir -p "$out/share/applications" "$out/share/dbus-1/services"
    printf '[Desktop Entry]\nType=Application\nName=VM activatable\nExec=%s\nDBusActivatable=true\n' \
      ${vmActivatableRun} > "$out/share/applications/org.vpnzones.VmActivatable.desktop"
    printf '[D-BUS Service]\nName=org.vpnzones.VmActivatable\nExec=%s\n' \
      ${vmActivatableRun} > "$out/share/dbus-1/services/org.vpnzones.VmActivatable.service"
  '';

  test = pkgs.testers.runNixOSTest {
    name = "vpn-zones-vm";

    nodes.machine =
      { config, pkgs, ... }:
      {
        imports = [ "${pins.home-manager}/nixos" ];

        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          # The zone holder maps its in-namespace root from this range via the
          # setuid newuidmap — the same prerequisite the README states for a
          # real machine.
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
          # A user manager without a login session: `vpn-zone up` talks to
          # `systemctl --user`, and nobody logs into a test VM.
          linger = true;
        };

        # zsh, like on a real desktop: without it /share/zsh is not linked into
        # the per-user profile and the completion assert below would test
        # nothing.
        programs.zsh.enable = true;

        home-manager.useGlobalPkgs = true;
        # Per-user profile at /etc/profiles/per-user/alice — the layout the
        # module sees on a real NixOS machine, and the path its tools manifest
        # bakes into `runner`/`picker` (home.profileDirectory).
        home-manager.useUserPackages = true;
        home-manager.users.alice = {
          imports = [ ../module ];
          programs.vpn-zones.enable = true;
          # A container declared in Nix: bound to direct, trusting a CA made
          # at build time. What the module writes, the runtime obeys and the
          # CLI refuses to change is asserted below.
          programs.vpn-zones.containers.vmdecl = {
            home = "overlay";
            network = "direct";
            apps = [ "vmdeclapp" ];
            trust = {
              certificates = [ "${declaredCa}/ca.pem" ];
              acknowledgeRisk = true;
            };
          };
          home.stateVersion = "26.05";
        };

        # systemd-resolved, exactly as a real desktop runs it — and this is
        # what makes the DNS leak test below possible at all. Enabling it puts
        # `resolve [!UNAVAIL=return]` into /etc/nsswitch.conf BEFORE `dns`,
        # turns /etc/resolv.conf into a symlink chain ending in
        # /run/systemd/resolve/stub-resolv.conf, and puts the varlink socket
        # nss-resolve talks to (io.systemd.Resolve) in that same directory. A
        # zone that leaves that socket in reach resolves every name through the
        # HOST's resolver, around the tunnel, however hermetic its namespace is
        # (`docs/GOTCHAS.md` §3).
        #
        # Its only DNS server is a dnsmasq on loopback that the test starts,
        # answering the one name with an address the tunnel's resolver never
        # returns — so a single lookup says which resolver answered it.
        services.resolved = {
          enable = true;
          settings.Resolve = {
            DNS = [ "127.0.0.1:5353" ];
            # No way out but that one server: an upstream fallback would make
            # "the host answered" ambiguous.
            FallbackDNS = [ ];
            # Route every lookup to it, search domains or not.
            Domains = [ "~." ];
          };
        };

        # The out-of-tree AmneziaWG module, built against this VM's kernel.
        # With it present the holder takes its ORDINARY branch for every zone
        # here: `ip link add awg0 type amneziawg`, configured by `awg`. The
        # fallback to the in-tree `wireguard` module (no amneziawg, plain
        # config) is not lost — it is what the CI smoke test runs on, since a
        # GitHub runner has no such module.
        boot.extraModulePackages = [ config.boot.kernelPackages.amneziawg ];

        boot.kernelModules = [
          # Modules cannot autoload from an unprivileged userns, so everything
          # a zone needs is loaded up front.
          "amneziawg"
          # Still loaded: the holder's fallback would need it, and the server
          # side of the plain tunnel is stock WireGuard.
          "wireguard"
          # pasta opens /dev/net/tun.
          "tun"
          # Second echelon; with the module loaded the nft asserts are strict.
          "nf_tables"
        ];

        environment.systemPackages = [
          # `wg genkey` for the synthetic config the test writes.
          pkgs.wireguard-tools
          # To READ rulesets from inside the zone's namespaces. The zone itself
          # gets its own nft path via the unit's ExecStart flags.
          pkgs.nftables
          # For the real-tunnel part: TCP client inside the zone, DNS client,
          # and the leak capture on the uplink interface.
          pkgs.socat
          pkgs.dnsutils
          pkgs.tcpdump
          # The host's own resolver for the DNS leak test — the one whose
          # answer must never appear inside a zone.
          pkgs.dnsmasq
          # Per-container trust (docs/CERTIFICATES.md): a CA made on the fly,
          # `certutil` to look into NSS databases, and p11-kit's `trust` to see
          # the anchors the way NSS sees them on NixOS.
          pkgs.openssl
          pkgs.nss.tools
          pkgs.p11-kit
          vmActivatable
        ];
        environment.pathsToLink = [ "/share/dbus-1" ];

        virtualisation.cores = 4;
        virtualisation.memorySize = 2048;
      };

    # A real WireGuard peer for the zone to talk to, on the test VLAN between
    # the two VMs (a virtual hub private to this test — the host is not
    # involved and neither VM has internet). Keys are generated at runtime
    # inside the VMs, so no VPN config ever exists outside the test.
    nodes.server =
      { config, pkgs, ... }:
      {
        # wg0 is stock WireGuard on purpose: it is the proof that an
        # AmneziaWG client without junk parameters stays compatible with an
        # ordinary WireGuard peer on the wire. awg1 is the obfuscated one.
        boot.extraModulePackages = [ config.boot.kernelPackages.amneziawg ];
        boot.kernelModules = [
          "wireguard"
          "amneziawg"
        ];
        environment.systemPackages = [
          pkgs.wireguard-tools
          # `awg` configures the obfuscated interface: the junk parameters
          # have no equivalent in `wg`.
          pkgs.amneziawg-tools
          # The service behind the tunnel: a TCP responder that reports the
          # peer address it saw, and a DNS server for the DNS= path.
          pkgs.socat
          pkgs.dnsmasq
        ];
        networking.firewall.allowedUDPPorts = [
          51820
          51821
        ];
        # Services listen on the tunnel address only; the firewall must not
        # get in their way there.
        networking.firewall.trustedInterfaces = [
          "wg0"
          "awg1"
        ];
      };

    testScript = ''
      import shlex

      STATE = "/home/alice/.local/state/vpn-zones"

      def alice(cmd):
          """Run a command as alice with her user manager reachable."""
          return machine.succeed(
              "su -l alice -c "
              + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )

      def in_zone(pid, cmd):
          """Enter the app namespace the way `vpn-zone run` does."""
          return alice(f"nsenter --preserve-credentials -U -n -m -t {pid} -- {cmd}")

      def in_zone_root(pid, cmd):
          """uid 0 inside the zone's userns: nfnetlink wants CAP_NET_ADMIN even
          for reading, and a plain user's capabilities die on execve
          (docs/GOTCHAS.md §1)."""
          return alice(f"nsenter -U -n -m -t {pid} -- {cmd}")

      # Both VMs boot in parallel; the server is only needed much later.
      start_all()

      machine.wait_for_unit("multi-user.target")
      # The module arrives through home-manager's system activation unit;
      # nothing exists in alice's profile before it finishes.
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_for_unit("user@1000.service")

      with subtest("module delivered: CLI in PATH, template unit installed"):
          alice("command -v vpn-zone")
          alice("systemctl --user cat vpn-zone@.service > /dev/null")
          alice("systemctl --user cat vpn-zone-desktop-sync.timer > /dev/null")
          machine.succeed(
              "test -f /etc/profiles/per-user/alice"
              "/share/zsh/site-functions/_vpn-zone"
          )

      # The DNS leak test needs two resolvers that disagree: the HOST's, which
      # a zone must never reach, and the tunnel's own further down. One lookup
      # then names whoever answered it. This one is the host's.
      with subtest("the host has a resolver of its own, and it answers"):
          machine.succeed(
              "systemd-run --unit=hostdns dnsmasq -k --port=5353 --bind-interfaces "
              "--listen-address=127.0.0.1 --no-resolv "
              "--address=/leaktest.internal/10.66.66.66"
          )
          # resolved may have written the server off while dnsmasq was not
          # there yet; a restart makes "it answers" mean what it says.
          machine.succeed("systemctl restart systemd-resolved")
          machine.wait_until_succeeds(
              "getent ahostsv4 leaktest.internal | grep -q 10.66.66.66"
          )
          machine.succeed("test -S /run/systemd/resolve/io.systemd.Resolve")

      with subtest("vpn-zone add: synthetic config (wg genkey, TEST-NET endpoint)"):
          alice(
              "priv=$(wg genkey); peer=$(wg genkey | wg pubkey); "
              "printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.99.0.2/32\\n\\n"
              "[Peer]\\nPublicKey = %s\\nAllowedIPs = 0.0.0.0/0\\n"
              "Endpoint = 192.0.2.1:51820\\n' \"$priv\" \"$peer\" > /tmp/vmsmoke.conf"
          )
          alice("vpn-zone add vmsmoke /tmp/vmsmoke.conf")
          machine.succeed(f"test -f {STATE}/vmsmoke/config.conf")

      with subtest("vpn-zone up: starts the vpn-zone@ unit and waits for ready"):
          alice("vpn-zone up vmsmoke")
          alice("systemctl --user is-active vpn-zone@vmsmoke.service")
          machine.succeed(f"test -f {STATE}/vmsmoke/ready")

      with subtest("tab completion offers the zone where a zone is expected"):
          out = alice("vpn-zone _complete -- vpn-zone up \"\" 3")
          assert "vmsmoke" in out.split(), out

      zpid = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
      upid = machine.succeed(f"cat {STATE}/vmsmoke/uplink.pid").strip()
      assert zpid != upid, "zone.pid and uplink.pid are one namespace, must be two"

      # The main hermeticity assert (docs/LEAK-MODEL.md): everything else —
      # routes, IPv6, DNS — is a consequence of "nothing but lo and the tunnel
      # exists in the app namespace".
      with subtest("hermeticity: exactly lo and awg0 in the app-ns"):
          links = in_zone(zpid, "ip -o link show")
          assert len(links.strip().splitlines()) == 2, f"extra links in app-ns: {links}"
          assert ": lo:" in links, links
          assert ": awg0" in links, links

      with subtest("v4 default route through the tunnel"):
          out = in_zone(zpid, "ip -4 route show default")
          assert "dev awg0" in out, out

      with subtest("no IPv6 path out (config has no v6)"):
          out = in_zone(zpid, "sh -c 'ip -6 route show default 2>/dev/null || true'")
          assert out.strip() == "" or out.strip().startswith("unreachable"), out

      with subtest("the zone's own nsswitch.conf: hosts is files dns, the host's is untouched"):
          out = in_zone(zpid, "grep '^hosts:' /etc/nsswitch.conf")
          assert out.strip() == "hosts: files dns", out
          out = machine.succeed("grep '^hosts:' /etc/nsswitch.conf")
          assert "resolve" in out, f"the zone changed the host's nsswitch.conf: {out}"

      with subtest("zone DNS defaults to 1.1.1.1 (config has no DNS=)"):
          out = in_zone(zpid, "cat /etc/resolv.conf")
          assert "nameserver 1.1.1.1" in out, out

      with subtest("route to the endpoint goes INTO the tunnel (no loop by design)"):
          out = in_zone(zpid, "ip route get 192.0.2.1")
          assert "dev awg0" in out, out

      with subtest("second echelon, app-ns: output drops everything but awg0"):
          rules = in_zone_root(zpid, "nft list ruleset")
          for pat in ["chain output", "policy drop", 'oifname "awg0" accept']:
              assert pat in rules, f"app-ns ruleset lacks {pat!r}:\n{rules}"

      with subtest("uplink: pasta interface, default route, awg0 moved away"):
          links = in_zone(upid, "ip -o link show")
          assert ": hostif" in links, f"no pasta interface in uplink-ns: {links}"
          assert "awg0" not in links, f"awg0 stayed in uplink-ns: {links}"
          out = in_zone(upid, "ip -4 route show default")
          assert out.strip(), "no default route in uplink-ns — pasta gave no way out"

      # pasta's defaults mirror every TCP/UDP port bound on the host's loopback
      # onto the uplink's loopback (-T/-U auto), and the uplink's filter
      # accepts lo. The host's dnsmasq listens on 127.0.0.1:5353: with the
      # defaults it would answer from inside the uplink within a second.
      with subtest("uplink: pasta mirrors none of the host's loopback ports"):
          machine.succeed("ss -tln | grep -q '127.0.0.1:5353'")
          machine.sleep(3)
          in_zone(upid, "sh -c '! timeout 3 socat -u OPEN:/dev/null TCP:127.0.0.1:5353'")

      with subtest("second echelon, uplink: only tunnel transport may leave"):
          rules = in_zone_root(upid, "nft list ruleset")
          for pat in [
              "chain output",
              "policy drop",
              "daddr 192.0.2.1 udp dport 51820 accept",
          ]:
              assert pat in rules, f"uplink ruleset lacks {pat!r}:\n{rules}"

      with subtest("vpn-zone down: unit stops, cgroup takes pasta with it"):
          alice("vpn-zone down vmsmoke")
          status = alice(
              "systemctl --user is-active vpn-zone@vmsmoke.service || true"
          ).strip()
          assert status in ("inactive", "failed"), status
          # The same needle `vpn-zone gc` uses to find an orphaned pasta —
          # except for the [p]: the test driver runs every command through
          # `timeout N bash -c '…'`, and THAT process carries the pattern text
          # in its argv, so a plain pattern matches its own invocation forever.
          # The bracket makes the regex miss its own literal text. On a real
          # failure, dump who the survivor is — uid, parent and cgroup say
          # whether it escaped the unit's cgroup or just ignored the signal.
          try:
              machine.wait_until_fails(
                  f"pgrep -f '[p]asta --netns /proc/{upid}/ns/net'", timeout=120
              )
          except Exception:
              _, dump = machine.execute(
                  "pid=$(pgrep -of '[p]asta --netns'); "
                  "ps -p $pid -o pid,ppid,uid,args; cat /proc/$pid/cgroup"
              )
              raise Exception(f"pasta survived vpn-zone down:\n{dump}")
          out = alice("vpn-zone list")
          assert "vmsmoke — опущена" in out, out

      with subtest("vpn-zone run on a down zone starts the unit by itself"):
          out = alice("vpn-zone run vmsmoke -- ip -o link show")
          assert ": awg0" in out, f"run did not enter the zone: {out}"
          status = alice(
              "systemctl --user is-active vpn-zone@vmsmoke.service || true"
          ).strip()
          assert status == "active", f"run did not leave the unit running: {status}"
          alice("vpn-zone down vmsmoke")

      # The picker branch the smoke test explicitly cannot cover: offline
      # starts vpn-zone@offline through `systemctl --user`. No graphics in the
      # VM either, so the picker must take what would have been highlighted —
      # the remembered last choice. The container axis is pinned to the main
      # profile (`__main__`) so no second dialog is needed.
      with subtest("picker offline branch: zone via systemctl --user, lo-only"):
          alice(f"mkdir -p {STATE}/.last {STATE}/.pinnedprofile")
          alice(f"printf offline > {STATE}/.last/vmpickapp")
          alice(f"printf __main__ > {STATE}/.pinnedprofile/vmpickapp")
          out = alice(
              "env -u WAYLAND_DISPLAY -u DISPLAY "
              "vpn-zone-pick --label VM-picker --id vmpickapp -- ip -o link show"
          )
          lines = [l for l in out.strip().splitlines() if ": " in l]
          assert len(lines) == 1 and ": lo:" in lines[0], f"offline zone not lo-only: {out}"
          status = alice(
              "systemctl --user is-active vpn-zone@offline.service || true"
          ).strip()
          assert status == "active", f"picker did not start the offline unit: {status}"

      # "Offline" has to mean offline for NAMES too. A unix socket is not an
      # interface: without the hiding, a program in a zone with nothing but
      # loopback could still have any name looked up by the host's resolver —
      # which tells the outside world what it wants and carries out with it
      # anything that can be spelled into a hostname.
      with subtest("an offline zone cannot reach the host's resolver either"):
          opid = machine.succeed(f"cat {STATE}/offline/zone.pid").strip()
          in_zone(opid, "test ! -e /run/systemd/resolve/io.systemd.Resolve")
          in_zone(opid, "sh -c '! getent ahostsv4 leaktest.internal'")
          alice("vpn-zone down offline")

      # `vpn-zone doctor` (ROADMAP M5): the probe runs INSIDE the zone and must
      # find nothing wrong there — and, run in the host's own namespaces, it
      # must find exactly what a zone hides: a second way out, the resolver's
      # socket, the host's nsswitch.conf. A probe that passes the host would
      # prove nothing about the zone.
      with subtest("doctor: a zone passes, the host's own namespace does not"):
          alice("vpn-zone up vmsmoke")
          out = alice("vpn-zone doctor vmsmoke --json")
          assert out.startswith('{"schema_version":1,'), out
          assert '"worst":"fail"' not in out, out
          for must in ["links", "route4", "route6", "nsswitch", "resolvers"]:
              assert f'{{"id":"{must}","level":"ok"' in out, (must, out)
          # Known open channels are named, not hidden.
          assert '{"id":"session-bus","level":"warn"' in out, out
          tools = alice(
              "grep -m1 -o '/nix/store/[^ \"]*-vpn-zone-tools.json' "
              "$(readlink -f $(command -v vpn-zone))"
          ).strip()
          core = machine.succeed(f"grep -o '\"core\": *\"[^\"]*\"' {tools}").strip().split('"')[3]
          host = alice(f"{core} doctor-probe 1000")
          for leak in ["links", "resolvers", "nsswitch"]:
              assert f"{leak}\tfail\t" in host, (leak, host)
          alice("vpn-zone down vmsmoke")

      # --- Per-container trust (docs/CERTIFICATES.md) ------------------------
      # A CA generated here and nowhere else. On NixOS every bundle path is a
      # symlink chain into ONE store file, and the layer binds over that file
      # in the launch's own mount namespace — this is the one place that
      # layout is exercised (the CI smoke runs on Ubuntu, a plain file).
      CA = "/tmp/vmca"

      def in_container(profile, net, cmd):
          return alice(f"vpn-zone run {net} --profile {profile} -- {cmd}")

      with subtest("trust: a CA and a server certificate made on the fly"):
          alice(
              f"mkdir -p {CA} && cd {CA} && "
              "openssl req -x509 -newkey rsa:2048 -nodes -days 2 "
              "-subj '/CN=vpn-zones vm CA' "
              "-addext 'basicConstraints=critical,CA:TRUE' "
              "-addext 'keyUsage=critical,keyCertSign,cRLSign' "
              "-keyout ca.key -out ca.pem 2>/dev/null && "
              "openssl req -newkey rsa:2048 -nodes -subj '/CN=tls.internal' "
              "-keyout srv.key -out srv.csr 2>/dev/null && "
              "printf 'subjectAltName=DNS:tls.internal\\n' > ext && "
              "openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key "
              "-CAcreateserial -days 2 -extfile ext -out srv.pem 2>/dev/null"
          )
          alice("vpn-zone profile create vmca && vpn-zone profile create vmnoca")
          alice(f"vpn-zone trust add vmca {CA}/ca.pem --yes")

      with subtest("trust: the container trusts it, through the store-file bind and p11-kit"):
          in_container("vmca", "direct", f"openssl verify {CA}/srv.pem")
          in_container("vmca", "direct", f"openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt {CA}/srv.pem")
          # p11-kit is what NSS reads on NixOS (libnssckbi.so is p11-kit-trust).
          out = in_container("vmca", "direct", "trust list --filter=ca-anchors")
          assert "vpn-zones vm CA" in out, f"p11-kit does not see the container's CA:\n{out}"
          out = in_container("vmca", "direct", "sh -c 'certutil -L -d sql:$HOME/.pki/nssdb'")
          assert "vpn-zones " in out, f"the container's NSS database lacks the CA:\n{out}"
          # Through a zone too: the layer lives in the launch's namespace, not
          # the zone's.
          in_container("vmca", "vmsmoke", f"openssl verify {CA}/srv.pem")

      with subtest("trust: the host and the container next door do not"):
          machine.fail(f"su -l alice -c 'openssl verify {CA}/srv.pem'")
          machine.fail("su -l alice -c 'trust list --filter=ca-anchors | grep -q \"vpn-zones vm CA\"'")
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              f"vpn-zone run direct --profile vmnoca -- openssl verify {CA}/srv.pem'"
          )
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              f"vpn-zone run vmsmoke --profile vmnoca -- openssl verify {CA}/srv.pem'"
          )
          machine.fail("grep -q 'vpn-zones vm CA' /etc/ssl/certs/ca-certificates.crt")
          machine.fail(
              "test -f /home/alice/.pki/nssdb/cert9.db && "
              "su -l alice -c 'certutil -L -d sql:/home/alice/.pki/nssdb' | grep -q 'vpn-zones '"
          )

      # The decision that makes environment leaks harmless: inside the
      # container the variables name the SYSTEM path. A program that pushes
      # them into the user manager changes nothing for anybody else — proven
      # with the push actually having happened.
      with subtest("trust: a leaked environment gives the host nothing"):
          in_container(
              "vmca",
              "direct",
              "systemctl --user import-environment SSL_CERT_FILE NIX_SSL_CERT_FILE",
          )
          out = alice("systemctl --user show-environment")
          assert "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" in out, out
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              f"systemd-run --user --wait --pipe --quiet openssl verify {CA}/srv.pem'"
          )
          alice("systemctl --user unset-environment SSL_CERT_FILE NIX_SSL_CERT_FILE")

      with subtest("trust: after a reset the container does not trust it either"):
          alice("vpn-zone trust reset vmca")
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              f"vpn-zone run direct --profile vmca -- openssl verify {CA}/srv.pem'"
          )
          out = in_container("vmca", "direct", "sh -c 'certutil -L -d sql:$HOME/.pki/nssdb || true'")
          assert "vpn-zones " not in out, f"the reset left the CA in the NSS database:\n{out}"
          alice("vpn-zone down vmsmoke")

      # --- Entries in the user's own directory (docs/LAUNCHERS.md §3.2) -----
      # The directory XDG gives the highest precedence, where programs write the
      # entries mimeapps.list sends links to. Taken over in place, never a
      # symlink (home-manager's own entries are right there), and given back
      # byte for byte.
      APPS = "/home/alice/.local/share/applications"

      with subtest("user entries: a foreign one is taken over, a symlink is not, and both come back"):
          # The original is written outside first: the path unit takes the
          # entry over the moment it lands in the directory.
          alice(
              "printf '[Desktop Entry]\\nType=Application\\nName=VM foreign\\n"
              "NoDisplay=true\\nExec=/bin/sh -c true %%u\\n' > /tmp/vmforeign.orig"
          )
          alice(f"cp /tmp/vmforeign.orig {APPS}/userapp-vmforeign.desktop")
          alice("vpn-zone sync")
          out = alice(f"cat {APPS}/userapp-vmforeign.desktop")
          assert "X-VPNZone=adopted" in out, out
          assert "vpn-zone-pick --id userapp-vmforeign --" in out, out
          alice("vpn-zone mode off")
          alice(f"cmp {APPS}/userapp-vmforeign.desktop /tmp/vmforeign.orig")
          alice("vpn-zone mode picker")
          alice(f"rm -f {APPS}/userapp-vmforeign.desktop")
          # A symlink is somebody's managed entry (home-manager's xdg.dataFile,
          # a dotfile manager): left as it is, never written through.
          alice(f"cp /tmp/vmforeign.orig /tmp/vmlink.desktop && ln -s /tmp/vmlink.desktop {APPS}/userapp-vmlink.desktop")
          alice("vpn-zone sync")
          alice(f"test -L {APPS}/userapp-vmlink.desktop")
          alice("cmp /tmp/vmlink.desktop /tmp/vmforeign.orig")
          alice(f"rm -f {APPS}/userapp-vmlink.desktop")

      # XDG autostart (docs/CONTAINERS.md §5): taken over like a user entry,
      # and the picker it goes through never asks. A program nobody chose
      # anything for starts offline, in a home of its own, without a file
      # access dialog — the owner's decision of 2026-09-17.
      # D-Bus activation (docs/CONTAINERS.md §5.3): the bus starts a
      # DBusActivatable program from its SERVICE file, around the launcher
      # entry. A shadow service in the user's directory wins over the system
      # one and goes through the picker — here pinned offline, so the program
      # must see loopback only. Without the shadow (or without the bus
      # reloading it) the system service would run it in the host's network,
      # and the link list below would say so.
      with subtest("D-Bus activation: the shadow service starts the program through the picker"):
          APP = "org.vpnzones.VmActivatable"
          alice(f"mkdir -p {STATE}/.pinned {STATE}/.pinnedprofile")
          alice(f"printf offline > {STATE}/.pinned/{APP}")
          alice(f"printf __main__ > {STATE}/.pinnedprofile/{APP}")
          machine.succeed("rm -f /tmp/vmactivated")
          alice("vpn-zone sync")
          out = alice(f"cat /home/alice/.local/share/dbus-1/services/{APP}.service")
          assert f"vpn-zone-pick --id {APP} --" in out, out
          alice("systemctl --user reload dbus.service")
          alice(
              f"${pkgs.glib.bin}/bin/gdbus call --session --timeout 5 --dest {APP} "
              f"--object-path /org/vpnzones/VmActivatable --method org.freedesktop.DBus.Peer.Ping || true"
          )
          machine.wait_until_succeeds("test -s /tmp/vmactivated", timeout=60)
          out = machine.succeed("cat /tmp/vmactivated")
          lines = [l for l in out.strip().splitlines() if ": " in l]
          assert len(lines) == 1 and ": lo:" in lines[0], f"activation ran outside the zone: {out}"
          alice("vpn-zone mode off")
          alice(f"test ! -e /home/alice/.local/share/dbus-1/services/{APP}.service")
          alice("vpn-zone mode picker")
          alice("vpn-zone down offline || true")

      AUTOSTART = "/home/alice/.config/autostart"
      with subtest("autostart: taken over, and an unassigned program starts offline in its own home"):
          alice(
              "printf '[Desktop Entry]\\nType=Application\\nName=VM auto\\n"
              "Exec=vmauto-program --flag\\n' > /tmp/vmauto.orig"
          )
          alice(f"mkdir -p {AUTOSTART} && cp /tmp/vmauto.orig {AUTOSTART}/vmauto.desktop")
          alice("vpn-zone sync")
          out = alice(f"cat {AUTOSTART}/vmauto.desktop")
          assert "vpn-zone-pick --autostart --id vmauto -- vmauto-program --flag" in out, out
          assert "X-VPNZone=adopted" in out, out
          alice("vpn-zone mode off")
          alice(f"cmp {AUTOSTART}/vmauto.desktop /tmp/vmauto.orig")
          alice("vpn-zone mode picker")
          alice(f"rm -f {AUTOSTART}/vmauto.desktop")

          # What the rewritten entry runs, as the session would run it.
          out = alice(
              "env -u WAYLAND_DISPLAY -u DISPLAY "
              "vpn-zone-pick --autostart --id vmauto -- ${pkgs.iproute2}/bin/ip -o link show"
          )
          lines = [l for l in out.strip().splitlines() if ": " in l]
          assert len(lines) == 1 and ": lo:" in lines[0], f"autostart not offline: {out}"
          alice("test -f /home/alice/.local/state/vpn-sandboxes/app-vmauto/perms")
          alice("test ! -s /home/alice/.local/state/vpn-sandboxes/app-vmauto/perms")
          alice("test -d /home/alice/.local/state/vpn-sandboxes/app-vmauto/home")
          # Nothing remembered: autostart is not a choice.
          alice(f"test ! -e {STATE}/.pinned/vmauto && test ! -e {STATE}/.last/vmauto")
          alice("vpn-zone down offline || true")

      # --- Declared in Nix (docs/CONTAINERS.md §8) ---------------------------
      DECLCA = "${declaredCa}"

      with subtest("declared: status --json names Nix as the source, and the CLI leaves it alone"):
          out = alice("vpn-zone status --json")
          assert out.startswith('{"schema_version":1,'), out
          assert '"selector":"vmdecl"' in out, out
          assert '"network":{"value":"direct","source":"nix"}' in out, out
          assert '"container":{"value":"vmdecl","source":"nix"}' in out, out
          assert '"source":"nix"}]' in out or '"source":"nix"}' in out, out
          alice("sh -c '! vpn-zone container set vmdecl network offline'")
          alice("test -d /home/alice/.local/state/vpn-profiles/vmdecl")

      with subtest("declared: the container runs in its network only, trusting its declared CA"):
          in_container("vmdecl", "direct", f"openssl verify {DECLCA}/srv.pem")
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              "vpn-zone run offline --profile vmdecl -- true'"
          )
          machine.fail(f"su -l alice -c 'openssl verify {DECLCA}/srv.pem'")
          alice("vpn-zone down offline || true")

      # --- The real tunnel: an actual WireGuard peer on the second VM -------
      # Everything above used an unreachable endpoint and checked mechanics;
      # from here on the handshake, the traffic and the DNS are real. This is
      # the first coverage of `vpn-zone check`'s "tunnel alive" branch, and a
      # first cut of the ROADMAP leak tests: while the zone is in active use,
      # the only thing allowed to leave the client machine towards the server
      # is the tunnel's own UDP.
      server.wait_for_unit("multi-user.target")

      with subtest("real tunnel: wireguard peer configured on the server VM"):
          server.succeed(
              "wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub"
          )
          spub = server.succeed("cat /root/wg.pub").strip()
          cpriv = machine.succeed("wg genkey").strip()
          cpub = machine.succeed(f"printf %s '{cpriv}' | wg pubkey").strip()
          server_ip = server.succeed(
              "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()
          assert server_ip, "server has no address on eth1"
          server.succeed(
              "ip link add wg0 type wireguard && "
              "ip addr add 10.99.0.1/24 dev wg0 && "
              "wg set wg0 listen-port 51820 private-key /root/wg.key "
              f"peer '{cpub}' allowed-ips 10.99.0.2/32 && "
              "ip link set wg0 up"
          )
          # The services behind the tunnel, bound to the tunnel address only:
          # a TCP responder that reports the peer address it saw, and DNS.
          server.succeed(
              "systemd-run --unit=hello socat "
              "TCP-LISTEN:8080,bind=10.99.0.1,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed(
              "systemd-run --unit=dns dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=10.99.0.1 --no-resolv "
              "--address=/leaktest.internal/10.99.0.9"
          )

      with subtest("vpn-zone add vmreal: config with DNS= and a live endpoint"):
          alice(
              f"printf '[Interface]\\nPrivateKey = {cpriv}\\nAddress = 10.99.0.2/32\\n"
              f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
              f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' "
              "> /tmp/vmreal.conf"
          )
          alice("vpn-zone add vmreal /tmp/vmreal.conf")
          alice("vpn-zone up vmreal")

      # The capture starts BEFORE any traffic, so the handshake itself is
      # under watch too. `vpn-zone gc`-style precision is not needed: filter
      # by the server address and drop the one flow that is allowed.
      with subtest("leak watch armed on the physical interface"):
          machine.succeed(
              "systemd-run --unit=leakwatch tcpdump -n --immediate-mode -i eth1 "
              f"-w /tmp/leak.pcap 'host {server_ip} and not arp "
              "and not (udp and port 51820)'"
          )
          machine.wait_until_succeeds(
              "journalctl -u leakwatch | grep -q 'listening on eth1'"
          )

      rzpid = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()

      # The holder's ordinary branch, which nothing else covers: with the
      # module present `ip link add awg0 type amneziawg` succeeds and `awg`
      # configures the interface. (The fallback to the in-tree wireguard
      # module lives in the CI smoke test — its runner has no amneziawg.)
      with subtest("the tunnel is a real amneziawg link, not the wireguard fallback"):
          out = in_zone(rzpid, "ip -d link show awg0")
          assert "amneziawg" in out, f"awg0 is not an amneziawg link:\n{out}"

      # And this config carries NO obfuscation parameters, so everything below
      # — handshake, traffic, DNS — is an amneziawg client talking to a stock
      # `wireguard` peer. Compatibility on the wire is the assert.
      with subtest("real traffic: TCP through the tunnel, server sees the tunnel address"):
          out = in_zone(rzpid, "socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, f"server saw someone else: {out}"

      with subtest("DNS from the config: resolv.conf points into the tunnel and answers"):
          out = in_zone(rzpid, "cat /etc/resolv.conf")
          assert "nameserver 10.99.0.1" in out, out
          out = in_zone(rzpid, "dig +time=5 +tries=2 +short leaktest.internal @10.99.0.1")
          assert "10.99.0.9" in out, f"DNS through the tunnel failed: {out}"

      # THE DNS LEAK TEST. Everything above went through resolv.conf; this is
      # the path programs actually take — glibc's NSS, where `resolve` stands
      # ahead of `dns` and talks varlink to the host's resolved over a unix
      # socket. That is how a browser in a zone reported the user's real ISP as
      # its resolver while `curl ifconfig.me` in the same zone correctly showed
      # the VPN's address (`docs/GOTCHAS.md` §3).
      with subtest("no DNS leak: the NSS path stays inside the tunnel"):
          # The socket is gone in the zone and untouched outside it: the tmpfs
          # lives in the zone's mount namespace and nowhere else.
          in_zone(rzpid, "test ! -e /run/systemd/resolve/io.systemd.Resolve")
          machine.succeed("test -S /run/systemd/resolve/io.systemd.Resolve")
          # getent and not dig, and that is the whole point: dig reads
          # resolv.conf itself and would have answered correctly while every
          # program on the machine was leaking.
          out = in_zone(rzpid, "getent ahostsv4 leaktest.internal")
          assert "10.66.66.66" not in out, f"DNS LEAK: the host's resolver answered inside the zone: {out}"
          assert "10.99.0.9" in out, f"the zone resolved nothing through the tunnel: {out}"
          # And the host still resolves as it did before the zone came up.
          out = machine.succeed("getent ahostsv4 leaktest.internal")
          assert "10.66.66.66" in out, f"the zone broke the host's own resolver: {out}"

      with subtest("vpn-zone check reports a live tunnel"):
          # The status mirror refreshes every 5 seconds from inside the zone;
          # give it a couple of cycles after the first handshake.
          machine.wait_until_succeeds(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              "vpn-zone check vmreal'",
              timeout=60,
          )

      with subtest("the leak capture is empty"):
          machine.succeed("systemctl stop leakwatch")
          count = machine.succeed(
              "tcpdump -nr /tmp/leak.pcap 2>/dev/null | wc -l"
          ).strip()
          if count != "0":
              escaped = machine.succeed("tcpdump -nr /tmp/leak.pcap 2>/dev/null")
              raise AssertionError(f"packets escaped the tunnel:\n{escaped}")
          alice("vpn-zone down vmreal")

      # --- The obfuscated tunnel: AmneziaWG as a real user runs it ----------
      # Everything so far was wire-compatible with plain WireGuard. This zone
      # is the branch nothing else in the project touches: junk packets before
      # the handshake (Jc/Jmin/Jmax), junk prefixes on the handshake packets
      # (S1/S2) and non-standard message-type headers (H1..H4), carried from
      # the config through `awg setconf` into the kernel on BOTH ends. A stock
      # WireGuard peer cannot answer such a client at all — so the handshake
      # below is itself the proof that the parameters arrived where they had
      # to.
      #
      # The values: H1..H4 must be four non-overlapping ranges, and they must
      # stay clear of the standard message types 1..4 or the traffic would be
      # recognisable again; S1/S2 must not make an initiation packet the size
      # of a response one (S2 == S1 + 56); Jmin < Jmax, and both well under
      # the maximum message size. Written as printf escapes, shared verbatim
      # by the server config and the zone config.
      AWG_JUNK = (
          "Jc = 4\\nJmin = 40\\nJmax = 70\\nS1 = 30\\nS2 = 40\\n"
          "H1 = 1234567\\nH2 = 2345678\\nH3 = 3456789\\nH4 = 4567890\\n"
      )

      # vmreal is really down before the next capture is armed: its own tunnel
      # UDP (port 51820) is not in the new filter's exception, and a straggler
      # would read as a leak.
      status = alice("systemctl --user is-active vpn-zone@vmreal.service || true").strip()
      assert status in ("inactive", "failed"), status

      with subtest("obfuscated peer: a second, amneziawg interface on the server VM"):
          server.succeed(
              "awg genkey > /root/awg.key && awg pubkey < /root/awg.key > /root/awg.pub"
          )
          apub = server.succeed("cat /root/awg.pub").strip()
          opriv = machine.succeed("wg genkey").strip()
          opub = machine.succeed(f"printf %s '{opriv}' | wg pubkey").strip()
          server.succeed(
              "printf '[Interface]\\nPrivateKey = %s\\nListenPort = 51821\\n"
              + AWG_JUNK
              + "\\n[Peer]\\nPublicKey = %s\\nAllowedIPs = 10.98.0.2/32\\n' "
              + f"\"$(cat /root/awg.key)\" '{opub}' > /root/awg1.conf"
          )
          server.succeed(
              "ip link add awg1 type amneziawg && "
              "awg setconf awg1 /root/awg1.conf && "
              "ip addr add 10.98.0.1/24 dev awg1 && "
              "ip link set awg1 up"
          )
          out = server.succeed("ip -d link show awg1")
          assert "amneziawg" in out, f"server awg1 is not an amneziawg link:\n{out}"
          # A separate responder on a separate subnet, so a packet that took
          # the wrong tunnel cannot pass for a right one.
          server.succeed(
              "systemd-run --unit=hello-awg socat "
              "TCP-LISTEN:8081,bind=10.98.0.1,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )

      with subtest("vpn-zone add vmawg: a config with real obfuscation parameters"):
          alice(
              f"printf '[Interface]\\nPrivateKey = {opriv}\\nAddress = 10.98.0.2/32\\n"
              + AWG_JUNK
              + f"\\n[Peer]\\nPublicKey = {apub}\\nAllowedIPs = 0.0.0.0/0\\n"
              + f"Endpoint = {server_ip}:51821\\n' > /tmp/vmawg.conf"
          )
          alice("vpn-zone add vmawg /tmp/vmawg.conf")

      # Armed before the zone comes up, so the very first junk packet is under
      # watch: towards the server, only the obfuscated tunnel's own UDP may
      # ever appear on the wire.
      with subtest("leak watch armed for the obfuscated tunnel"):
          machine.succeed(
              "systemd-run --unit=leakawg tcpdump -n --immediate-mode -i eth1 "
              f"-w /tmp/leak-awg.pcap 'host {server_ip} and not arp "
              "and not (udp and port 51821)'"
          )
          machine.wait_until_succeeds(
              "journalctl -u leakawg | grep -q 'listening on eth1'"
          )

      with subtest("vpn-zone up vmawg: the obfuscated zone comes up"):
          alice("vpn-zone up vmawg")
          alice("systemctl --user is-active vpn-zone@vmawg.service")
          machine.succeed(f"test -f {STATE}/vmawg/ready")

      azpid = machine.succeed(f"cat {STATE}/vmawg/zone.pid").strip()

      with subtest("the obfuscated zone rides amneziawg as well"):
          out = in_zone(azpid, "ip -d link show awg0")
          assert "amneziawg" in out, f"awg0 is not an amneziawg link:\n{out}"

      # Traffic FIRST, handshake second — and not the other way round: nothing
      # in the zone sends anything of its own, and WireGuard (AmneziaWG with
      # it) only initiates a handshake when there is a packet to carry. Asking
      # `vpn-zone check` before any traffic waits forever on a tunnel that is
      # perfectly fine, merely idle. The TCP connection is what starts it: the
      # SYN queues behind the handshake and its retransmit gets through.
      with subtest("real traffic through the obfuscated tunnel"):
          out = in_zone(azpid, "socat -T10 - TCP:10.98.0.1:8081")
          assert "peer=10.98.0.2" in out, f"server saw someone else: {out}"

      with subtest("obfuscated handshake: vpn-zone check reports a live tunnel"):
          # Same 5-second status mirror as above; give it a couple of cycles.
          machine.wait_until_succeeds(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              "vpn-zone check vmawg'",
              timeout=60,
          )

      with subtest("the obfuscated tunnel's leak capture is empty"):
          machine.succeed("systemctl stop leakawg")
          count = machine.succeed(
              "tcpdump -nr /tmp/leak-awg.pcap 2>/dev/null | wc -l"
          ).strip()
          if count != "0":
              escaped = machine.succeed("tcpdump -nr /tmp/leak-awg.pcap 2>/dev/null")
              raise AssertionError(
                  f"packets escaped the obfuscated tunnel:\n{escaped}"
              )
          alice("vpn-zone down vmawg")
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
