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

  # A stand-in for the sound server's control socket: it records the command
  # of every frame that reaches it, one number per line.
  fakePulse = pkgs.writeText "fake-pulse.py" ''
    import os, socket, struct, threading
    path = "/run/user/1000/pulse/native"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX)
    server.bind(path)
    server.listen(8)
    def client(c):
        buf = b""
        while True:
            data = c.recv(65536)
            if not data:
                return
            buf += data
            while len(buf) >= 20:
                length = struct.unpack(">I", buf[:4])[0]
                if len(buf) < 20 + length:
                    break
                frame, buf = buf[:20 + length], buf[20 + length:]
                command = struct.unpack(">I", frame[21:25])[0]
                with open("/tmp/pulse-seen", "a") as log:
                    log.write(f"{command}\n")
    while True:
        c, _ = server.accept()
        threading.Thread(target=client, args=(c,), daemon=True).start()
  '';
  # A client in a zone: LOAD_MODULE, then GET_SERVER_INFO; prints the command
  # of the answer to the first.
  pulseClient = pkgs.writeText "pulse-client.py" ''
    import socket, struct, time
    def frame(command, tag):
        payload = b"L" + struct.pack(">I", command) + b"L" + struct.pack(">I", tag)
        return struct.pack(">IIIII", len(payload), 0xFFFFFFFF, 0, 0, 0) + payload
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/user/1000/pulse/native")
    s.sendall(frame(51, 1))
    answer = s.recv(64)
    print("reply", struct.unpack(">I", answer[21:25])[0])
    s.sendall(frame(20, 2))
    time.sleep(1)
  '';

  # A raw session-bus client: ends the authentication the way dbus-daemon and
  # xdg-dbus-proxy allow and the bus filter used to miss ("BEGIN" and more on
  # the line), then asks the portal to open the link in argv[1]. Prints what
  # came back.
  rawBegin = pkgs.writeText "raw-begin.py" ''
    import os, socket, struct, sys
    def pad(b, n):
        return b + b"\0" * ((-len(b)) % n)
    def s(v):
        e = v.encode()
        return struct.pack("<I", len(e)) + e + b"\0"
    def msg(serial, path, iface, member, dest, sig="", body=b""):
        fields = b""
        items = [(1, "o", path), (2, "s", iface), (3, "s", member), (6, "s", dest)]
        if sig:
            items.append((8, "g", sig))
        for code, t, val in items:
            fields = pad(fields, 8)
            f = bytes([code, 1]) + t.encode() + b"\0"
            if t == "g":
                f += bytes([len(val)]) + val.encode() + b"\0"
            else:
                f += s(val)
            fields += f
        head = b"l" + bytes([1, 0, 1]) + struct.pack("<III", len(body), serial, len(fields))
        return pad(head + fields, 8) + body
    body = pad(pad(s(""), 4) + s(sys.argv[1]), 4) + struct.pack("<I", 0)
    body = pad(body, 8)
    c = socket.socket(socket.AF_UNIX)
    c.connect("/run/user/1000/bus")
    c.sendall(b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode() + b"\r\n")
    ok = c.recv(4096)
    assert ok.startswith(b"OK"), ok
    c.sendall(
        b"BEGIN now\r\n"
        + msg(1, "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "org.freedesktop.DBus")
        + msg(2, "/org/freedesktop/portal/desktop", "org.freedesktop.portal.OpenURI",
              "OpenURI", "org.freedesktop.portal.Desktop", "ssa{sv}", body)
    )
    c.settimeout(5)
    data = b""
    try:
        while b"/org/freedesktop/portal/desktop/request/" not in data:
            d = c.recv(4096)
            if not d:
                break
            data += d
    except socket.timeout:
        pass
    print(data)
  '';

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
          # A door that a group opens: the session has it, a zone must not.
          extraGroups = [ "vzdoor" ];
        };
        users.groups.vzdoor = { };
        systemd.tmpfiles.rules = [
          "d /var/lib/vzdoor 0750 root vzdoor -"
          "f /var/lib/vzdoor/door 0640 root vzdoor - open"
        ];

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
          # Hermeticity declared the way an owner switches it on for one zone:
          # the default spelled out (off, as it is anyway) and the zone as the
          # exception. The holder has to find this in ~/.config on its own.
          programs.vpn-zones.hermetic = {
            default = false;
            exceptions = [ "vmherm" ];
          };
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
          # The evil host's tmux server (LEAK-MODEL §15).
          pkgs.tmux
          # gdbus: a sandboxed program calling the portal (LEAK-MODEL §2).
          pkgs.glib
          # A real compositor for the restricted-Wayland check, headless.
          pkgs.sway
          pkgs.wayland-utils
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
        # The responder a host-interface zone talks to directly, on eth1.
        networking.firewall.allowedTCPPorts = [ 8090 ];
        # Services listen on the tunnel address only; the firewall must not
        # get in their way there.
        networking.firewall.trustedInterfaces = [
          "wg0"
          "awg1"
        ];
      };

    testScript = ''
      import json
      import re
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
          alice("systemctl --user cat vpn-zone-watch.timer > /dev/null")
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

      # The system bus (docs/HERMETICITY.md §7, B2): filtered by a proxy in
      # every zone. hostname1 and the session list are refused, reading
      # login1's properties and inhibiting sleep are not — and the host keeps
      # its whole bus.
      with subtest("system bus in a zone: hostname1 and ListSessions refused, login1 readable"):
          zp = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
          busctl = "busctl --system --timeout=5"
          inz = f"nsenter --preserve-credentials -U -n -m -t {zp} --"

          def bus(cmd, zone=True):
              """(exit status, stdout+stderr) of a busctl call as alice."""
              prefix = f"{inz} " if zone else ""
              return machine.execute(
                  "su -l alice -c "
                  + shlex.quote(
                      f"export XDG_RUNTIME_DIR=/run/user/1000; {prefix}{busctl} {cmd} 2>&1"
                  )
              )

          hostname = "get-property org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 Hostname"
          sessions = "call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ListSessions"
          idle = "get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager IdleHint"
          # The host first: every call works there, so a refusal in the zone
          # is the filter and not the test.
          # (Inhibit is allowed too, but polkit refuses it to a user without an
          # active session even on the host, so it cannot be shown here.)
          for call in [hostname, sessions, idle]:
              code, out = bus(call, zone=False)
              assert code == 0, f"on the host: {call}: {out}"
          code, out = bus(hostname)
          assert code != 0, f"hostname1 answered in the zone: {out}"
          code, out = bus(sessions)
          assert code != 0, f"ListSessions answered in the zone: {out}"
          # Reading is allowed — which also proves the proxy is up and the
          # refusals above are the filter, not a dead bus.
          code, out = bus(idle)
          assert code == 0, f"reading login1 refused in the zone: {out}"

      # X11 (docs/HERMETICITY.md §7, A): a socket in the host's /tmp/.X11-unix
      # is out of sight in a zone, and a launch into a zone carries no DISPLAY.
      with subtest("x11 in a zone: the host's socket is hidden and DISPLAY is gone"):
          machine.succeed(
              "mkdir -p /tmp/.X11-unix && systemd-run --unit=fakex "
              "socat UNIX-LISTEN:/tmp/.X11-unix/X77,fork /dev/null"
          )
          machine.wait_until_succeeds("test -S /tmp/.X11-unix/X77")
          zp = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
          in_zone(zp, "test ! -e /tmp/.X11-unix/X77")
          out = alice("DISPLAY=:77 vpn-zone run vmsmoke -- sh -c 'echo D=$DISPLAY.'")
          assert "D=." in out, f"DISPLAY reached the zone: {out}"
          machine.succeed("systemctl stop fakex")

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

      # `down` takes the network away; `kill` also takes away the programs,
      # which live in cgroups of their own. The host's are not touched.
      with subtest("vpn-zone kill: the zone's programs die, the zone is down, the host's live"):
          alice("systemd-run --user --unit=vmremote vpn-zone run vmsmoke -- sleep 4242")
          alice("systemd-run --user --unit=vmhostsleep sleep 4343")
          # The program itself, not the launch still waiting for the zone:
          # only the exec'd sleep has exactly this command line.
          machine.wait_until_succeeds("pgrep -f '^(/[^ ]*/)?sleep 424[2]$'", timeout=60)
          machine.wait_until_succeeds("pgrep -f 'sleep 434[3]'", timeout=30)
          out = alice("vpn-zone kill vmsmoke")
          assert "оборвана" in out, out
          machine.wait_until_fails("pgrep -f 'sleep 424[2]'", timeout=15)
          machine.succeed("pgrep -f 'sleep 434[3]'")
          status = alice(
              "systemctl --user is-active vpn-zone@vmsmoke.service || true"
          ).strip()
          assert status != "active", f"the zone is still up: {status}"
          out = alice("vpn-zone journal --json")
          assert '"event":"kill","zone":"vmsmoke"' in out and '"down":"yes"' in out, out
          assert re.search(r'"killed":"[1-9]', out), out
          alice("systemctl --user stop vmhostsleep.service")
          alice("systemctl --user reset-failed vmremote.service || true")

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
          # Declared as `direct`, the old name: read as the new one.
          assert '"network":{"value":"unconfined","source":"nix"}' in out, out
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

      # The marker a host egress policy lets the zones out by
      # (docs/CONTAINERS.md §9, `uplink_owner`): counted from here on, every
      # packet of the tunnel must leave from a socket of the zone's uid 0.
      with subtest("egress marker: status --json names the owner of the zone's sockets"):
          owner = json.loads(alice("vpn-zone status --json"))["uplink_owner"]
          assert owner and owner["uid"] != 1000, f"no usable uplink_owner: {owner}"
          machine.succeed(
              "nft add table inet vzowner && "
              "nft add chain inet vzowner out '{ type filter hook output priority 0; }' && "
              f"nft add rule inet vzowner out ip daddr {server_ip} udp dport 51820 "
              f"meta skuid {owner['uid']} meta skgid {owner['gid']} counter && "
              f"nft add rule inet vzowner out ip daddr {server_ip} udp dport 51820 counter"
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

      with subtest("egress marker: every tunnel packet left from the zone's uid"):
          out = machine.succeed("nft list chain inet vzowner out")
          counts = re.findall(r"counter packets (\d+)", out)
          assert len(counts) == 2 and int(counts[1]) > 0, out
          assert counts[0] == counts[1], f"tunnel packets from another owner:\n{out}"
          machine.succeed("nft delete table inet vzowner")

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

      # --- The compositor's IPC and its raw socket (docs/LEAK-MODEL.md §13) --
      # Fake listeners first, where niri keeps its IPC socket and a compositor
      # its own socket: neither may be reachable from ANY zone, created before
      # the zone or after it. A socket the zone does keep — pipewire's — is
      # recreated on the host and must come back into the zone by itself.
      with subtest("compositor IPC and raw socket: out of reach of an ordinary zone"):
          alice(
              "systemd-run --user --unit=fakeniri socat "
              "UNIX-LISTEN:/run/user/1000/niri.wayland-9.4242.sock,fork "
              "OPEN:/tmp/niri-got,creat,append"
          )
          alice(
              "systemd-run --user --unit=fakewayland socat "
              "UNIX-LISTEN:/run/user/1000/wayland-9,fork OPEN:/tmp/wayland-got,creat,append"
          )
          machine.wait_until_succeeds("test -S /run/user/1000/niri.wayland-9.4242.sock")
          machine.wait_until_succeeds("test -S /run/user/1000/wayland-9")
          # Not only where the socket lies: through the process that holds it,
          # /proc/<pid>/root (LEAK-MODEL §16). On the host that path works —
          # otherwise the refusal below would prove nothing.
          niri_pid = alice("systemctl --user show -p MainPID --value fakeniri").strip()
          via_proc = f"/proc/{niri_pid}/root/run/user/1000/niri.wayland-9.4242.sock"
          alice(f"echo proc-from-host | socat - UNIX-CONNECT:{via_proc}")
          machine.wait_until_succeeds("grep -q proc-from-host /tmp/niri-got")
          machine.succeed(
              "printf '%s\\n' 'echo \"NIRI=$NIRI_SOCKET\"' "
              "'echo spawn-from-zone | socat - UNIX-CONNECT:/run/user/1000/niri.wayland-9.4242.sock || echo NIRI-REFUSED' "
              "'echo raw-from-zone | socat - UNIX-CONNECT:/run/user/1000/wayland-9 || echo RAW-REFUSED' "
              f"'echo proc-from-zone | socat - UNIX-CONNECT:{via_proc} || echo PROC-REFUSED' "
              "> /tmp/niri-probe.sh && chmod 755 /tmp/niri-probe.sh"
          )
          out = alice(
              "NIRI_SOCKET=/run/user/1000/niri.wayland-9.4242.sock "
              "vpn-zone run vmsmoke -- sh /tmp/niri-probe.sh"
          )
          assert "NIRI=/run" not in out, out
          assert "NIRI-REFUSED" in out and "RAW-REFUSED" in out and "PROC-REFUSED" in out, out
          machine.sleep(2)
          machine.fail("grep -q spawn-from-zone /tmp/niri-got")
          machine.fail("grep -q proc-from-zone /tmp/niri-got")
          machine.fail("grep -q raw-from-zone /tmp/wayland-got")
          zp = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
          # The ordinary zone keeps its bus and systemd --user (LEAK-MODEL §1).
          in_zone(zp, "test -S /run/user/1000/bus")
          in_zone(zp, "test -S /run/user/1000/systemd/private")
          # Created after the zone: a compositor socket stays out, a kept
          # socket comes in — and comes in again when it is recreated.
          alice(
              "systemd-run --user --unit=latewayland socat "
              "UNIX-LISTEN:/run/user/1000/wayland-8,fork OPEN:/dev/null"
          )
          alice(
              "systemd-run --user --unit=fakepipewire socat "
              "UNIX-LISTEN:/run/user/1000/pipewire-0,fork SYSTEM:'echo pipewire-one'"
          )
          machine.wait_until_succeeds("test -S /run/user/1000/pipewire-0")
          in_zone(zp, "sh -c 'for i in $(seq 50); do socat -T2 - UNIX-CONNECT:/run/user/1000/pipewire-0 </dev/null | grep -q pipewire-one && exit 0; sleep 0.2; done; exit 1'")
          alice("systemctl --user stop fakepipewire.service")
          machine.succeed("rm -f /run/user/1000/pipewire-0")
          alice(
              "systemd-run --user --unit=fakepipewire2 socat "
              "UNIX-LISTEN:/run/user/1000/pipewire-0,fork SYSTEM:'echo pipewire-two'"
          )
          in_zone(zp, "sh -c 'for i in $(seq 50); do socat -T2 - UNIX-CONNECT:/run/user/1000/pipewire-0 </dev/null | grep -q pipewire-two && exit 0; sleep 0.2; done; exit 1'")
          in_zone(zp, "test ! -e /run/user/1000/wayland-8")
          in_zone(zp, "test ! -e /run/user/1000/wayland-9")
          in_zone(zp, "test ! -e /run/user/1000/niri.wayland-9.4242.sock")
          out = alice("vpn-zone doctor vmsmoke --json")
          assert '{"id":"wayland-raw","level":"ok"' in out, out
          assert '{"id":"compositor-ipc","level":"ok"' in out, out
          assert '{"id":"session-bus","level":"warn"' in out, out
          alice("vpn-zone down vmsmoke")

      # The sound server's control socket reaches a zone through the filter
      # (rust/src/pulse_filter.rs): a zone plays and records, it does not make
      # the host's sound server load a module that connects out, in the host's
      # network (review 2026-09-25). A stand-in server records what reaches it.
      with subtest("pulse: a zone cannot load a module into the host's sound server"):
          alice("systemd-run --user --unit=fakepulse ${pkgs.python3}/bin/python3 ${fakePulse}")
          machine.wait_until_succeeds("test -S /run/user/1000/pulse/native")
          alice("vpn-zone up vmsmoke")
          zp = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
          out = in_zone(zp, "${pkgs.python3}/bin/python3 ${pulseClient}")
          assert "reply 0" in out, f"LOAD_MODULE was not answered with ERROR: {out}"
          machine.wait_until_succeeds("grep -qx 20 /tmp/pulse-seen", timeout=15)
          machine.fail("grep -qx 51 /tmp/pulse-seen")
          alice("vpn-zone down vmsmoke")
          alice("systemctl --user stop fakepulse.service")

      # A real compositor, headless: sway speaks wp_security_context_v1 and
      # hides its privileged protocols from a restricted client. A program in a
      # zone gets Wayland — through the socket wl-sandbox made on the host — and
      # neither screencopy nor a virtual keyboard; sway's IPC does not answer it.
      with subtest("headless sway: a zone program gets restricted Wayland and no IPC"):
          alice(
              "systemd-run --user --unit=vmsway "
              "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
              "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
              "sway -c /dev/null"
          )
          machine.wait_until_succeeds("ls /run/user/1000/sway-ipc.*.sock", timeout=60)
          display = machine.succeed(
              "ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | grep -v '^wayland-[89]$' | head -1"
          ).strip()
          assert display, "sway made no socket"
          swaysock = machine.succeed("ls /run/user/1000/sway-ipc.*.sock | head -1").strip()
          host = alice(f"WAYLAND_DISPLAY={display} wayland-info")
          assert "zwlr_screencopy_manager_v1" in host, host
          alice(f"SWAYSOCK={swaysock} swaymsg -t get_version")
          zone = alice(
              f"WAYLAND_DISPLAY={display} SWAYSOCK={swaysock} "
              "vpn-zone run vmsmoke -- sh -c 'wayland-info; echo SWAY; swaymsg -t get_version || echo SWAY-REFUSED'"
          )
          assert "wl_compositor" in zone, zone
          assert "zwlr_screencopy_manager_v1" not in zone, zone
          assert "zwp_virtual_keyboard_manager_v1" not in zone, zone
          assert "SWAY-REFUSED" in zone, zone
          alice("vpn-zone down vmsmoke")

          alice("systemctl --user stop vmsway.service")

      # --- A hermetic zone (docs/HERMETICITY.md §7 C, the prototype) --------
      # The evil host: from inside, systemd --user is gone and its D-Bus name
      # refused, while the filtered bus still answers — so the refusal is the
      # filter. The broker starts a launch into the same zone and refuses one
      # into another network with nobody to ask.
      with subtest("hermetic zone: no systemd --user, a filtered bus, the broker as the door"):
          alice("vpn-zone add vmherm /tmp/vmsmoke.conf")
          out = json.loads(alice("vpn-zone status --json"))
          herm = next(n for n in out["networks"] if n["name"] == "vmherm")["hermetic"]
          assert herm == {"value": True, "source": "nix"}, herm
          # What the zone is let besides: nothing, until said.
          zone = next(n for n in out["networks"] if n["name"] == "vmherm")
          assert zone["nix_daemon"] == {"value": False, "source": "default"}, zone
          assert zone["host_files_writable"] == {"value": False, "source": "default"}, zone
          assert out["defaults"]["hermetic"] == {"value": False, "source": "nix"}, out["defaults"]
          alice("sh -c '! vpn-zone hermetic vmherm off'")
          # The broker is socket-activated, and every zone wants its socket:
          # no race with the session (red on main and in CI before).
          alice("vpn-zone up vmherm")
          alice("systemctl --user is-active vpn-zone-broker.socket")
          hp = machine.succeed(f"cat {STATE}/vmherm/zone.pid").strip()
          # Neither the compositor's IPC nor its own socket (LEAK-MODEL §13).
          in_zone(hp, "test ! -e /run/user/1000/niri.wayland-9.4242.sock")
          in_zone(hp, "test ! -e /run/user/1000/wayland-9")
          units = "call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager ListUnits"
          names = "call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListNames"
          alice(f"busctl --user --timeout=5 {units} > /dev/null")
          in_zone(hp, "test ! -e /run/user/1000/systemd/private")
          in_zone(hp, f"sh -c '! busctl --user --timeout=5 {units}'")
          in_zone(hp, "sh -c '! systemctl --user is-system-running'")
          in_zone(hp, f"busctl --user --timeout=5 {names}")
          # Tray icons (owner 2026-09-24: none from Claude Desktop): Electron and
          # Qt own org.kde.StatusNotifierItem-<pid>-<n> first — that name may be
          # taken, KWallet's may not (the patched proxy's `--own=…-*`).
          own = "call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su"
          out = in_zone(hp, f"busctl --user --timeout=5 {own} org.kde.StatusNotifierItem-4242-1 4")
          assert out.strip() == "u 1", out
          in_zone(hp, f"sh -c '! busctl --user --timeout=5 {own} org.kde.kwalletd6 4'")
          in_zone(hp, f"sh -c '! busctl --user --timeout=5 {own} org.kde.StatusNotifierItem-1.evil 4'")
          # The project's state out of the zone's reach (review 2026-09-25):
          # no zone.pid to rewrite, no raw proxy behind the bus filter, no key;
          # the settings and the shims read-only; the host still writes.
          out = in_zone(hp, "ls -A /home/alice/.local/state/vpn-zones")
          assert sorted(out.split()) == [".running", ".throwaway"], out
          for path in [".local/state/vpn-zones/.running/x", ".config/vpn-zones/x", ".local/share/vpn-zones/x"]:
              in_zone(hp, f"sh -c '! touch /home/alice/{path}'")
          alice("touch ~/.config/vpn-zones/from-host && rm ~/.config/vpn-zones/from-host")
          # The host's Nix daemon out of reach (review 2026-09-25): it fetches
          # in the host's network whatever a derivation names.
          machine.succeed("test -S /nix/var/nix/daemon-socket/socket")
          in_zone(hp, "test ! -e /nix/var/nix/daemon-socket/socket")
          # What the host runs from the home, read-only in a hermetic zone
          # (owner, 2026-09-25); the host itself writes there as before.
          for path in [".config/autostart/x.desktop", ".local/share/applications/x.desktop", ".config/systemd/x"]:
              in_zone(hp, f"sh -c '! touch /home/alice/{path}'")
          alice("touch ~/.config/autostart/from-host && rm ~/.config/autostart/from-host")
          # A program started in the zone has the user's own group only: the
          # session's groups open doors (libvirt, docker, /dev/input).
          alice("cat /var/lib/vzdoor/door")
          alice("vpn-zone run vmherm -- sh -c 'id -G > /home/alice/zone-groups; cat /var/lib/vzdoor/door > /home/alice/zone-door 2>&1; true'")
          groups = machine.succeed("cat /home/alice/zone-groups").split()
          assert groups == ["100"], groups
          machine.fail("grep -q open /home/alice/zone-door")
          # In the home: the zone's /tmp is its own (LEAK-MODEL §15).
          in_zone(hp, "env VPN_ZONE_CURRENT=vmherm vpn-zone run vmherm -- touch /home/alice/brokered-same")
          machine.wait_until_succeeds("test -e /home/alice/brokered-same", timeout=30)
          in_zone(hp, "sh -c '! env VPN_ZONE_CURRENT=vmherm vpn-zone run direct -- touch /tmp/brokered-escape'")
          machine.sleep(3)
          machine.fail("test -e /tmp/brokered-escape")
          # "Always" said before for this very program of the store (the
          # broker-always file is what the dialog's third button writes): the
          # launch in another network goes on without a question — there is
          # nobody to ask here, so a question would have been a refusal.
          touch = machine.succeed("readlink -f /run/current-system/sw/bin").strip() + "/touch"
          alice(
              "mkdir -p ~/.config/vpn-zones && "
              f"printf 'vmherm\tunconfined\t%s\n' {touch} >> ~/.config/vpn-zones/broker-always"
          )
          in_zone(hp, f"env VPN_ZONE_CURRENT=vmherm vpn-zone run direct -- {touch} /tmp/brokered-always")
          machine.wait_until_succeeds("test -e /tmp/brokered-always", timeout=30)
          # Only that program: another one is asked about — and refused.
          in_zone(hp, "sh -c '! env VPN_ZONE_CURRENT=vmherm vpn-zone run direct -- mkdir /tmp/brokered-other'")
          machine.sleep(3)
          machine.fail("test -e /tmp/brokered-other")
          # Both decisions are on the record, the escape under the new name.
          out = alice("vpn-zone journal --json")
          assert '"event":"broker","origin":"vmherm","target":"vmherm"' in out, out
          assert '"target":"unconfined","app":"","decision":"refused"' in out, out
          out = alice("vpn-zone doctor vmherm --json")
          assert '{"id":"session-bus","level":"ok"' in out, out

      # The evil host's /tmp (LEAK-MODEL §15): a tmux server — `run-shell` runs
      # on the host, in the host's network —, a listening socket, an abstract
      # one and shared memory. None of it reaches a hermetic zone, whose /tmp,
      # /var/tmp and /dev/shm are its own; the abstract socket is out of reach
      # of every zone (its own network namespace). And a sandbox's bus filter
      # is in the zone's runtime directory, not in the /tmp all zones shared.
      with subtest("hermetic zone: the host's /tmp, /dev/shm and abstract sockets are out of reach"):
          alice("tmux new-session -d -s evil 'sleep 600'")
          machine.wait_until_succeeds("test -S /tmp/tmux-1000/default")
          alice(
              "systemd-run --user --unit=eviltmp socat "
              "UNIX-LISTEN:/tmp/evil.sock,fork OPEN:/tmp/evil-got,creat,append"
          )
          alice(
              "systemd-run --user --unit=evilabs socat "
              "ABSTRACT-LISTEN:vzevil,fork OPEN:/tmp/evil-abs-got,creat,append"
          )
          alice("sh -c 'echo secret > /dev/shm/vzevil && echo secret > /var/tmp/vzevil'")
          machine.wait_until_succeeds("test -S /tmp/evil.sock")
          # On the host all of it answers — otherwise the rest proves nothing.
          alice("tmux -S /tmp/tmux-1000/default ls")
          alice("echo host | socat -T2 - ABSTRACT-CONNECT:vzevil")
          machine.wait_until_succeeds("grep -q host /tmp/evil-abs-got")
          in_zone(hp, "test ! -e /tmp/evil.sock")
          in_zone(hp, "test ! -e /tmp/tmux-1000")
          in_zone(hp, "sh -c '! tmux -S /tmp/tmux-1000/default ls'")
          in_zone(hp, "sh -c '! echo zone | socat -T2 - ABSTRACT-CONNECT:vzevil'")
          in_zone(hp, "test ! -e /dev/shm/vzevil")
          in_zone(hp, "test ! -e /var/tmp/vzevil")
          machine.sleep(1)
          machine.fail("grep -q zone /tmp/evil-abs-got")
          out = alice("vpn-zone doctor vmherm --json")
          assert '{"id":"tmp-sockets","level":"ok"' in out, out
          # Its own, and writable: what the zone puts there stays there.
          in_zone(hp, "sh -c 'touch /tmp/from-zone /dev/shm/from-zone && test -d /tmp/.X11-unix'")
          machine.fail("test -e /tmp/from-zone")
          machine.fail("test -e /dev/shm/from-zone")
          # A sandbox's bus filter: in the zone's runtime directory.
          alice("systemd-run --user --unit=vmsbsleep vpn-zone run vmherm --fs-sandbox -- sleep 60")
          probe = shlex.quote(
              "export XDG_RUNTIME_DIR=/run/user/1000; "
              f"nsenter --preserve-credentials -U -n -m -t {hp} -- "
              "sh -c 'test -S /run/user/1000/vpn-zones/sandbox/*/bus'"
          )
          machine.wait_until_succeeds(f"su -l alice -c {probe}", timeout=30)
          machine.fail("ls -d /tmp/vpn-fs-sandbox-*")
          alice("systemctl --user stop vmsbsleep eviltmp evilabs || true")
          alice("tmux kill-server || true")

      # LEAK-MODEL §2: a sandboxed program (it sees /.flatpak-info) opens a link
      # through the portal's OpenURI. The sandbox's bus filter answers the call
      # itself and hands the link to xdg-open IN THE ZONE — never to the host's
      # portal. The handler is a symlinked entry, which the interception leaves
      # alone, so what runs is exactly what xdg-open picked: it records the link
      # and its network namespace. A file: link is answered and not opened.
      with subtest("sandbox: a link through the portal opens in the zone, a file: link not at all"):
          alice("mkdir -p ~/.local/share/vmurl ~/.local/share/applications ~/.config")
          alice(
              "printf '#!/bin/sh\\necho \"$1\" >> /home/alice/opened-urls\\n"
              "readlink /proc/self/ns/net >> /home/alice/opened-urls\\n' "
              "> ~/.local/share/vmurl/record && chmod 755 ~/.local/share/vmurl/record"
          )
          alice(
              "printf '[Desktop Entry]\\nType=Application\\nName=VM URL\\n"
              "Exec=/home/alice/.local/share/vmurl/record %%u\\n"
              "MimeType=x-scheme-handler/https;\\n' > ~/.local/share/vmurl/vmurl.desktop"
          )
          alice("ln -sfn ~/.local/share/vmurl/vmurl.desktop ~/.local/share/applications/vmurl.desktop")
          alice("printf '[Default Applications]\\nx-scheme-handler/https=vmurl.desktop\\n' > ~/.config/mimeapps.list")
          # xdg-open looks for a scheme handler only in a graphical session
          # (WAYLAND_DISPLAY or DISPLAY set) and goes for console browsers
          # otherwise; the VM has no compositor, only the variable is needed.
          portal = (
              "gdbus call --session --dest org.freedesktop.portal.Desktop "
              "--object-path /org/freedesktop/portal/desktop "
              "--method org.freedesktop.portal.OpenURI.OpenURI"
          )
          # The sandbox's bus works at all in a hermetic zone: a second
          # xdg-dbus-proxy on the zone's own used to refuse every connection.
          alice(
              "vpn-zone run vmherm --fs-sandbox -- gdbus call --session --dest org.freedesktop.DBus "
              "--object-path /org/freedesktop/DBus --method org.freedesktop.DBus.GetId"
          )
          out = alice(f"WAYLAND_DISPLAY=wayland-vmtest vpn-zone run vmherm --fs-sandbox -- {portal} ''' 'https://example.test/from-sandbox' '@a{{sv}} {{}}'")
          assert "/org/freedesktop/portal/desktop/request/" in out, out
          machine.wait_until_succeeds("grep -q from-sandbox /home/alice/opened-urls", timeout=30)
          zone_ns = machine.succeed(f"readlink /proc/{hp}/ns/net").strip()
          host_ns = machine.succeed("readlink /proc/1/ns/net").strip()
          opened = machine.succeed("cat /home/alice/opened-urls")
          assert zone_ns in opened and host_ns not in opened, f"{opened} (zone {zone_ns})"
          out = alice(f"WAYLAND_DISPLAY=wayland-vmtest vpn-zone run vmherm --fs-sandbox -- {portal} ''' 'file:///etc/hostname' '@a{{sv}} {{}}'")
          assert "/org/freedesktop/portal/desktop/request/" in out, out
          machine.sleep(2)
          machine.fail("grep -q hostname /home/alice/opened-urls")
          # WITHOUT a sandbox (libportal, GTK4 with portals): the hermetic
          # zone's own bus filter answers, and asks the broker to open the link
          # in this very zone — no question for the same zone. The broker runs
          # the launch with the session manager's environment: the display
          # variable goes there (see xdg-open above).
          alice("systemctl --user set-environment WAYLAND_DISPLAY=wayland-vmtest")
          alice("systemctl --user stop vpn-zone-broker.service || true")
          out = in_zone(hp, f"{portal} ''' 'https://example.test/from-zone' '@a{{sv}} {{}}'")
          assert "/org/freedesktop/portal/desktop/request/" in out, out
          machine.wait_until_succeeds("grep -q from-zone /home/alice/opened-urls", timeout=30)
          lines = machine.succeed("cat /home/alice/opened-urls").splitlines()
          at = lines.index("https://example.test/from-zone")
          assert lines[at + 1] == zone_ns, f"{lines} (zone {zone_ns})"
          # The same call after an authentication ended with more on the
          # BEGIN line, which the proxy takes as the end: the filter takes it
          # so too, answers, and the link opens in the zone.
          out = in_zone(hp, "${pkgs.python3}/bin/python3 ${rawBegin} https://example.test/raw-begin")
          assert "/org/freedesktop/portal/desktop/request/" in out, out
          machine.wait_until_succeeds("grep -q raw-begin /home/alice/opened-urls", timeout=30)
          lines = machine.succeed("cat /home/alice/opened-urls").splitlines()
          at = lines.index("https://example.test/raw-begin")
          assert lines[at + 1] == zone_ns, f"{lines} (zone {zone_ns})"
          # The zone's bus is still the zone's: names and calls go through.
          in_zone(hp, "busctl --user --timeout=5 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListNames")
          # But not the portals the portal would grant a "host application"
          # without a dialog: it sees our proxy, not the program (review
          # 2026-09-25) — the dynamic launcher installs and starts a launcher
          # on the host. Refused by the filter, whether a portal runs or not.
          launcher = (
              "gdbus call --session --timeout 5 --dest org.freedesktop.portal.Desktop "
              "--object-path /org/freedesktop/portal/desktop "
              "--method org.freedesktop.portal.DynamicLauncher.RequestInstallToken"
          )
          out = in_zone(hp, f"sh -c \"{launcher} vm '@a{{sv}} {{}}' 2>&1 || true\"")
          assert "AccessDenied" in out, out
          # Nor the host's network state: the filter answers for the zone —
          # no name is looked up or tried by the host.
          desk = (
              "gdbus call --session --timeout 5 --dest org.freedesktop.portal.Desktop "
              "--object-path /org/freedesktop/portal/desktop --method "
          )
          out = in_zone(hp, f"{desk}org.freedesktop.portal.ProxyResolver.Lookup https://example.test")
          assert "direct://" in out, out
          out = in_zone(hp, f"{desk}org.freedesktop.portal.NetworkMonitor.CanReach leak.test 443")
          assert "true" in out, out
          alice("systemctl --user unset-environment WAYLAND_DISPLAY")
          alice("vpn-zone down vmherm")
          # An ordinary zone: the sandbox's own proxy over the host's bus, the
          # filter in front of it — the link opens in THAT zone.
          out = alice(f"WAYLAND_DISPLAY=wayland-vmtest vpn-zone run vmsmoke --fs-sandbox -- {portal} ''' 'https://example.test/from-ordinary' '@a{{sv}} {{}}'")
          assert "/org/freedesktop/portal/desktop/request/" in out, out
          machine.wait_until_succeeds("grep -q from-ordinary /home/alice/opened-urls", timeout=30)
          sp = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
          smoke_ns = machine.succeed(f"readlink /proc/{sp}/ns/net").strip()
          lines = machine.succeed("cat /home/alice/opened-urls").splitlines()
          at = lines.index("https://example.test/from-ordinary")
          assert lines[at + 1] == smoke_ns, f"{lines} (zone {smoke_ns})"
          alice("vpn-zone down vmsmoke")

      # --- A network through an interface of the host (CONTAINERS §3.3) -----
      # No tunnel: pasta attached to the app namespace and bound to one host
      # interface. The server must see the machine's own eth1 address, and a
      # zone bound to eth0 must not reach the server at all — the binding, not
      # the host's routing table, decides where packets go.
      with subtest("host-interface zone: out through eth1 only"):
          server.succeed(
              "systemd-run --unit=hello-lan socat "
              f"TCP-LISTEN:8090,bind={server_ip},fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          alice("printf '[HostInterface]\\nInterface = eth1\\n' > /tmp/vmlan.conf")
          alice("vpn-zone add vmlan /tmp/vmlan.conf")
          alice("vpn-zone up vmlan")
          lpid = machine.succeed(f"cat {STATE}/vmlan/zone.pid").strip()
          links = in_zone(lpid, "ip -o link show")
          assert len(links.strip().splitlines()) == 2 and ": awg0" in links, links
          out = in_zone(lpid, "ip -4 route show default")
          assert "dev awg0" in out, out
          out = in_zone(lpid, f"socat -T10 - TCP:{server_ip}:8090")
          assert "peer=192.168.1.1" in out, f"server saw someone else: {out}"
          # The app namespace's filter holds here too.
          rules = in_zone_root(lpid, "nft list ruleset")
          assert 'oifname "awg0" accept' in rules and "policy drop" in rules, rules
          machine.wait_until_succeeds(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; vpn-zone check vmlan'",
              timeout=30,
          )
          out = alice("vpn-zone doctor vmlan --json")
          assert '"worst":"fail"' not in out, out
          alice("vpn-zone down vmlan")

      # A dummy interface with an address and no way to the server: bound to
      # it, the zone must not reach the server even though the host itself
      # routes there through eth1.
      with subtest("host-interface zone bound to another interface cannot reach eth1's network"):
          machine.succeed(
              "ip link add vmdummy type dummy && ip addr add 10.77.0.1/24 dev vmdummy "
              "&& ip link set vmdummy up"
          )
          alice("printf '[HostInterface]\\nInterface = vmdummy\\n' > /tmp/vmwan.conf")
          alice("vpn-zone add vmwan /tmp/vmwan.conf")
          alice("vpn-zone up vmwan")
          wpid = machine.succeed(f"cat {STATE}/vmwan/zone.pid").strip()
          in_zone(wpid, f"sh -c '! timeout 10 socat -T5 - TCP:{server_ip}:8090'")
          alice("vpn-zone down vmwan")

      # The interface deleted under a running zone: pasta binding a socket to
      # an interface that is gone connects it UNBOUND (review 2026-09-24), so
      # the holder watches the interface and takes the zone down at once.
      with subtest("host-interface zone: its interface deleted, the zone goes down"):
          alice("vpn-zone up vmwan")
          wpid = machine.succeed(f"cat {STATE}/vmwan/zone.pid").strip()
          machine.succeed("ip link del vmdummy")
          machine.wait_until_fails(f"test -e /proc/{wpid}", timeout=15)
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              "systemctl --user is-active vpn-zone@vmwan'"
          )

      with subtest("host-interface zone: a missing interface refuses to come up"):
          alice("printf '[HostInterface]\\nInterface = nosuchif0\\n' > /tmp/vmnone.conf")
          alice("vpn-zone add vmnone /tmp/vmnone.conf")
          machine.fail(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; vpn-zone up vmnone'"
          )
          machine.fail(f"test -f {STATE}/vmnone/ready")
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
