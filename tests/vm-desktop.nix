# A desktop as people have it: niri (nested in headless sway, its winit
# backend, software GL), hermetic containers by default, a real Firefox —
# on Wayland and through a container's own X server — and a real pointer
# (tests/vm-pointer.py on sway's seat, which niri reads as its input).
#
# What it holds (tests/vm-desktop.py):
#
#   - Firefox launched again into the container it runs in opens a window
#     of the running one — no "Firefox is already running";
#   - Firefox with the real home open in another network: the launch asks
#     to open it there, and does;
#   - the permission panel on a real Firefox window (in its container's own
#     X server) and on foot, clicked as people click: a click too soon is
#     none and is seen to be none, one after resting on the button answers;
#   - AyuGram, and KeePassXC closed into a tray,
#     launched again from the menu: no question, its window to the front;
#   - a throwaway container: a second program joins the open one and sees
#     its home, a new one is empty, the launch window offers the open one,
#     a program open there launched again asks — and the home goes with
#     its last program;
#   - the permissions in the launch window: one changed there is kept in
#     the container's record and shown as it is at the next launch;
#   - Firefox in a container layered over the home and in one of its own;
#     TeamSpeak too where its tarball is given (`teamspeakSrc`).
#
# One scenario: `--argstr only <words of its name>`.
#
# Screenshots of every step land in the test's output:
#
#   nix-build tests/vm-desktop.nix -A test -o vm-desktop
#   ls vm-desktop/*.png
#
# Interactive (needs /dev/kvm where the driver runs), watched live through
# VNC — in the driver's prompt `test_script()` runs it all:
#
#   nix-build tests/vm-desktop.nix -A driverInteractive --arg vnc true -o vm-desktop-driver
#   ./vm-desktop-driver/bin/nixos-test-driver
#   vncviewer localhost:5901        # once sway is up: the screen niri draws on
#
# A video of a run instead: `--arg record true`, then vm-desktop/desktop.mp4.
{
  system ? builtins.currentSystem,
  # Only the scenarios whose names contain this (tests/vm-desktop.py).
  only ? "",
  # TeamSpeak's tarball (`teamspeak-client.tar.gz` of teamspeak6-client),
  # where its own server cannot be reached from here: without it TeamSpeak
  # is left out, and so are its scenarios.
  teamspeakSrc ? null,
  # To watch it live: a VNC server on the screen, at localhost:5901 of the
  # machine the driver runs on (driverInteractive; see the header).
  vnc ? false,
  # A video of the whole run, `desktop.mp4` in the output.
  record ? false,
}:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    # TeamSpeak, the one program here that is not free: by name.
    config.allowUnfreePredicate = p: (p.pname or "") == "teamspeak6-client";
    overlays = [ ];
  };

  test = pkgs.testers.runNixOSTest {
    name = "cellward-vm-desktop";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [ "${pins.home-manager}/nixos" ];
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
        home-manager.useGlobalPkgs = true;
        home-manager.useUserPackages = true;
        home-manager.users.alice = {
          imports = [ ../module ];
          programs.cellward.enable = true;
          # As on the owner's desktop: every network hermetic, the title
          # strip always there.
          programs.cellward.hermetic.default = true;
          programs.cellward.frame = {
            colors.offline = "#ff00ff";
            colors.host = "#00c8ff";
            width = 4;
            title = "always";
          };
          home.stateVersion = "25.05";
        };
        environment.systemPackages =
          # What the owner runs in a container layered over the home.
          pkgs.lib.optional (teamspeakSrc != null) (
            pkgs.teamspeak6-client.overrideAttrs { src = teamspeakSrc; }
          )
          ++ [
          pkgs.sway
          pkgs.niri
          pkgs.grim
          # Quiet on its own: no first-run pages, studies or checks — the
          # connections the tests see are the ones they ask for.
          (pkgs.firefox.override {
            extraPolicies = {
              DisableTelemetry = true;
              DisableFirefoxStudies = true;
              DontCheckDefaultBrowser = true;
              DisableAppUpdate = true;
              CaptivePortal = false;
              OverrideFirstRunPage = "";
              OverridePostUpdatePage = "";
              NoDefaultBookmarks = true;
            };
          })
          pkgs.foot
          pkgs.jq
          pkgs.wayvnc
          pkgs.wf-recorder
          # The owner's messenger: a Telegram Desktop fork, one copy per profile.
          pkgs.ayugram-desktop
          # A tray (StatusNotifierWatcher and host): the messenger hides
          # there when its window is closed, as on the owner's desktop.
          pkgs.waybar
          # A program that closes into the tray with no account to log in.
          pkgs.keepassxc
        ];
        environment.etc."vm-desktop/waybar.json".text = builtins.toJSON {
          layer = "top";
          position = "bottom";
          height = 24;
          modules-right = [ "tray" ];
        };
        environment.etc."vm-desktop/sway.conf".text = ''
          default_border none
          output * bg #202020 solid_color
          output * resolution 1600x1000
        '';
        hardware.graphics.enable = true;
        fonts.packages = [ pkgs.dejavu_fonts ];
        virtualisation.memorySize = 4096;
        # The screen to the driver's machine (`vnc`): QEMU's user network.
        virtualisation.forwardPorts = pkgs.lib.optional vnc {
          from = "host";
          host.port = 5901;
          guest.port = 5900;
        };
        networking.firewall.allowedTCPPorts = pkgs.lib.optional vnc 5900;
        virtualisation.cores = 4;
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.0.2.1";
            prefixLength = 24;
          }
        ];
        networking.defaultGateway = {
          address = "192.168.1.2";
          interface = "eth1";
        };
      };

    nodes.peer =
      { pkgs, ... }:
      {
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.0.2.2";
            prefixLength = 24;
          }
        ];
        networking.firewall.allowedTCPPorts = [ 8080 ];
        environment.etc."permission-http/index.html".text = "<h1>permission-ok</h1>\n";
        systemd.services.permission-http = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory /etc/permission-http";
        };
      };

    testScript = ''
      import os
      os.environ["VM_DESKTOP_ONLY"] = ${builtins.toJSON only}
      os.environ["VM_DESKTOP_VNC"] = ${builtins.toJSON (if vnc then "1" else "")}
      os.environ["VM_DESKTOP_RECORD"] = ${builtins.toJSON (if record then "1" else "")}
      POINTER = "${pkgs.python3}/bin/python3 ${./vm-pointer.py}"
      exec(open("${./vm-desktop.py}").read())
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
