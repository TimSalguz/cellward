# The launch window (window/), seen on a real compositor: headless sway, the
# picker with a few zones and containers to fill both columns, a screenshot of
# the window as it comes up. The screenshot is the point — this is how its
# look is checked without a screen — so the test keeps it in its output:
#
#   nix-build tests/vm-window.nix -A driver -o vm-window-driver
#   mkdir -p /tmp/vm-window && ./vm-window-driver/bin/nixos-test-driver -o /tmp/vm-window
#
# In CI it is a smoke: the window comes up, stays up, and closed starts nothing
# (the same check is a subtest of tests/vm.nix).
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
    name = "vpn-zones-vm-window";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [ "${pins.home-manager}/nixos" ];
        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          linger = true;
          # A zone for the hotkey menu's part: the offline one needs nothing
          # but a user namespace.
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
          programs.vpn-zones.enable = true;
          # The window menu on a key and our windows floating: the snippet
          # sway is started with below.
          programs.vpn-zones.desktop = {
            windowMenu.key = "Mod+Shift+Z";
            sway.enable = true;
          };
          home.stateVersion = "25.05";
        };
        environment.systemPackages = [
          pkgs.sway
          pkgs.grim
          pkgs.wtype
          pkgs.foot
        ];
        fonts.packages = [ pkgs.dejavu_fonts ];
        virtualisation.memorySize = 1536;
      };

    testScript = ''
      import json
      import shlex

      def alice(cmd):
          return machine.succeed(
              "su -l alice -c " + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_for_unit("user@1000.service")

      # What the columns show: zones (a directory with a config is a zone to
      # the picker), a named sandbox, a profile.
      state = "/home/alice/.local/state/vpn-zones"
      for zone in ["nl", "de", "work-vpn"]:
          alice(f"mkdir -p {state}/{zone} && printf '[Interface]\\n' > {state}/{zone}/config.conf")
      alice("mkdir -p ~/.local/state/vpn-sandboxes/общая/home ~/.local/state/vpn-profiles/банк")

      alice(
          "systemd-run --user --unit=vmsway "
          "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
          "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
          "sway -c /home/alice/.config/sway/vpn-zones.conf"
      )
      machine.wait_until_succeeds("ls /run/user/1000/sway-ipc.*.sock", timeout=60)
      display = machine.succeed(
          "ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | head -1"
      ).strip()

      with subtest("the launch window comes up, stays up, and closed starts nothing"):
          alice(
              f"systemd-run --user --unit=vmpick --setenv=WAYLAND_DISPLAY={display} "
              "vpn-zone-pick --label 'Огненный лис' --id firefox -- touch /tmp/started"
          )
          machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
          machine.sleep(3)
          machine.succeed("pgrep -x vpn-zone-window")
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/launch-window.png")
          machine.copy_from_vm("/tmp/launch-window.png", "")
          # The keyboard: to the container column, two rows down, tick
          # "always" — and the screenshot shows where the choice went. wtype
          # makes a virtual keyboard per call, and a key sent before the window
          # has its keymap is lost: -s waits first.
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Right -k Down -k Down -k space")
          machine.sleep(1)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/launch-window-keys.png")
          machine.copy_from_vm("/tmp/launch-window-keys.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
          machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=15)
          machine.sleep(1)
          machine.fail("test -e /tmp/started")

      def find(node, app_id):
          if node.get("app_id") == app_id:
              return node
          for child in node.get("nodes", []) + node.get("floating_nodes", []):
              found = find(child, app_id)
              if found:
                  return found
          return None

      # The hotkey menu (docs/WINDOW-FRAME.md §7б): a program in a zone opens a
      # window; `focused` finds its launch through the compositor's IPC — the
      # pid of the window, up its parents to the registry —, and `window-menu`
      # offers what can be done with it.
      swaysock = machine.succeed("ls /run/user/1000/sway-ipc.*.sock | head -1").strip()
      with subtest("the focused window's zone and program; the hotkey menu"):
          alice(
              f"systemd-run --user --unit=vmfoot --setenv=WAYLAND_DISPLAY={display} "
              "vpn-zone run offline -- foot"
          )
          machine.wait_until_succeeds(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q foot",
              timeout=60,
          )
          # The window came through wl-sandbox's Wayland proxy (§8): the
          # compositor's pid of it is the proxy's, which runs on the host, not
          # dumpable — and still the launch and its zone are found, through the
          # supervisor the proxy is a child of.
          tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
          foot = find(tree, "foot")
          assert foot is not None, tree
          comm = machine.succeed(f"cat /proc/{foot['pid']}/comm").strip()
          assert comm == "vz-wl-proxy", comm
          out = alice(f"SWAYSOCK={swaysock} vpn-zone focused --json")
          assert '"zone":"offline"' in out and '"program":"foot"' in out, out
          out = alice(f"SWAYSOCK={swaysock} vpn-zone focused --bar")
          assert '"class":"zone-offline"' in out, out
          alice(
              f"systemd-run --user --unit=vmmenu --setenv=WAYLAND_DISPLAY={display} "
              f"--setenv=SWAYSOCK={swaysock} vpn-zone window-menu"
          )
          machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
          machine.sleep(2)
          # Its app id, for a compositor's window rule.
          alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree | grep -q '\"app_id\": *\"vpn-zone-window\"'")
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/window-menu.png")
          machine.copy_from_vm("/tmp/window-menu.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
          machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=15)
          # Closed: nothing done — foot is still there.
          machine.succeed("pgrep -x foot")

      # The key of programs.vpn-zones.desktop.windowMenu.key, pressed on the
      # compositor: the menu comes up by itself, floating by the window rule.
      with subtest("the window menu's key of the module opens the menu, floating"):
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -M logo -M shift -k z -m shift -m logo")
          machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
          machine.sleep(2)
          tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
          menu = find(tree, "vpn-zone-window")
          assert menu is not None and menu["type"] == "floating_con", menu
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/window-menu-key.png")
          machine.copy_from_vm("/tmp/window-menu-key.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
          machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=15)
          machine.succeed("pgrep -x foot")
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
