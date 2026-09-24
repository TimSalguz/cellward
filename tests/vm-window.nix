# The launch window (window/), seen on a real compositor: headless sway, the
# picker with a few zones and containers to fill both columns, a screenshot of
# the window as it comes up. The screenshot is the point — this is how its
# look is checked without a screen — so the test keeps it in its output:
#
#   nix-build tests/vm-window.nix -A driver -o vm-window-driver
#   ./vm-window-driver/bin/nixos-test-driver -o /tmp/vm-window   # launch-window.png
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
        };
        home-manager.useGlobalPkgs = true;
        home-manager.useUserPackages = true;
        home-manager.users.alice = {
          imports = [ ../module ];
          programs.vpn-zones.enable = true;
          home.stateVersion = "25.05";
        };
        environment.systemPackages = [
          pkgs.sway
          pkgs.grim
          pkgs.wtype
        ];
        fonts.packages = [ pkgs.dejavu_fonts ];
        virtualisation.memorySize = 1536;
      };

    testScript = ''
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
          "sway -c /dev/null"
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
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
