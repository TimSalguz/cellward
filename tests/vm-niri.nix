# The zone's frame on niri (docs/WINDOW-FRAME.md, «Скругление по niri и
# снаружи рамки»): niri nested in headless sway — its winit backend, software
# GL —, foot in a zone on it, the frame's round corners checked by the
# pixels of niri's own screen (grim through its screencopy):
#
#   - niri clips the window at its radius (`clip-to-geometry true`), and the
#     corners inside the frame, `frame radius niri`, follow the same circle:
#     niri's radius less the border at the bottom, square at the top under
#     the title strip;
#   - without niri's clipping, the frame's own corners
#     (`frame outer-radius niri`) cut the frame round themselves, on the fly;
#   - a new radius in niri's config reaches the open window.
#
#   nix-build tests/vm-niri.nix -A driver -o vm-niri-driver
#   mkdir -p /tmp/vm-niri && ./vm-niri-driver/bin/nixos-test-driver -o /tmp/vm-niri
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
    name = "cellward-vm-niri";

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
          # The frame in one colour nothing else on the screen has (`full`),
          # a border of 4 under the title strip, and the corners inside it
          # niri's.
          programs.cellward.frame = {
            colors.offline = "#ff00ff";
            width = 4;
            style = "full";
            title = "always";
            radius = "niri";
          };
          home.stateVersion = "25.05";
        };
        environment.systemPackages = [
          pkgs.sway
          pkgs.niri
          pkgs.grim
          pkgs.foot
        ];
        # sway plain: no bar, no borders — niri's window is all of its
        # output.
        environment.etc."vm-niri/sway.conf".text = ''
          default_border none
          output * bg #202020 solid_color
        '';
        # niri's software GL (llvmpipe) comes from here.
        hardware.graphics.enable = true;
        fonts.packages = [ pkgs.dejavu_fonts ];
        virtualisation.memorySize = 2048;
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

      alice(
          "systemd-run --user --unit=vmsway "
          "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
          "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
          "sway -c /etc/vm-niri/sway.conf"
      )
      machine.wait_until_succeeds("ls /run/user/1000/sway-ipc.*.sock", timeout=60)
      sway = machine.succeed(
          "ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | head -1"
      ).strip()

      def niri_config(radius, clip):
          """niri's config with one rule for every window: `radius`, clipped
          or not. A new file moved over the old one, as home-manager
          replaces a link: niri reloads it, cellward's supervisor sees it."""
          text = (
              'output "winit" {\n    scale 1.0\n}\n'
              "layout {\n    gaps 16\n    focus-ring {\n        off\n    }\n"
              "    border {\n        off\n    }\n"
              "    default-column-width { fixed 640; }\n}\n"
              "prefer-no-csd\n"
              "animations {\n    off\n}\n"
              "hotkey-overlay {\n    skip-at-startup\n}\n"
              "window-rule {\n"
              f"    geometry-corner-radius {radius}\n"
              f"    clip-to-geometry {'true' if clip else 'false'}\n"
              "}\n"
          )
          alice(
              "mkdir -p ~/.config/niri && printf %s "
              + shlex.quote(text)
              + " > ~/.config/niri/config.kdl.new"
              + " && mv ~/.config/niri/config.kdl.new ~/.config/niri/config.kdl"
          )

      niri_config(20, True)
      alice(
          f"systemd-run --user --unit=vmniri --setenv=WAYLAND_DISPLAY={sway} "
          "--setenv=LIBGL_ALWAYS_SOFTWARE=1 niri"
      )
      try:
          machine.wait_until_succeeds(
              "ls /run/user/1000 | grep -qE '^niri\\..*\\.sock$'", timeout=90
          )
      finally:
          print(alice("journalctl --user -u vmniri --no-pager | tail -40 || true"))
      nested = machine.succeed(
          f"ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | grep -vx {sway} | head -1"
      ).strip()
      assert nested, "niri has no socket"

      MAGENTA = (255, 0, 255)

      class Shot:
          """A screen's pixels: `at(x, y)` the colour there (None off it),
          `size` its width and height."""

          def __init__(self, pixels, w, h):
              self.pixels = pixels
              self.size = (w, h)

          def __call__(self, x, y):
              w, h = self.size
              if not (0 <= x < w and 0 <= y < h):
                  return None
              i = (y * w + x) * 3
              return tuple(self.pixels[i : i + 3])

      def shot(name):
          """niri's screen (device pixels): a PNG to look at, a PPM to read."""
          alice(f"WAYLAND_DISPLAY={nested} grim /tmp/{name}.png")
          machine.copy_from_vm(f"/tmp/{name}.png", "")
          alice(f"WAYLAND_DISPLAY={nested} grim -t ppm /tmp/{name}.ppm")
          machine.copy_from_vm(f"/tmp/{name}.ppm", "")
          ppm = machine.out_dir / f"{name}.ppm"
          magic, size, _depth, pixels = ppm.read_bytes().split(b"\n", 3)
          ppm.unlink()
          assert magic == b"P6", magic
          w, h = map(int, size.split())
          return Shot(pixels, w, h)

      def frame_box(at):
          """The frame's pixels' bounds: the window's geometry, whatever
          niri's clipping took of its corners."""
          w, h = at.size
          xs, ys = [], []
          for y in range(0, h):
              for x in range(0, w, 2):
                  if at(x, y) == MAGENTA:
                      xs.append(x)
                      ys.append(y)
          assert xs, "no frame on niri's screen"
          x0, x1 = min(xs), max(xs)
          # A step of 2 may miss the last column.
          while at(x0 - 1, (min(ys) + max(ys)) // 2) == MAGENTA:
              x0 -= 1
          while at(x1 + 1, (min(ys) + max(ys)) // 2) == MAGENTA:
              x1 += 1
          return x0, min(ys), x1, max(ys)

      def settled(name, check, tries=20):
          """Shot again until `check` of it passes: a change is laid with the
          program's next commit, niri reloads its config by itself."""
          for n in range(tries):
              at = shot(name)
              try:
                  return check(at)
              except AssertionError:
                  if n == tries - 1:
                      raise
                  machine.sleep(1)
          raise AssertionError(f"{name}: never tried")

      alice(
          f"systemd-run --user --unit=vmfoot --setenv=WAYLAND_DISPLAY={nested} "
          "cellward run offline -- foot --app-id niri-foot"
      )

      def framed(at):
          box = frame_box(at)
          x0, y0, x1, y1 = box
          mid = (y0 + y1) // 2
          # A border of 4 at scale 1, the title strip of 20 under the top.
          assert at(x0 + 3, mid) == MAGENTA and at(x0 + 4, mid) != MAGENTA, (box, at(x0 + 4, mid))
          assert at((x0 + x1) // 2, y0 + 23) == MAGENTA, box
          return box

      box = settled("niri-frame", framed, tries=60)
      x0, y0, x1, y1 = box

      with subtest("niri clips the frame round, the corners inside follow its circle"):
          def clipped(at):
              assert framed(at) == box
              for c in [(x0, y0), (x1, y0), (x0, y1), (x1, y1)]:
                  assert at(*c) != MAGENTA, ("a corner not clipped", c, at(*c))
              # Inside niri's curve: the title strip at the top...
              assert at(x0 + 7, y0 + 7) == MAGENTA, at(x0 + 7, y0 + 7)
              # ... and at the bottom our corner over the content's, on the
              # same circle (niri's 20 less the border: 16) — three pixels
              # in from the content's corner cut, twelve in foot's.
              assert at(x0 + 7, y1 - 7) == MAGENTA, at(x0 + 7, y1 - 7)
              assert at(x1 - 7, y1 - 7) == MAGENTA, at(x1 - 7, y1 - 7)
              assert at(x0 + 12, y1 - 12) != MAGENTA, at(x0 + 12, y1 - 12)
              # The top one square: the strip over it is niri's to round.
              assert at(x0 + 4, y0 + 24) != MAGENTA, at(x0 + 4, y0 + 24)

          settled("niri-clipped", clipped)

      with subtest("without niri's clipping, the frame's own corners cut it round, on the fly"):
          niri_config(20, False)

          def square(at):
              assert framed(at) == box
              for c in [(x0, y0), (x1, y0), (x0, y1), (x1, y1)]:
                  assert at(*c) == MAGENTA, ("a corner round", c, at(*c))

          settled("niri-unclipped", square)
          alice("cellward frame outer-radius niri")

          def round_outside(at):
              assert framed(at) == box
              for c in [(x0, y0), (x1, y0), (x0, y1), (x1, y1)]:
                  assert at(*c) != MAGENTA, ("a corner square", c, at(*c))
              assert at(x0 + 7, y0 + 7) == MAGENTA, "the strip's end"
              assert at(x1 - 7, y0 + 7) == MAGENTA, "the strip's end"
              assert at(x0 + 3, y1 - 12) == MAGENTA, "the border's ring"
              assert at(x1 - 3, y1 - 12) == MAGENTA, "the border's ring"
              # The strips short of the pieces, the pieces the frame: no gap
              # along the edges.
              for x in range(x0 + 20, x1 - 20):
                  assert at(x, y0 + 1) == MAGENTA and at(x, y1 - 1) == MAGENTA, x
              for y in range(y0 + 24, y1 - 20):
                  assert at(x0 + 1, y) == MAGENTA and at(x1 - 1, y) == MAGENTA, y

          settled("niri-outer", round_outside)

      with subtest("a new radius in niri's config reaches the open window"):
          niri_config(12, True)

          def smaller(at):
              assert framed(at) == box
              # 12 less the border: 8 — three pixels in from the content's
              # corner is foot's now.
              assert at(x0 + 7, y1 - 7) != MAGENTA, at(x0 + 7, y1 - 7)
              assert at(x0 + 5, y1 - 5) == MAGENTA, at(x0 + 5, y1 - 5)

          settled("niri-radius-12", smaller)
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
