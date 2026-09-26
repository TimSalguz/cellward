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
    name = "cellward-vm-window";

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
          programs.cellward.enable = true;
          # The window menu on a key and our windows floating: the snippet
          # sway is started with below.
          programs.cellward.desktop = {
            windowMenu.key = "Mod+Shift+Z";
            sway.enable = true;
          };
          # The zone's border around foot below: a colour nothing else on
          # the screen has, and a width that is not the default.
          programs.cellward.frame = {
            colors.offline = "#ff00ff";
            width = 6;
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
      # the picker), a named sandbox, a profile. The sandbox where the layout
      # before one name per container kept it: the picker's first look moves
      # it in with the rest.
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
              "cellward run offline -- foot"
          )
          machine.wait_until_succeeds(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q foot",
              timeout=60,
          )
          # The window came through wl-sandbox's Wayland proxy (§8): the
          # compositor's pid of it is the supervisor's — it makes the
          # connection upstream —, which runs on the host with the proxy for a
          # child; and still the zone is found, through the supervisor's
          # children.
          tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
          foot = find(tree, "foot")
          assert foot is not None, tree
          comm = machine.succeed(f"cat /proc/{foot['pid']}/comm").strip()
          assert comm == "vz-wl-sandbox", comm
          machine.succeed(f"pgrep -x -P {foot['pid']} vz-wl-proxy")
          out = alice(f"SWAYSOCK={swaysock} cellward focused --json")
          assert '"zone":"offline"' in out and '"program":"foot"' in out, out
          out = alice(f"SWAYSOCK={swaysock} cellward focused --bar")
          assert '"class":"zone-offline"' in out, out
          alice(
              f"systemd-run --user --unit=vmmenu --setenv=WAYLAND_DISPLAY={display} "
              f"--setenv=SWAYSOCK={swaysock} cellward window-menu"
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

      # The zone's frame (docs/WINDOW-FRAME.md §0а, rust/src/wl_frame.rs),
      # seen on the screen: the proxy draws it INSIDE the window geometry —
      # sway clips a tiled window to it —, in the colour and width the module
      # declared, with the title strip (rust/src/wl_title.rs) under the top
      # border; and what is inside is foot's own, the window's size less the
      # frame: foot was told that size and drew it.
      border = (255, 0, 255)
      width = 6
      # The title strip's height (wl_title::HEIGHT), and the colour of its
      # text on magenta: near-black, the one that stands out more.
      title = 20
      ink = (0x14, 0x14, 0x14)

      def view(app_id):
          """Where sway shows a window's contents, in logical pixels."""
          tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
          node = find(tree, app_id)
          assert node is not None, tree
          r, w = node["rect"], node["window_rect"]
          return r["x"] + w["x"], r["y"] + w["y"], w["width"], w["height"]

      def shot(name):
          """The screen as grim sees it (device pixels): a PNG to look at,
          a PPM to read pixels from."""
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/{name}.png")
          machine.copy_from_vm(f"/tmp/{name}.png", "")
          alice(f"WAYLAND_DISPLAY={display} grim -t ppm /tmp/{name}.ppm")
          machine.copy_from_vm(f"/tmp/{name}.ppm", "")
          ppm = machine.out_dir / f"{name}.ppm"
          magic, size, _depth, pixels = ppm.read_bytes().split(b"\n", 3)
          ppm.unlink()
          assert magic == b"P6", magic
          w, h = map(int, size.split())

          def at(x, y):
              if not (0 <= x < w and 0 <= y < h):
                  return None
              i = (y * w + x) * 3
              return tuple(pixels[i : i + 3])

          return at

      def span(at, x, y, dx, dy):
          """The run of the border's colour through (x, y) along (dx, dy):
          where it starts, and how long it is."""
          assert at(x, y) == border, (x, y, at(x, y))
          back = 0
          while back < 64 and at(x - (back + 1) * dx, y - (back + 1) * dy) == border:
              back += 1
          ahead = 0
          while ahead < 64 and at(x + (ahead + 1) * dx, y + (ahead + 1) * dy) == border:
              ahead += 1
          return (x - back * dx, y - back * dy), back + ahead + 1

      def framed(at, x, y, w, h, scale=1, slack=0, top=width):
          """The frame on all four sides of the view (x, y, w, h) at `scale`,
          starting at the view's edge: `width` wide at the sides and the
          bottom, `top` at the top (the border and the title strip under it,
          measured right of the title's text), and not a pixel of it across
          the middle: that is foot's, (w - 2 width) wide."""
          d = lambda v: int(round(v * scale))
          b = width / 2
          sides = [
              (d(x + b), d(y + h / 2), 1, 0, (d(x), d(y + h / 2)), width),
              (d(x + w - b), d(y + h / 2), -1, 0, (d(x + w) - 1, d(y + h / 2)), width),
              (d(x + w * 3 / 4), d(y + top / 2), 0, 1, (d(x + w * 3 / 4), d(y)), top),
              (d(x + w / 2), d(y + h - b), 0, -1, (d(x + w / 2), d(y + h) - 1), width),
          ]
          for sx, sy, dx, dy, edge, want in sides:
              start, n = span(at, sx, sy, dx, dy)
              assert abs(n - want * scale) <= slack, (sx, sy, n, want * scale)
              assert abs(start[0] - edge[0]) + abs(start[1] - edge[1]) <= slack, (start, edge)
          row = d(y + top + (h - top - width) / 2)
          inside = [at(d(x + width) + slack + i, row) for i in range(d(w - 2 * width) - 2 * slack)]
          assert border not in inside, "the border inside the window"

      def lettering(at, x, y, w, scale=1):
          """The pixels of the title strip that are not the zone's colour:
          its text. The strip is under the top border, between the sides."""
          d = lambda v: int(round(v * scale))
          rows = range(d(y + width), d(y + width + title))
          cols = range(d(x + width), d(x + w - width))
          return [(c, r) for r in rows for c in cols if at(c, r) != border]

      def titled(at, x, y, w, scale=1):
          """The zone's name in the strip: text there, at the left after the
          pad, and nowhere else; and crisp — drawn at this scale, not
          blurred up from another: a fifth of its pixels or more at least
          three quarters ink (the line drawn at 1 and 1.5 has 26% and 41%;
          drawn at 1 and stretched to 1.5 bilinearly, 6%). On magenta the
          ink's share of a pixel is in its red: 255 - 235 × share."""
          text = lettering(at, x, y, w, scale)
          assert len(text) > 100 * scale * scale, f"no text in the title strip: {len(text)}"
          strong = sum(1 for c, r in text if at(c, r)[0] <= 255 - 0.75 * (255 - ink[0]))
          assert strong >= 0.2 * len(text), f"the text is not crisp: {strong} of {len(text)}"
          left = min(c for c, _ in text)
          pad = round((x + width + 8) * scale)
          # The first glyph's own side bearing: 2 pixels at 1.
          assert pad - 1 <= left <= pad + 4 * scale, (left, pad)
          assert max(c for c, _ in text) < round((x + w / 2) * scale), "text across the strip"

      with subtest("the zone's border and title: inside the window, the declared colour and width"):
          x, y, w, h = view("foot")
          at = shot("frame")
          # The top is the border and the title strip, both the zone's
          # colour; foot's content starts under them: it asked for the size
          # it was told, the window's less the frame, and drew exactly that.
          framed(at, x, y, w, h, top=width + title)
          titled(at, x, y, w)

      # Fullscreen: the border stays, the title strip goes, and foot gets its
      # room.
      with subtest("in fullscreen the border stays, the title goes"):
          alice(f"SWAYSOCK={swaysock} swaymsg '[app_id=foot] fullscreen enable'")
          machine.sleep(2)
          x, y, w, h = view("foot")
          framed(shot("frame-fullscreen"), x, y, w, h)
          alice(f"SWAYSOCK={swaysock} swaymsg '[app_id=foot] fullscreen disable'")
          machine.sleep(2)
          x, y, w, h = view("foot")
          framed(shot("frame-fullscreen-back"), x, y, w, h, top=width + title)

      # A fractional scale: the border is a stretched pixel, the same colour
      # to its edges, and `width` logical pixels wide — give or take a device
      # pixel where an edge falls between two. The text is drawn anew at 1.5
      # (wp_fractional_scale_v1): its strokes have pixels of the ink itself.
      with subtest("the frame at a fractional scale, after the resize it brings"):
          output = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_outputs -r"))[0]["name"]
          alice(f"SWAYSOCK={swaysock} swaymsg output {output} scale 1.5")
          machine.sleep(3)
          x, y, w, h = view("foot")
          at = shot("frame-scale")
          framed(at, x, y, w, h, scale=1.5, slack=1, top=width + title)
          titled(at, x, y, w, scale=1.5)
          alice(f"SWAYSOCK={swaysock} swaymsg output {output} scale 1")
          machine.sleep(3)

      # The switch (`cellward frame hide`, for sharing the screen) is read
      # when a program connects: a window opened after it has no border, one
      # opened before keeps it — now half the screen wide, the border
      # following the resize.
      with subtest("hidden, a new window comes up without the border"):
          alice("cellward frame hide")
          alice(
              f"systemd-run --user --unit=vmbare --setenv=WAYLAND_DISPLAY={display} "
              "cellward run offline -- foot --app-id bare"
          )
          machine.wait_until_succeeds(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"bare\"'",
              timeout=60,
          )
          machine.sleep(2)
          at = shot("frame-hidden")
          x, y, w, h = view("bare")
          assert at(x + 1, y + h // 2) != border, "a border though hidden"
          assert at(x + w // 2, y + 1) != border, "a border though hidden"
          x, y, w, h = view("foot")
          framed(at, x, y, w, h, top=width + title)
          titled(at, x, y, w)
          alice("cellward frame show")
          alice("systemctl --user stop vmbare")
          machine.wait_until_fails(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"bare\"'",
              timeout=30,
          )
          machine.sleep(2)

      # `cellward frame title hover` (read at launch): the strip takes no
      # room and is not there until the pointer comes to the window's top
      # edge — which this seat, with no pointer device at all, never does
      # (the coming out is the proxy's unit test). The status names it.
      with subtest("a hover title takes no room and is not shown by itself"):
          alice("cellward frame title hover")
          out = alice("cellward status --json")
          assert '"frame_title":{"value":"hover","source":"local"}' in out, out
          alice(
              f"systemd-run --user --unit=vmhover --setenv=WAYLAND_DISPLAY={display} "
              "cellward run offline -- foot --app-id hover"
          )
          machine.wait_until_succeeds(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"hover\"'",
              timeout=60,
          )
          machine.sleep(2)
          at = shot("frame-hover")
          x, y, w, h = view("hover")
          framed(at, x, y, w, h)
          # The older window keeps its strip: the mode is its launch's.
          x, y, w, h = view("foot")
          framed(at, x, y, w, h, top=width + title)
          alice("cellward frame title default")
          alice("systemctl --user stop vmhover")
          machine.wait_until_fails(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"hover\"'",
              timeout=30,
          )
          machine.sleep(2)

      # The key of programs.cellward.desktop.windowMenu.key, pressed on the
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

      # "Close" from the menu signals the window's pid, which behind the proxy
      # is the supervisor's: it passes the signal on to the program, and goes
      # after it, the proxy and the sockets with it — it does not die alone
      # and leave foot running (review 2026-09-25). Entries: pin, restart,
      # close; the third is picked by its number.
      with subtest("the window menu's close ends the program behind the proxy, and its supervisor"):
          tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
          sup = find(tree, "foot")["pid"]
          machine.succeed(f"test -e /run/user/1000/vpn-zones/wayland/offline/wl-sandbox-{sup}")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -M logo -M shift -k z -m shift -m logo")
          machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
          machine.sleep(2)
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k 3 -k Return")
          machine.wait_until_fails("pgrep -x foot", timeout=30)
          machine.wait_until_fails(f"test -e /proc/{sup}", timeout=30)
          machine.wait_until_fails("pgrep -x vz-wl-proxy", timeout=30)
          machine.fail(f"test -e /run/user/1000/vpn-zones/wayland/offline/wl-sandbox-{sup}")
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
