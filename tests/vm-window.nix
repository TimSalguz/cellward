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
          # The network is asked about, as by default: on the program's own
          # window (tests/vm-window-question.py); the rest is offline.
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
        # The host's own network (`cellward run host`) is pasta by the
        # host's routes: a default one, to nowhere.
        networking.defaultGateway = {
          address = "192.168.1.254";
          interface = "eth1";
        };
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
          # A new container (the eighth row, «Новый контейнер со своим
          # домом…», below «Без изоляции» since 2026-09-29): its name is
          # typed beside the buttons, and the lists keep the height the
          # window fitted itself to.
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 8")
          machine.sleep(1)
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 proba")
          machine.sleep(1)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/launch-window-name.png")
          machine.copy_from_vm("/tmp/launch-window-name.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
          machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=15)
          machine.sleep(1)
          machine.fail("test -e /tmp/started")

      # A launch through the picker that does not start (2026-09-28): the
      # picker watches it and tells the person — before, it ended with a
      # line in the session's log and nothing on the screen. The program is
      # a layer container's, bound to offline: no question, and nothing in
      # the instance by that name (code 127, said by wl-sandbox). No
      # notification daemon here: the picker's own line in its unit's log
      # is looked at.
      with subtest("a launch through the picker that does not start is said"):
          alice("cellward container create vmnostart --home layer")
          alice("cellward container set vmnostart network offline")
          alice("cellward container assign vmnosuch vmnostart")
          alice(
              f"systemd-run --user --unit=vmpickfail --setenv=WAYLAND_DISPLAY={display} "
              "vpn-zone-pick --label 'Нет такой' --id vmnosuch -- /nonexistent/vmnosuch"
          )
          # By the picker's name, not its unit: a line it writes as it ends
          # may reach the journal after the unit is gone, without the unit's
          # name on it (red once in CI).
          machine.wait_until_succeeds(
              "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 journalctl --user -t vpn-zone-pick' "
              "| grep -q '«Нет такой» не запущена'",
              timeout=90,
          )
          said = alice("journalctl --user -t vpn-zone-pick -o cat")
          assert "код 127" in said or "в контейнере её не" in said, said
          machine.fail("pgrep -x vpn-zone-window")
          alice("cellward container unassign vmnosuch")
          alice("cellward container rm vmnostart")

      # The cellward window (2026-09-28): the network monitor and the
      # containers, on the launch window's toolkit, in place of cellward-gui's
      # kdialog menus. Screenshots of both tabs, a container chosen by key.
      with subtest("the cellward window: the network monitor and the containers"):
          alice(
              f"systemd-run --user --unit=vmpanel --setenv=WAYLAND_DISPLAY={display} "
              "cellward-gui monitor"
          )
          # `[v]`: the test's own shell has the words on its command line.
          machine.wait_until_succeeds("pgrep -f '[v]pn-zone-window panel'", timeout=30)
          machine.sleep(3)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/panel-network.png")
          machine.copy_from_vm("/tmp/panel-network.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Right -k Down")
          machine.sleep(2)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/panel-containers.png")
          machine.copy_from_vm("/tmp/panel-containers.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Right")
          machine.sleep(2)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/panel-zones.png")
          machine.copy_from_vm("/tmp/panel-zones.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Right")
          machine.sleep(2)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/panel-settings.png")
          machine.copy_from_vm("/tmp/panel-settings.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
          machine.wait_until_fails("pgrep -f '[v]pn-zone-window panel'", timeout=15)
          # The data it reads.
          out = alice("cellward _panel")
          assert "network\toffline\toffline\t1\t" in out, out

      # The question of what a program with a home of its own may see
      # (2026-09-28): the window's checklist, guarded — a screenshot, and
      # Esc is «nothing» (exit 1).
      with subtest("the file access question is the window's checklist"):
          tools = alice(
              "grep -m1 -o '/nix/store/[^ \"]*-vpn-zone-tools.json' "
              "$(readlink -f $(command -v cellward))"
          ).strip()
          win = machine.succeed(f"grep -o '\"window\": *\"[^\"]*\"' {tools}").strip().split('"')[3]
          machine.succeed(
              "printf 'title\\tДоступ к файлам: Проба\\nnote\\tЧто показать программе?\\n"
              "guard\\t1500\\ncheck\\tdownloads\\tЗагрузки (~/Downloads)\\t\\n"
              "check\\thome\\tВЕСЬ домашний каталог\\tdanger\\n' > /tmp/checklist.req"
          )
          alice(
              f"systemd-run --user --unit=vmchecklist --setenv=WAYLAND_DISPLAY={display} "
              f"-p StandardInput=file:/tmp/checklist.req {win} checklist"
          )
          machine.wait_until_succeeds("pgrep -f '[v]pn-zone-window checklist'", timeout=30)
          machine.sleep(3)
          alice(f"WAYLAND_DISPLAY={display} grim /tmp/checklist.png")
          machine.copy_from_vm("/tmp/checklist.png", "")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
          machine.wait_until_fails("pgrep -f '[v]pn-zone-window checklist'", timeout=15)
          code = alice("systemctl --user show -p ExecMainStatus --value vmchecklist || true").strip()
          assert code in ("1", ""), code

      def find(node, app_id):
          if node.get("app_id") == app_id:
              return node
          for child in node.get("nodes", []) + node.get("floating_nodes", []):
              found = find(child, app_id)
              if found:
                  return found
          return None

      # The zone's frame in the checks below is the `full` style
      # (rust/src/wl_title.rs, Look): the zone's colour itself, one colour to
      # the border's edges — the pixels stages 2 and 3 were checked by. The
      # default since 2026-09-28 is `soft`, two calmer tones;
      # tests/vm-window-looks.py shows it next to this one, and the other
      # looks.
      alice("cellward frame style full")

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
      # The row of buttons at the strip's right end (wl_title::LOOK and the
      # fullscreen button, `frame fullscreen-button one`): four of 24 —
      # their glyphs are not the title's text.
      buttons = 4 * 24

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

      def settled(name, check, tries=15):
          """The screen shot again until `check` of it passes: a frame
          changed on the fly (step 6 of docs/PERMISSIONS.md §11.15) is laid
          anew with the program's next commit, after it has laid itself out
          for the size the new frame leaves it."""
          for n in range(tries):
              at = shot(name)
              try:
                  check(at)
                  return at
              except AssertionError:
                  if n == tries - 1:
                      raise
                  machine.sleep(1)

      def lettering(at, x, y, w, scale=1):
          """The pixels of the title strip that are not the zone's colour:
          its text. The strip is under the top border, between the sides,
          and its text before the row of buttons."""
          d = lambda v: int(round(v * scale))
          rows = range(d(y + width), d(y + width + title))
          cols = range(d(x + width), d(x + w - width - buttons))
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

      # Fullscreen (the owner's defaults, 2026-09-29): the border stays, the
      # title strip goes, and foot gets its room — after the zone's name over
      # the top of the content for a moment on the way in
      # (`frame fullscreen notice`: here long enough to be seen whatever the
      # machine's pace, then none).
      with subtest("in fullscreen the border stays; the zone's name for a moment, then no title"):
          def fullscreen(on):
              state = "enable" if on else "disable"
              alice(f"SWAYSOCK={swaysock} swaymsg '[app_id=foot] fullscreen {state}'")
              machine.sleep(2)

          alice("cellward frame fullscreen notice 30")
          machine.sleep(2)
          fullscreen(True)
          x, y, w, h = view("foot")

          def labelled(at):
              """The name over the top of the content, under the border: its
              text drawn (it was not, shown in the commit that ends sway's
              transaction — `Window::after_commit`)."""
              framed(at, x, y, w, h, top=width + title)
              titled(at, x, y, w)

          settled("frame-fullscreen-label", labelled)
          fullscreen(False)
          # Without the name: the border alone.
          alice("cellward frame fullscreen notice 0")
          machine.sleep(2)
          fullscreen(True)
          x, y, w, h = view("foot")
          settled("frame-fullscreen", lambda at: framed(at, x, y, w, h))
          fullscreen(False)
          # `always` in fullscreen: the strip in its room, with its text.
          alice("cellward frame fullscreen title always")
          machine.sleep(2)
          fullscreen(True)
          x, y, w, h = view("foot")
          settled("frame-fullscreen-always", labelled)
          fullscreen(False)
          alice("cellward frame fullscreen title default")
          alice("cellward frame fullscreen notice default")
          machine.sleep(2)
          x, y, w, h = view("foot")
          settled(
              "frame-fullscreen-back", lambda at: framed(at, x, y, w, h, top=width + title)
          )

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

      # `cellward frame title hover`: the strip takes no room and is not
      # there until the pointer comes to the window's top edge — which this
      # seat, with no pointer device at all, never does (the coming out is
      # the proxy's unit test). The status names it. On the fly: the older
      # window's strip goes too, and both have one again with the mode back.
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

          def strips(top):
              def check(at):
                  for app in ("hover", "foot"):
                      x, y, w, h = view(app)
                      framed(at, x, y, w, h, top=top)

              return check

          settled("frame-hover", strips(width))
          alice("cellward frame title default")
          settled("frame-hover-back", strips(width + title))
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
          # Offline, the program is in the main home's instance (stage 1 of
          # the container design): its sockets go by the instance's key,
          # instance::key("main:offline").
          wl = "/run/user/1000/vpn-zones/wayland/i-242da5417b1a1e19"
          machine.succeed(f"test -e {wl}/wl-sandbox-{sup}")
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -M logo -M shift -k z -m shift -m logo")
          machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
          machine.sleep(2)
          alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k 3 -k Return")
          machine.wait_until_fails("pgrep -x foot", timeout=30)
          machine.wait_until_fails(f"test -e /proc/{sup}", timeout=30)
          machine.wait_until_fails("pgrep -x vz-wl-proxy", timeout=30)
          machine.fail(f"test -e {wl}/wl-sandbox-{sup}")

      # A network's «Подключение» (docs/PERMISSIONS.md §11.16): `ask` — a
      # launch into it while it is down asks first, in the launch window,
      # and the program waits; «Не подключать» (Enter, the safe answer)
      # refuses the launch, said; «Подключить» starts the network (this
      # one's tunnel is a stand-in: it does not come up, and that is said).
      with subtest("a network that asks: the question before it comes up"):
          alice("cellward connection de ask")
          out = alice("cellward status --json")
          assert '"connection":{"value":"ask","source":"local"}' in out, out

          def launch_into_de(unit):
              alice(
                  f"systemd-run --user --unit={unit} --setenv=WAYLAND_DISPLAY={display} "
                  "cellward run de -- foot --app-id conn"
              )
              machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=60)
              machine.sleep(2)
              alice(f"WAYLAND_DISPLAY={display} grim /tmp/{unit}.png")
              machine.copy_from_vm(f"/tmp/{unit}.png", "")

          def answer(downs):
              keys = " ".join(["-s 3500 -k Down"] * downs)
              alice(f"WAYLAND_DISPLAY={display} wtype {keys} -s 3500 -k Return")
              machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=30)

          def said(unit):
              return f"journalctl --no-pager _SYSTEMD_USER_UNIT={unit}.service"

          launch_into_de("connect-refused")
          answer(0)
          machine.wait_until_succeeds(
              said("connect-refused") + " | grep -F 'не запущена: сеть de не подключена'",
              timeout=30,
          )
          machine.fail(said("connect-refused") + " | grep -F 'поднимаю зону de'")

          def sorry_closed():
              """The refusal's own window («Запуск остановлен», kdialog)
              closed: it would take the keys meant for the next question."""
              machine.wait_until_succeeds("pgrep -x kdialog", timeout=30)
              machine.succeed("pkill -x kdialog")
              machine.wait_until_fails("pgrep -x kdialog", timeout=30)

          sorry_closed()
          launch_into_de("connect-agreed")
          answer(1)
          machine.wait_until_succeeds(
              said("connect-agreed") + " | grep -F 'поднимаю зону de'", timeout=30
          )
          machine.wait_until_succeeds(
              said("connect-agreed") + " | grep -F 'зона de не поднимается'", timeout=90
          )
          sorry_closed()
          assert find(json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r")), "conn") is None
          alice("cellward connection de default")

      # The frame's buttons, dragging and resizing (docs/WINDOW-FRAME.md §8,
      # "Этап 3"), with a pointer: a file of its own, exec()'d in these
      # globals, and the virtual pointer it drives (tests/vm-pointer.py).
      POINTER = "${pkgs.python3}/bin/python3 ${./vm-pointer.py}"
      exec(open("${./vm-window-buttons.py}").read())

      # A container's focus policy (rust/src/wl_focus.rs): a program in a
      # zone that asks for the focus again and again after one click
      # (tests/vm-activate.py), under input, allow and notify.
      ACTIVATE = "${pkgs.python3}/bin/python3 ${./vm-activate.py}"
      exec(open("${./vm-window-focus.py}").read())

      # The network question on the program's own window (docs/FIREWALL.md
      # §4.3.1): a panel of the proxy's, a hasty click none, «Запретить» a
      # rule, «Разрешить…» the launch window on the launch's compositor.
      exec(open("${./vm-window-question.py}").read())

      # A daemon the program leaves behind (stage 3 of the container design,
      # rust/src/profile.rs `supervise`): in its instance's pid namespace an
      # orphan goes to the launch's profile-run, not to the instance's pid 1
      # — and stays below the supervisor, whose close reaches it.
      with subtest("close reaches a daemon the program left, through the pid namespace"):
          alice(
              f"systemd-run --user --unit=vmfootd --setenv=WAYLAND_DISPLAY={display} "
              "cellward run offline -- bash -c "
              "'(exec sleep 600.401 </dev/null >/dev/null 2>&1 &); "
              "exec foot --app-id footd'"
          )
          machine.wait_until_succeeds(
              f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q footd",
              timeout=60,
          )
          # A sleep of a duration of its own: NixOS's coreutils goes by
          # argv[0], so `exec -a <name> sleep` would be no sleep.
          daemon = machine.succeed("pgrep -u alice -f '^sleep 600.401'").split()[0]
          tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
          sup = find(tree, "footd")["pid"]
          machine.succeed(f"kill -TERM {sup}")
          machine.wait_until_fails(f"test -e /proc/{daemon}", timeout=30)
          machine.wait_until_fails(f"test -e /proc/{sup}", timeout=30)

      # The frame's looks (docs/WINDOW-FRAME.md §8, «Вид рамки»): the full
      # style and the soft one taken on the fly, round corners and square
      # again, the tag, and each look of the buttons — a screenshot of each
      # in the output.
      exec(open("${./vm-window-looks.py}").read())
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
