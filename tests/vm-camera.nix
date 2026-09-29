# The black camera, stage 0 (rust/src/camera.rs): the device alone, where it
# has to work — mounted by a user in a user namespace of their own, as FUSE,
# and taken for a V4L2 camera by programs there:
#
#   - a program of ours as Chromium and Firefox are one (vm-camera-client.py):
#     what it is, a format, buffers mapped, five frames taken — black —, by
#     a blocking DQBUF and by poll(2) on a non-blocking file;
#   - ffmpeg's v4l2 input, a real one, three frames of it;
#   - nothing spent while nobody streams: the server's CPU time the same
#     after seconds of it; streaming ten seconds, under 1 % of a core;
#   - given to a container (stage A): the main home's camera `black` (Nix),
#     a launch into the offline network under headless sway — its
#     supervisor serves the camera, the program in the container takes black
#     frames from /dev/video0; the server in namespaces of its own with an
#     empty root, and gone with the program.
#
#   nix-build tests/vm-camera.nix -A driver -o vm-camera-driver
#   ./vm-camera-driver/bin/nixos-test-driver
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
    name = "cellward-vm-camera";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [ "${pins.home-manager}/nixos" ];
        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          linger = true;
          # The offline network: a user namespace, nothing more.
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
          # The main home's programs get a black camera.
          programs.cellward.main.permissions.camera = "black";
          home.stateVersion = "25.05";
        };
        environment.systemPackages = [
          pkgs.python3
          pkgs.ffmpeg-headless
          pkgs.util-linux
          pkgs.sway
        ];
        environment.etc."vm-camera/client.py".source = ./vm-camera-client.py;
        environment.etc."vm-camera/sway.conf".text = "default_border none\n";
        fonts.packages = [ pkgs.dejavu_fonts ];
        virtualisation.memorySize = 1536;
      };

    testScript = ''
      import shlex

      def alice(cmd):
          return machine.succeed("su -l alice -c " + shlex.quote(cmd))

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_for_unit("user@1000.service")
      core = alice("command -v vpn-zone-core").strip()

      def in_namespace(body):
          """`body` in a user namespace and a mount namespace of alice's
          own, the camera mounted there first and its server's pid in
          $server; the server stopped after."""
          script = (
              "set -eu\n"
              "mkdir -p /tmp/cam\n"
              f"{core} camera-serve --mount /tmp/cam 2>/tmp/camera-serve.log &\n"
              "server=$!\n"
              "for i in $(seq 100); do [ -e /tmp/cam/video0 ] && break; sleep 0.1; done\n"
              "test -f /tmp/cam/video0\n"
              + body
              + "\numount /tmp/cam; wait $server || true\n"
          )
          try:
              return alice("unshare --user --map-root-user --mount sh -c " + shlex.quote(script))
          finally:
              print(machine.execute("cat /tmp/camera-serve.log")[1])

      with subtest("a program takes black frames, waiting and by poll"):
          out = in_namespace(
              "stat -c '%F %s' /tmp/cam/video0\n"
              "python3 /etc/vm-camera/client.py /tmp/cam/video0 block\n"
              "python3 /etc/vm-camera/client.py /tmp/cam/video0 poll\n"
          )
          print(out)
          assert "regular file" in out, out
          assert "block: 5 black frames of 640x480" in out, out
          assert "poll: 5 black frames of 640x480" in out, out

      with subtest("ffmpeg's v4l2 input takes it for a camera"):
          out = in_namespace(
              "ffmpeg -hide_banner -loglevel error -f v4l2 -input_format yuyv422 "
              "-video_size 640x480 -i /tmp/cam/video0 -frames:v 3 -f rawvideo -y /tmp/f.yuv\n"
              "python3 -c \"d = open('/tmp/f.yuv', 'rb').read(); "
              "assert len(d) == 3 * 640 * 480 * 2, len(d); "
              "assert set(d[0::2]) == {16} and set(d[1::2]) == {128}; "
              "print('ffmpeg: 3 black frames')\"\n"
          )
          assert "ffmpeg: 3 black frames" in out, out

      with subtest("nothing spent while nobody streams"):
          out = in_namespace(
              "python3 /etc/vm-camera/client.py /tmp/cam/video0 block >/dev/null\n"
              "cpu() { awk '{ print $14 + $15 }' /proc/$server/stat; }\n"
              "before=$(cpu); sleep 3; after=$(cpu)\n"
              "echo \"idle: $before $after\"\n"
              "test \"$before\" = \"$after\"\n"
          )
          assert "idle:" in out, out

      # What a program streaming for ten seconds costs the server: its CPU
      # time over them, fifty black frames. Printed, and held to under 1 %
      # of a core — the owner's worry (2026-09-29) was a black window's load.
      with subtest("streaming costs the server next to nothing"):
          out = in_namespace(
              "cpu() { awk '{ print $14 + $15 }' /proc/$server/stat; }\n"
              "before=$(cpu)\n"
              "python3 /etc/vm-camera/client.py /tmp/cam/video0 block 50\n"
              "after=$(cpu)\n"
              "echo \"streaming: $before $after $(getconf CLK_TCK)\"\n"
          )
          print(out)
          line = next(l for l in out.splitlines() if l.startswith("streaming:"))
          before, after, tick = map(int, line.split()[1:])
          spent = (after - before) / tick
          print(f"the server spent {spent:.3f} s of CPU over 10 s of streaming")
          assert spent <= 0.1, spent

      def user(cmd):
          return alice("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)

      with subtest("a container's black camera: served by its launch's supervisor"):
          out = user("cellward status --json")
          assert '"camera_mode":{"value":"black","source":"nix"}' in out, out
          user(
              "systemd-run --user --unit=vmsway "
              "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
              "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
              "sway -c /etc/vm-camera/sway.conf"
          )
          machine.wait_until_succeeds("ls /run/user/1000/sway-ipc.*.sock", timeout=60)
          display = machine.succeed(
              "ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | head -1"
          ).strip()
          # A program that holds the camera open a while, for the server to
          # be looked at.
          user(
              f"systemd-run --user --unit=vmcamhold --setenv=WAYLAND_DISPLAY={display} "
              "cellward run offline -- python3 -c "
              "\"import time; f = open('/dev/video0', 'rb'); time.sleep(60)\""
          )
          machine.wait_until_succeeds("pgrep -u alice -f 'camera-serve --from'", timeout=60)
          server = machine.succeed("pgrep -u alice -f 'camera-serve --from' | head -1").strip()
          # Out of the program's reach and of the host's: a user namespace of
          # its own, an empty root.
          mine = machine.succeed(f"readlink /proc/{server}/ns/user").strip()
          shell = machine.succeed("readlink /proc/self/ns/user").strip()
          assert mine != shell, (mine, shell)
          machine.wait_until_succeeds(f"test -z \"$(ls -A /proc/{server}/root/)\"", timeout=30)
          user("systemctl --user stop vmcamhold")
          # Gone with the program: nothing left of the camera.
          machine.wait_until_fails(f"test -e /proc/{server}", timeout=30)
          # The program takes black frames from /dev/video0, in the container.
          out = user(
              f"WAYLAND_DISPLAY={display} cellward run offline -- sh -c "
              "'stat -c %F /dev/video0; python3 /etc/vm-camera/client.py /dev/video0 block'"
          )
          print(out)
          assert "regular file" in out, out
          assert "block: 5 black frames of 640x480" in out, out
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
