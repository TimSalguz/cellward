# The black camera, stage 0 (rust/src/camera.rs): the device alone, where it
# has to work — mounted by a user in a user namespace of their own, as FUSE,
# and taken for a V4L2 camera by programs there:
#
#   - a program of ours as Chromium and Firefox are one (vm-camera-client.py):
#     what it is, a format, buffers mapped, five frames taken — black —, by
#     a blocking DQBUF and by poll(2) on a non-blocking file;
#   - ffmpeg's v4l2 input, a real one, three frames of it;
#   - nothing spent while nobody streams: the server's CPU time the same
#     after seconds of it.
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
        };
        home-manager.useGlobalPkgs = true;
        home-manager.useUserPackages = true;
        home-manager.users.alice = {
          imports = [ ../module ];
          programs.cellward.enable = true;
          home.stateVersion = "25.05";
        };
        environment.systemPackages = [
          pkgs.python3
          pkgs.ffmpeg-headless
          pkgs.util-linux
        ];
        environment.etc."vm-camera/client.py".source = ./vm-camera-client.py;
      };

    testScript = ''
      import shlex

      def alice(cmd):
          return machine.succeed("su -l alice -c " + shlex.quote(cmd))

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("home-manager-alice.service")
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
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
