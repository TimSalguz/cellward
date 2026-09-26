# A hermetic zone's PipeWire (docs/LEAK-MODEL.md §20, rust/src/pw_context.rs,
# module/wireplumber/policy.lua): a real PipeWire and WirePlumber for the user
# in the VM, with the policy of the NixOS module — switched on by its single
# entry, programs.cellward.enable, as a machine does it —, a sink and a
# microphone that are null devices (the VM has no sound card), and the
# offline zone — hermetic by default, and needing nothing but a user
# namespace.
#
# What is asserted, from inside the zone: its pipewire-0 is the security
# context's socket and never the host's raw one (a PipeWire restart
# included); it sees its own streams and the sink, not the host's streams,
# not the sink's ports, not the link factory; it plays; a sink's monitor
# records nothing; the microphone is not there on "no" and is on "yes" — and
# taken back on "no" while recording; a duplex device is never recorded
# from (its capture ports are a monitor); an earlier run's "yes" left in the
# metadata never decides for a zone brought up on "no"; a virtual sink it
# makes is destroyed and never becomes the default; an audio manager gets
# the raw socket, and the doctor says so loudly.
#
#   nix-build tests/vm-audio.nix -A driver -o vm-audio-driver
#   ./vm-audio-driver/bin/nixos-test-driver
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

  # A null device as the daemon itself makes it: owned by no client.
  # `priority`: which one WirePlumber takes as the default.
  nullDevice = name: class: priority: {
    factory = "adapter";
    args = {
      "factory.name" = "support.null-audio-sink";
      "node.name" = name;
      "node.description" = name;
      "media.class" = class;
      "priority.session" = priority;
      "audio.position" = [
        "FL"
        "FR"
      ];
      "object.linger" = true;
    };
  };

  test = pkgs.testers.runNixOSTest {
    name = "cellward-vm-audio";

    nodes.machine =
      { ... }:
      {
        imports = [
          "${pins.home-manager}/nixos"
          ../module/nixos.nix
        ];
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
        services.pipewire = {
          enable = true;
          pulse.enable = true;
          wireplumber.enable = true;
          extraConfig.pipewire."90-vm-devices" = {
            "context.objects" = [
              (nullDevice "vm-sink" "Audio/Sink" 2000)
              (nullDevice "vm-mic" "Audio/Source/Virtual" 2000)
              # Never the default: the zone's streams go to vm-sink.
              (nullDevice "vm-duplex" "Audio/Duplex" 1)
            ];
          };
        };
        # The single entry (module/entry.nix), as a machine switches cellward
        # on: the policy under test comes on by itself with WirePlumber, the
        # home-manager module for alice by itself too, and the kernel modules
        # of a zone are loaded at boot.
        programs.cellward.enable = true;
        # The policy's own log lines, for a failure to be read.
        systemd.user.services.wireplumber.environment.WIREPLUMBER_DEBUG = "2,s-vpn-zones:4";
        home-manager.useGlobalPkgs = true;
        home-manager.useUserPackages = true;
        home-manager.users.alice.home.stateVersion = "26.05";
        virtualisation.memorySize = 1536;
      };

    testScript = ''
      import json
      import shlex

      STATE = "/home/alice/.local/state/vpn-zones"

      def alice(cmd):
          return machine.succeed(
              "su -l alice -c " + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )

      def alice_any(cmd):
          """Output whatever the exit code."""
          return machine.execute(
              "su -l alice -c " + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )[1]

      def zone(cmd):
          return alice("cellward run offline -- " + cmd)

      def parse(out):
          return json.loads(out[out.index("["):])

      def host_dump():
          return parse(alice("timeout 20 pw-dump"))

      def zone_dump():
          return parse(zone("timeout 20 pw-dump"))

      def nodes(objs):
          return {
              o["info"]["props"].get("node.name"): o["id"]
              for o in objs
              if o["type"] == "PipeWire:Interface:Node" and o.get("info")
          }

      def linked(objs, out_name, in_name):
          """A link from the node `out_name` to the node `in_name`."""
          n = nodes(objs)
          if out_name not in n or in_name not in n:
              return False
          return any(
              o["type"] == "PipeWire:Interface:Link"
              and o.get("info")
              and o["info"]["output-node-id"] == n[out_name]
              and o["info"]["input-node-id"] == n[in_name]
              for o in objs
          )

      def logs():
          """What to read when something here fails: the policy's, the
          helper's and the zone's programs' lines, and the host's clients."""
          print(machine.execute(
              "journalctl --no-pager _UID=1000 | grep -v -E 'su\\[|pam_unix' | tail -150"
          )[1])
          print(alice_any("pw-cli ls Client"))
          print(alice_any("pw-cli ls Node"))

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_for_unit("user@1000.service")

      with subtest("the single entry: the home-manager module, a zone's kernel modules"):
          alice("command -v cellward && command -v cw && command -v vpn-zone")
          for module in ["amneziawg", "wireguard", "nf_tables"]:
              machine.succeed(f"grep -q '^{module} ' /proc/modules")

      with subtest("PipeWire, WirePlumber and the policy are up"):
          alice("systemctl --user start pipewire.service pipewire-pulse.service wireplumber.service")
          try:
              machine.wait_until_succeeds(
                  "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 pw-metadata -n vpn-zones' "
                  "| grep -q vpn-zones.policy",
                  timeout=60,
              )
          except Exception:
              logs()
              raise
          n = nodes(host_dump())
          assert "vm-sink" in n and "vm-mic" in n and "vm-duplex" in n, n

      with subtest("the zone's pipewire-0 is the restricted one, never the host's"):
          zone("true")
          try:
              machine.wait_until_succeeds(f"grep -qx active {STATE}/offline/pipewire-context.state", timeout=30)
          except Exception:
              logs()
              raise
          mounts = zone("cat /proc/self/mountinfo")
          assert "/pipewire-context /run/user/1000/pipewire-0 " in mounts, mounts
          zone("test ! -e /run/user/1000/pipewire-0-manager")
          # A client of the zone gets through at all.
          try:
              print(zone("timeout 20 pw-cli info 0"))
          except Exception:
              logs()
              raise
          out = json.loads(alice("cellward status --json"))
          z = next(n for n in out["networks"] if n["name"] == "offline")
          assert z["audio_manager"] == {"value": False, "source": "default"}, z
          assert z["hermetic"]["value"] is True, z
          out = json.loads(alice_any("cellward doctor offline --json"))
          checks = next(z for z in out["zones"] if z["name"] == "offline")["checks"]
          pw = [c for c in checks if c["id"] == "pipewire"]
          assert pw and pw[0]["level"] == "ok", checks
          assert not any(c["id"] == "socket" and "pipewire-0" in c["detail"] for c in checks), checks

      with subtest("the zone sees its own streams and the sink, and plays"):
          alice(
              "systemd-run --user --unit=hostplay pw-play --raw --target vm-sink "
              "-P node.name=host-player /dev/urandom"
          )
          machine.wait_until_succeeds(
              "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 pw-dump' | grep -q host-player"
          )
          alice(
              "systemd-run --user --unit=zoneplay cellward run offline -- "
              "pw-play --raw -P node.name=vz-player /dev/zero"
          )
          for _ in range(60):
              objs = host_dump()
              if linked(objs, "vz-player", "vm-sink"):
                  break
              machine.sleep(1)
          else:
              logs()
              raise Exception("the zone's playback was never linked to the sink")
          seen = zone_dump()
          names = nodes(seen)
          print(f"what the zone sees: {sorted(k for k in names if k)}")
          assert "vz-player" in names and "vm-sink" in names, names
          assert "host-player" not in names, names
          assert "vm-mic" not in names, names
          kinds = {o["type"] for o in seen}
          assert "PipeWire:Interface:Link" not in kinds, kinds
          assert "PipeWire:Interface:Device" not in kinds, kinds
          assert "PipeWire:Interface:Module" not in kinds, kinds
          for o in seen:
              props = (o.get("info") or {}).get("props") or {}
              if o["type"] == "PipeWire:Interface:Client":
                  assert props.get("pipewire.sec.engine") == "vpn-zone", o
              if o["type"] == "PipeWire:Interface:Factory":
                  name = o["info"].get("name") or props.get("factory.name")
                  assert name == "client-node", o
              if o["type"] == "PipeWire:Interface:Port":
                  assert props.get("node.id") != names["vm-sink"], o
          # Nothing of the host's to destroy or link: the sink stays.
          alice_any(f"cellward run offline -- timeout 10 pw-cli destroy {names['vm-sink']}")
          alice_any("cellward run offline -- timeout 10 pw-link vm-sink vz-player")
          objs = host_dump()
          assert "vm-sink" in nodes(objs), "the zone destroyed the sink"
          assert not linked(objs, "vm-sink", "vz-player"), "the zone made a link"

      with subtest("a sink's monitor records nothing"):
          out = zone(
              "sh -c 'timeout 5 pw-record --raw --target vm-sink "
              "-P stream.capture.sink=true -P node.name=vz-monitor - | wc -c'"
          )
          assert out.strip() == "0", f"the zone recorded the host's sound: {out}"

      with subtest("the microphone as the zone's switch says"):
          alice("cellward microphone offline no")
          machine.sleep(3)
          assert "vm-mic" not in nodes(zone_dump())
          out = zone(
              "sh -c 'timeout 5 pw-record --raw --target vm-mic -P node.name=vz-mic - | wc -c'"
          )
          assert out.strip() == "0", f"recorded with the microphone off: {out}"
          alice("cellward microphone offline yes")
          for _ in range(30):
              if "vm-mic" in nodes(zone_dump()):
                  break
              machine.sleep(1)
          else:
              logs()
              raise Exception("the microphone did not appear on yes")
          out = zone(
              "sh -c 'timeout 5 pw-record --raw --target vm-mic -P node.name=vz-mic - | wc -c'"
          )
          assert int(out.strip()) > 10000, f"nothing recorded with the microphone on: {out}"
          # A duplex device is a sink to WirePlumber: what a capture of it
          # gets is its monitor — what the host plays there — microphone or
          # not. (A plain capture aimed at it is no capture of it: WirePlumber
          # takes it for a sink, and the stream goes to the default source —
          # the microphone, rightly recorded on "yes".)
          out = zone(
              "sh -c 'timeout 5 pw-record --raw --target vm-duplex "
              "-P stream.capture.sink=true -P node.dont-fallback=true "
              "-P node.name=vz-duplex - | wc -c'"
          )
          assert out.strip() == "0", f"the zone recorded a duplex device's monitor: {out}"
          # Taken back while recording: the link goes at once.
          alice(
              "systemd-run --user --unit=zonerec cellward run offline -- "
              "sh -c 'pw-record --raw --target vm-mic -P node.name=vz-rec - > /dev/null'"
          )
          for _ in range(60):
              if linked(host_dump(), "vm-mic", "vz-rec"):
                  break
              machine.sleep(1)
          else:
              raise Exception("the recording was never linked")
          alice("cellward microphone offline no")
          for _ in range(30):
              if not linked(host_dump(), "vm-mic", "vz-rec"):
                  break
              machine.sleep(1)
          else:
              logs()
              raise Exception("the microphone stayed linked after no")
          alice("systemctl --user stop zonerec.service || true")

      with subtest("an earlier run's yes never decides for a zone brought up on no"):
          # The key outlives the zone's helper: WirePlumber keeps it. The
          # helper publishes this run's value before the socket goes out.
          mic_key = "pw-metadata -n vpn-zones 0 vpn-zones.microphone.offline"
          alice("cellward microphone offline yes")
          machine.wait_until_succeeds(
              "su -l alice -c " + shlex.quote("XDG_RUNTIME_DIR=/run/user/1000 " + mic_key)
              + " | grep -q \"value:'yes'\"",
              timeout=30,
          )
          alice("systemctl --user stop zoneplay.service || true")
          alice("cellward down offline")
          alice("cellward microphone offline no")
          out = alice(mic_key)
          assert "value:'yes'" in out, f"no stale yes to test against: {out}"
          # Recorded from the first moment the zone's socket answers.
          out = zone(
              "sh -c 'timeout 30 sh -c \"until pw-cli info 0 >/dev/null 2>&1; do sleep 0.05; done\"; "
              "timeout 4 pw-record --raw --target vm-mic -P node.name=vz-stale - | wc -c'"
          )
          assert out.strip() == "0", f"recorded by an earlier run's yes: {out}"
          out = alice(mic_key)
          assert "value:'no'" in out, out

      with subtest("the microphone by the container of each client"):
          # Each client of the zone gets a key of its own, by the container
          # of the program that connected (rust/src/pw_context.rs,
          # rust/src/origin.rs): a container's yes records while its zone
          # says no, the zone's own programs do not, and a container's no
          # stands against the zone's yes. A client is held until its key
          # comes, so it sees at once what its container may.
          alice("cellward microphone offline no")
          alice("cellward container create vmpwmic --home layer")
          alice("cellward container set vmpwmic microphone yes")
          record = (
              "sh -c 'timeout 5 pw-record --raw --target vm-mic -P node.name={} - | wc -c'"
          )
          in_container = lambda cmd: alice("cellward run offline --container vmpwmic -- " + cmd)
          out = in_container(record.format("vz-cmic"))
          assert int(out.strip()) > 10000, f"a container's yes did not record: {out}"
          assert "vm-mic" in nodes(parse(in_container("timeout 20 pw-dump"))), \
              "the container's first look at the graph had no microphone"
          out = zone(record.format("vz-zmic"))
          assert out.strip() == "0", f"the zone's own program recorded on the zone's no: {out}"
          meta = alice("pw-metadata -n vpn-zones 0")
          assert "vpn-zones.microphone-by-client.offline" in meta, meta
          # A client's key goes with it: nothing is left of those above.
          assert "vpn-zones.microphone.client." not in meta, meta
          alice("cellward microphone offline yes")
          alice("cellward container set vmpwmic microphone no")
          out = in_container(record.format("vz-cno"))
          assert out.strip() == "0", f"the zone's yes overrode a container's no: {out}"
          alice("cellward microphone offline no")
          alice("cellward container rm vmpwmic")

      with subtest("a device the zone makes is destroyed and never the default"):
          alice(
              "systemd-run --user --unit=zonesink cellward run offline -- "
              "pw-loopback --capture-props=media.class=Audio/Sink,node.name=zone-vsink "
              "--playback-props=node.name=zone-vsink-out"
          )
          machine.sleep(5)
          n = nodes(host_dump())
          assert "zone-vsink" not in n, n
          default = alice("pw-metadata 0 default.audio.sink")
          assert "zone-vsink" not in default, default
          alice("systemctl --user stop zonesink.service || true")

      with subtest("PipeWire restarts: the restricted socket comes back, the raw one never"):
          alice("systemctl --user restart pipewire.service")
          alice("systemctl --user start pipewire-pulse.service wireplumber.service")
          machine.wait_until_succeeds(f"grep -qx active {STATE}/offline/pipewire-context.state", timeout=60)
          mounts = zone("cat /proc/self/mountinfo")
          assert "/pipewire-context /run/user/1000/pipewire-0 " in mounts, mounts
          for _ in range(30):
              if "vm-sink" in nodes(zone_dump()):
                  break
              machine.sleep(1)
          else:
              logs()
              raise Exception("the zone has no PipeWire after the restart")
          assert "host-player" not in nodes(zone_dump())

      with subtest("an audio manager gets the raw socket, loudly"):
          # The host's player died with the daemon above: another.
          alice(
              "systemd-run --user --unit=hostplay2 pw-play --raw --target vm-sink "
              "-P node.name=host-player /dev/urandom"
          )
          out = alice("cellward audio-manager offline on")
          assert "ВНИМАНИЕ" in out, out
          alice("systemctl --user stop zoneplay.service || true")
          alice("cellward down offline")
          zone("true")
          mounts = zone("cat /proc/self/mountinfo")
          assert "/pipewire-context /run/user/1000/pipewire-0 " not in mounts, mounts
          machine.wait_until_succeeds(
              "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 pw-dump' | grep -q host-player"
          )
          assert "host-player" in nodes(zone_dump())
          out = json.loads(alice_any("cellward doctor offline --json"))
          checks = next(z for z in out["zones"] if z["name"] == "offline")["checks"]
          pw = [c for c in checks if c["id"] == "pipewire"]
          assert pw and pw[0]["level"] == "warn" and "МЕНЕДЖЕР ЗВУКА" in pw[0]["detail"], checks
          out = json.loads(alice("cellward status --json"))
          z = next(n for n in out["networks"] if n["name"] == "offline")
          assert z["audio_manager"] == {"value": True, "source": "local"}, z
          alice("cellward audio-manager offline default")
          alice("cellward down offline")
    '';
  };
in
test
