# Focused end-to-end strict ownership test; no real host network/config.
{ system ? builtins.currentSystem }:
let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs { inherit system; config = {}; overlays = []; };
  loopClient = pkgs.writeText "strict-network-client.py" ''
    import time, urllib.request
    while True:
        try:
            with urllib.request.urlopen("http://198.51.100.1:8000/", timeout=0.5) as response:
                if b"STRICT_OK" in response.read():
                    print("STRICT_OK", flush=True)
        except Exception:
            print("STRICT_DENIED", flush=True)
        time.sleep(0.2)
  '';
  test = pkgs.testers.runNixOSTest {
    name = "cellward-strict-network";
    nodes.machine = { pkgs, ... }: {
      imports = [ "${pins.home-manager}/nixos" ];
      users.users.alice = {
        isNormalUser = true; uid = 1000; linger = true;
        subUidRanges = [{ startUid = 100000; count = 65536; }];
        subGidRanges = [{ startGid = 100000; count = 65536; }];
      };
      home-manager.useGlobalPkgs = true;
      home-manager.useUserPackages = true;
      home-manager.users.alice = {
        imports = [ ../module ];
        programs.cellward.enable = true;
        programs.cellward.defaults.permissions = { strictNetwork = true; network = "yes"; };
        home.stateVersion = "26.05";
      };
      environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.nftables pkgs.procps ];
      virtualisation.memorySize = 1536;
      virtualisation.cores = 2;
    };
    nodes.peer = { pkgs, ... }: {
      environment.systemPackages = [ pkgs.python3 ];
      networking.firewall.allowedTCPPorts = [ 8000 ];
      virtualisation.memorySize = 512;
    };
    testScript = ''
      import json, shlex
      start_all()
      machine.wait_for_unit("multi-user.target")
      peer.wait_for_unit("multi-user.target")
      machine.wait_for_unit("user@1000.service")
      def alice(cmd):
          return machine.succeed("su -l alice -c " + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd))
      def run(cmd):
          # A root-created login must be delegated automatically by Cellward.
          return alice("cellward run host --container strict-test -- " + cmd)
      def rotate_queue():
          code = "import pathlib,socket; p=next(pathlib.Path('/home/alice/.local/state/vpn-zones/.instances').glob('*/strict-network')); s=socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(str(p.parent/'control')); s.sendall(b'ROTATE-OWNER-QUEUE\\\\n'); assert s.recv(512)==b'REQUEUED\\\\n'"
          alice("python3 -c " + shlex.quote(code))
      peer.succeed("ip addr add 198.51.100.1/24 dev eth1; mkdir -p /tmp/strict-http; echo STRICT_OK > /tmp/strict-http/index.html")
      peer.succeed("systemd-run --unit=strict-http ${pkgs.python3}/bin/python3 -m http.server 8000 --bind 0.0.0.0 --directory /tmp/strict-http")
      peer.wait_for_open_port(8000)
      machine.succeed("ip route add 198.51.100.0/24 dev eth1")
      alice("cellward container create strict-test --home layer")
      with subtest("registration precedes exec and HTTP egress works"):
          alice("systemd-run --user --unit=strict-keep cellward run host --container strict-test -- sleep infinity")
          machine.wait_until_succeeds("find /home/alice/.local/state/vpn-zones/.instances -mindepth 2 -maxdepth 2 -name strict-network -type f | grep -q .", timeout=90)
          assert "STRICT_OK" in run("curl --noproxy '*' -fsS --max-time 15 http://198.51.100.1:8000/")
      with subtest("raw unregistered process cannot use the instance network"):
          status = json.loads(alice("cellward status --json"))
          instance = next(i for i in status["instances"] if i["id"] == "strict-test")
          assert instance["network_ownership"] == "strict", instance
          pid = instance["pid"]
          # Root intentionally enters without a registered launch cgroup.
          machine.fail(f"nsenter -t {pid} -U -n curl --noproxy '*' -fsS --max-time 2 http://198.51.100.1:8000/")
      with subtest("a launch started denied can gain and lose permission without moving identity"):
          policy = "/home/alice/.config/vpn-zones/containers/strict-test/container.conf"
          alice(f"printf '\\nnet_default = deny\\n' >> {policy}")
          request = "cellward run host --container strict-test -- python3 ${loopClient} > /tmp/strict-loop.log"
          alice("systemd-run --user --unit=strict-loop sh -c " + shlex.quote(request))
          machine.wait_until_succeeds("grep -q STRICT_DENIED /tmp/strict-loop.log", timeout=45)
          assert int(machine.succeed("grep -c STRICT_OK /tmp/strict-loop.log || true").strip()) == 0
          alice(f"printf '\\nnet_default = allow\\n' >> {policy}")
          machine.wait_until_succeeds("grep -q STRICT_OK /tmp/strict-loop.log", timeout=20)
          rotate_queue()
          machine.sleep(1)
          rotated = machine.succeed("grep -c STRICT_OK /tmp/strict-loop.log").strip()
          rotate_queue()
          machine.wait_until_succeeds(f"test $(grep -c STRICT_OK /tmp/strict-loop.log) -gt {rotated}", timeout=20)
          alice(f"printf '\\nnet_default = deny\\n' >> {policy}")
          machine.sleep(2)
          before = machine.succeed("grep -c STRICT_OK /tmp/strict-loop.log").strip()
          machine.sleep(2)
          assert machine.succeed("grep -c STRICT_OK /tmp/strict-loop.log").strip() == before
          alice(f"printf '\\nnet_default = allow\\n' >> {policy}")
          machine.wait_until_succeeds(f"test $(grep -c STRICT_OK /tmp/strict-loop.log) -gt {before}", timeout=20)
          alice("systemctl --user stop strict-loop.service")
      with subtest("doctor has an explicit network-denied diagnostic registration"):
          result = alice("cellward doctor host || true")
          assert "strict launch registration failed" not in result, result
          assert "network-owner" in result, result
      with subtest("network switch drains and re-registers existing launches"):
          alice("cellward container set strict-test network offline --yes")
          alice("cellward container set strict-test network host --yes")
          assert "STRICT_OK" in run("curl --noproxy '*' -fsS --max-time 15 http://198.51.100.1:8000/")
      alice("systemctl --user stop strict-keep.service")
      machine.succeed("journalctl -b --no-pager > /tmp/strict-journal")
      machine.copy_from_vm("/tmp/strict-journal", "strict-journal")
    '';
  };
in { inherit (test) driver; inherit test; }
