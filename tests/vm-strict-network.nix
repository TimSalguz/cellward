# Focused end-to-end strict ownership test; no real host network/config.
{ system ? builtins.currentSystem }:
let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs { inherit system; config = {}; overlays = []; };
  transferServer = pkgs.writeText "strict-transfer-server.py" ''
    import http.server, socket, threading
    payload = b"cellward-strict-transfer" * 100000
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200 if data == payload else 400)
            self.end_headers()
            self.wfile.write(b"TRANSFER_OK" if data == payload else b"BAD_DATA")
    def udp():
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Keep the reply source equal to the address the client contacted.
        # Wildcard bind picks the VM's primary 192.168 address instead.
        server.bind(("198.51.100.1", 9000))
        while True:
            data, peer = server.recvfrom(65535)
            server.sendto(data, peer)
    threading.Thread(target=udp, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
  '';
  transferClient = pkgs.writeText "strict-transfer-client.py" ''
    import socket, urllib.request
    assert socket.gethostbyname("peer.cellward.test") == "198.51.100.1"
    payload = b"cellward-strict-transfer" * 100000
    url = "http://peer.cellward.test:8001/"
    with urllib.request.urlopen(url, timeout=20) as response:
        assert response.read() == payload
    with urllib.request.urlopen(url, data=payload, timeout=20) as response:
        assert response.read() == b"TRANSFER_OK"
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)
    datagram = b"fragmented-cellward" * 3000
    udp.sendto(datagram, ("198.51.100.1", 9000))
    assert udp.recv(65535) == datagram
    print("TRANSFER_OK")
  '';
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
        # No explicit strictNetwork: verify the built-in production default.
        programs.cellward.defaults.permissions.network = "yes";
        home.stateVersion = "26.05";
      };
      environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.nftables pkgs.procps ];
      virtualisation.memorySize = 1536;
      virtualisation.cores = 2;
    };
    nodes.peer = { pkgs, ... }: {
      environment.systemPackages = [ pkgs.python3 ];
      networking.firewall.allowedTCPPorts = [ 8000 8001 ];
      networking.firewall.allowedUDPPorts = [ 53 9000 ];
      services.dnsmasq = {
        enable = true;
        settings = { address = [ "/cellward.test/198.51.100.1" ]; no-resolv = true; };
      };
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
          code = "import pathlib,socket; p=next(pathlib.Path('/home/alice/.local/state/vpn-zones/.instances').glob('*/strict-network')); s=socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(str(p.parent/'control')); s.sendall(b'ROTATE-OWNER-QUEUE\\n'); assert s.recv(512)==b'REQUEUED\\n'"
          alice("python3 -c " + shlex.quote(code))
      peer.succeed("ip addr add 198.51.100.1/24 dev eth1; mkdir -p /tmp/strict-http; echo STRICT_OK > /tmp/strict-http/index.html")
      peer.succeed("systemd-run --unit=strict-http ${pkgs.python3}/bin/python3 -m http.server 8000 --bind 0.0.0.0 --directory /tmp/strict-http")
      peer.wait_for_open_port(8000)
      machine.succeed("ip route add 198.51.100.0/24 dev eth1")
      machine.succeed("printf 'nameserver 198.51.100.1\\n' > /etc/resolv.conf")
      peer.succeed("systemd-run --unit=strict-transfer ${pkgs.python3}/bin/python3 ${transferServer}")
      peer.wait_for_open_port(8001)
      alice("cellward container create strict-test --home layer")
      with subtest("registration precedes exec and HTTP egress works"):
          alice("systemd-run --user --unit=strict-keep cellward run host --container strict-test -- sleep infinity")
          machine.wait_until_succeeds("find /home/alice/.local/state/vpn-zones/.instances -mindepth 2 -maxdepth 2 -name strict-network -type f | grep -q .", timeout=90)
          assert "STRICT_OK" in run("curl --noproxy '*' -fsS --max-time 15 http://198.51.100.1:8000/")
      with subtest("ordinary interactive terminal delegates through a PTY"):
          command = "cellward run host --container strict-test -- curl --noproxy '*' -fsS --max-time 15 http://198.51.100.1:8000/"
          result = alice("${pkgs.util-linux}/bin/script -q -e -c " + shlex.quote(command) + " /dev/null")
          assert "STRICT_OK" in result, result
      with subtest("DNS, multi-megabyte TCP and fragmented UDP work"):
          assert "TRANSFER_OK" in run("python3 ${transferClient}")
      with subtest("small host receive buffers do not strand allowed packets"):
          previous = machine.succeed("sysctl -n net.core.rmem_max").strip()
          try:
              machine.succeed("sysctl -w net.core.rmem_max=212992")
              alice("cellward container create strict-small --home layer")
              assert "TRANSFER_OK" in alice("cellward run host --container strict-small -- python3 ${transferClient}")
          finally:
              machine.succeed("sysctl -w net.core.rmem_max=" + previous)
      with subtest("raw unregistered process cannot use the instance network"):
          status = json.loads(alice("cellward status --json"))
          instance = next(i for i in status["instances"] if i["id"] == "strict-test")
          assert instance["network_ownership"] == "strict", instance
          pid = instance["pid"]
          # Root intentionally enters without a registered launch cgroup.
          machine.fail(f"nsenter -t {pid} -U -n curl --noproxy '*' -fsS --max-time 2 http://198.51.100.1:8000/")
      with subtest("distinct launches in one container keep separate program policy"):
          alice("cellward container create strict-policy --home layer")
          alice("printf '\\nnet_deny = curl\\n' >> /home/alice/.config/vpn-zones/containers/strict-policy/container.conf")
          machine.fail("su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; cellward run host --container strict-policy -- curl --noproxy \"*\" -fsS --max-time 3 http://198.51.100.1:8000/'")
          assert "TRANSFER_OK" in alice("cellward run host --container strict-policy -- python3 ${transferClient}")
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
