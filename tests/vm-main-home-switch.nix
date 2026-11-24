# Focused end-to-end proof for a named container using the real home and the
# host network. Everything mutable happens inside the two test VMs.
# Run: nix-build tests/vm-main-home-switch.nix -A driver -o main-home-driver
{ system ? builtins.currentSystem, focusOnly ? false }:
let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs { inherit system; config = {}; overlays = []; };
  helper = ./vm-main-home-helper.py;
  test = pkgs.testers.runNixOSTest {
    name = "cellward-main-home-switch";
    nodes.machine = { pkgs, ... }: {
      imports = [ "${pins.home-manager}/nixos" ];
      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        linger = true;
        subUidRanges = [{ startUid = 100000; count = 65536; }];
        subGidRanges = [{ startGid = 100000; count = 65536; }];
      };
      home-manager.useGlobalPkgs = true;
      home-manager.useUserPackages = true;
      home-manager.users.alice = {
        imports = [ ../module ];
        programs.cellward.enable = true;
        programs.cellward.defaults.permissions.network = "yes";
        # Exercise epochs and route publication, not the separate NFQUEUE
        # ownership mechanism (its intermittent offline→host failure is logged
        # by the default-mode runs preserved in the test artifacts).
        programs.cellward.defaults.permissions.strictNetwork = false;
        home.stateVersion = "26.05";
      };
      boot.kernelModules = [ "wireguard" "tun" "nf_tables" ];
      environment.systemPackages = [
        pkgs.wireguard-tools
        pkgs.socat
        pkgs.python3
        pkgs.nftables
        pkgs.procps
      ] ++ pkgs.lib.optionals focusOnly [
        pkgs.sway
        pkgs.foot
        pkgs.grim
        pkgs.wtype
      ];
      virtualisation.cores = 2;
      virtualisation.memorySize = 1536;
    };
    nodes.server = { pkgs, ... }: {
      boot.kernelModules = [ "wireguard" ];
      environment.systemPackages = [ pkgs.wireguard-tools pkgs.socat pkgs.python3 ];
      networking.firewall.allowedTCPPorts = [ 8090 ];
      networking.firewall.allowedUDPPorts = [ 51820 7300 ];
      networking.firewall.trustedInterfaces = [ "wg0" ];
      virtualisation.memorySize = 512;
    };
    testScript = ''
      import shlex

      STATE = "/home/alice/.local/state/vpn-zones"
      HELPER = "${helper}"

      def alice(cmd):
          return machine.succeed(
              "su -l alice -c "
              + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )

      start_all()
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_for_unit("user@1000.service")
      server.wait_for_unit("multi-user.target")
      machine.copy_from_host(HELPER, "/tmp/main-home-helper.py")
      server.copy_from_host(HELPER, "/tmp/main-home-helper.py")
    '' + (if focusOnly then ''
      exec(open("${./vm-main-home-focus-only.py}").read())
    '' else ''
      exec(open("${./vm-main-home-switch.py}").read())
    '');
  };
in { inherit (test) driver driverInteractive; inherit test; }
