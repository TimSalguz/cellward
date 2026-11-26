# The legacy login-session case belongs outside an instance's epoch.
{ system ? builtins.currentSystem }:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
in
pkgs.testers.runNixOSTest {
  name = "cellward-legacy-outside";
  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ "${pins.home-manager}/nixos" ];
      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        linger = true;
        subUidRanges = [ { startUid = 100000; count = 65536; } ];
        subGidRanges = [ { startGid = 100000; count = 65536; } ];
      };
      home-manager.useGlobalPkgs = true;
      home-manager.useUserPackages = true;
      home-manager.users.alice = {
        imports = [ ../module ];
        programs.cellward.enable = true;
        programs.cellward.defaults.permissions.strictNetwork = false;
        home.stateVersion = "26.05";
      };
      boot.kernelModules = [ "tun" "nf_tables" ];
      virtualisation.vlans = [ 1 ];
      virtualisation.cores = 2;
      virtualisation.memorySize = 1536;
    };

  testScript = ''
    import json
    import shlex

    STATE = "/home/alice/.local/state/vpn-zones"

    def alice(cmd):
        return machine.succeed(
            "su -l alice -c "
            + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
        )

    def instance(name):
        rows = json.loads(alice("cellward status --json"))["instances"]
        return next((row for row in rows if row["id"] == name), None)

    def live_switch_is(name, available, reason):
        for _ in range(120):
            row = instance(name)
            if row and (row["live_switch"]["available"], row["live_switch"]["reason"]) == (available, reason):
                return
            machine.sleep(1)
        raise AssertionError(f"{name}: never {available}/{reason}: {instance(name)}")

    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("home-manager-alice.service")
    machine.wait_for_unit("user@1000.service")

    alice("cellward container create vmia --home layer")
    alice("systemd-run --user --collect --unit=vmia-keep cellward run offline --container vmia -- sleep infinity")
    machine.wait_until_succeeds(
        "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 cellward status --json' | grep -q '\"id\":\"vmia\"'",
        timeout=30,
    )
    cg = alice(
        "systemctl --user show -p ControlGroup --value vpn-zone-container@vmia.service"
    ).strip()

    with subtest("a legacy login launch stays outside and holds the switch"):
        machine.succeed(
            "su -l alice -c "
            + shlex.quote(
                "export XDG_RUNTIME_DIR=/run/user/1000; setsid cellward run offline --container "
                "vmia -- sleep 4343 </dev/null >/dev/null 2>&1 &"
            )
        )
        live_switch_is("vmia", False, "outside")
        outsider = machine.succeed("pgrep -xf 'sleep 4343'").strip()
        assert f"{cg}/e1" not in machine.succeed(f"cat /proc/{outsider}/cgroup"), outsider
        machine.succeed("pkill -xf 'sleep 4343'")
        live_switch_is("vmia", True, None)
  '';
}
