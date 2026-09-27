"""tests/vm.nix, continued: the keyring and flatpak's host command out of a
hermetic zone's reach (docs/THREAT-MODEL.md P5).

Executed by the main test script with exec(), in its globals (machine, alice,
in_zone, `hp` of the hermetic zone, FAKE_BUS_OWNER): the script is handed to
the driver's build in one environment variable, and the kernel takes 128 KiB
there.
"""

with subtest("hermetic zone: the keyring and flatpak's host command are out of reach"):
    # A stand-in owns each name on the host's session bus and writes down
    # every byte it is sent: a call that reached it is in its file. The host
    # first, so that nothing in the file afterwards is the zone's doing.
    introspect = "org.freedesktop.DBus.Introspectable Introspect"
    for n, (name, path) in enumerate([
        ("org.freedesktop.secrets", "/org/freedesktop/secrets"),
        ("org.freedesktop.Flatpak", "/org/freedesktop/Flatpak/Development"),
    ]):
        got = f"/home/alice/bus-got-{n}"
        alice(
            f"systemd-run --user --unit=fakeowner{n} {FAKE_BUS_OWNER} {got} {name}"
        )
        machine.wait_until_succeeds(
            "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
            "busctl --user --timeout=5 list' | grep -q " + name,
            timeout=30,
        )
        alice(f"sh -c 'busctl --user --timeout=2 call {name} {path} {introspect} || true'")
        machine.wait_until_succeeds(f"grep -q Introspect {got}", timeout=10)
        alice(f": > {got}")
        # Refused, or let through to a stand-in that never answers: busctl
        # then waits its two seconds, long after the bytes arrived. Either
        # way the file says which it was once busctl is back.
        in_zone(hp, f"sh -c '! busctl --user --timeout=2 call {name} {path} {introspect}'")
        machine.fail(f"grep -q Introspect {got}")
        alice(f"systemctl --user stop fakeowner{n}.service")
