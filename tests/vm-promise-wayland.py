"""tests/vm.nix, continued: a launch into a zone is restricted whatever its
program is called (docs/THREAT-MODEL.md W5).

Executed by the main test script with exec(), in its globals (machine, alice,
`display` and `swaysock` of the sway subtest): the script is handed to the
driver's build in one environment variable, and the kernel takes 128 KiB there.
"""

with subtest("a launch into a zone is restricted whatever its program is called"):
    # `obs` is on the built-in list of programs that keep the full protocols
    # — for unconfined launches. Into a zone the restriction applies to every
    # program: its name is its own word, and no name is a way around it.
    alice("ln -sf $(command -v wayland-info) /home/alice/obs")
    zone = alice(f"WAYLAND_DISPLAY={display} cellward run vmsmoke -- /home/alice/obs")
    assert "wl_compositor" in zone, zone
    assert "zwlr_screencopy_manager_v1" not in zone, zone
    assert "zwp_virtual_keyboard_manager_v1" not in zone, zone
    alice("rm -f /home/alice/obs")
