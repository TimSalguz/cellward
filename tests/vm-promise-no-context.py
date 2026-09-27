"""tests/vm.nix, continued: a compositor without wp_security_context_v1
(docs/THREAT-MODEL.md W4).

Executed by the main test script with exec(), in its globals (machine,
alice, STATE; vmsmoke down, sway stopped): the script is handed to the
driver's build in one environment variable, and the kernel takes 128 KiB
there (MAX_ARG_STRLEN).
"""

import re

# cage (wlroots, headless, one program of its own) offers no security
# context, as GNOME's Mutter does not: wl-sandbox has no restricted socket to
# make. A launch into a zone then goes on with the compositor's own socket's
# name and without the socket, which no zone has — no Wayland at all, never
# the unrestricted one. `unconfined` is the host's own, and gets all of it.
with subtest("a compositor without the security context: no Wayland in a zone, all of it unconfined"):
    alice(
        "systemd-run --user --unit=vmcage "
        "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
        "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
        "cage -- sh -c 'echo $WAYLAND_DISPLAY > /tmp/vmcage-display; exec sleep 600'"
    )
    machine.wait_until_succeeds("test -s /tmp/vmcage-display", timeout=60)
    bare = machine.succeed("cat /tmp/vmcage-display").strip()
    assert bare.startswith("wayland-"), bare

    def interfaces(out):
        return set(re.findall(r"interface: '([^']+)'", out))

    host = interfaces(alice(f"WAYLAND_DISPLAY={bare} wayland-info"))
    print(f"cage offers: {sorted(host)}")
    assert "wl_compositor" in host, host
    assert "wp_security_context_manager_v1" not in host, (
        "cage speaks the security context now: W4 needs a compositor that does not"
    )

    # In a zone: nothing of the compositor's — at most its socket's name in
    # the environment, and no socket by that name or any other.
    out = alice(
        f"WAYLAND_DISPLAY={bare} cellward run vmsmoke -- sh -c "
        "'echo D=$WAYLAND_DISPLAY; wayland-info 2>&1 || echo NO-WAYLAND; "
        "ls -A $XDG_RUNTIME_DIR | grep ^wayland- || echo NO-SOCKET'"
    )
    print(out)
    assert "wl_compositor" not in out and "NO-WAYLAND" in out, out
    assert "NO-SOCKET" in out, out
    # Nor through the compositor's own process: /proc/<pid>/root leads to the
    # host's runtime directory — from the host, not from the zone.
    cage = alice("systemctl --user show -p MainPID --value vmcage").strip()
    via = f"/proc/{cage}/root/run/user/1000/{bare}"
    alice(f"socat -u OPEN:/dev/null UNIX-CONNECT:{via}")
    out = alice(
        f"cellward run vmsmoke -- sh -c 'socat -u OPEN:/dev/null UNIX-CONNECT:{via} 2>&1 "
        "|| echo PROC-REFUSED'"
    )
    assert "PROC-REFUSED" in out, out
    out = alice("cellward doctor vmsmoke --json")
    assert '{"id":"wayland-raw","level":"ok"' in out, out

    # Unconfined: the compositor's own socket, every global it offers.
    unconfined = interfaces(alice(f"WAYLAND_DISPLAY={bare} cellward run unconfined -- wayland-info"))
    assert unconfined == host, (sorted(host - unconfined), sorted(unconfined - host))

    alice("cellward down vmsmoke")
    alice("systemctl --user stop vmcage")
    machine.succeed("rm -f /tmp/vmcage-display")
