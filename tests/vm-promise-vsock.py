"""tests/vm.nix, continued: a zone's program and vsock (docs/THREAT-MODEL.md).

AF_VSOCK is not a network namespace's: a host's listener on vsock — a VM's
sshd since systemd 256, an agent — would be a way out of a zone around its
tunnel. Executed by the main test script with exec(), in its globals
(machine, alice, vmsmoke up).
"""

with subtest("a zone's program cannot reach the host over vsock"):
    code, _ = machine.execute("modprobe vsock_loopback")
    if code != 0:
        print("no vsock_loopback module: the vsock check is skipped")
    else:
        alice(
            "systemd-run --user --unit=vmvsock socat VSOCK-LISTEN:5555,fork "
            "'SYSTEM:echo vsock-host'"
        )
        # From the host it answers: the channel is there to be reached.
        machine.wait_until_succeeds(
            "su -l alice -c 'socat -T5 - VSOCK-CONNECT:1:5555 </dev/null' | grep -q vsock-host",
            timeout=30,
        )
        out = alice(
            "cellward run vmsmoke -- sh -c "
            "'socat -T5 - VSOCK-CONNECT:1:5555 </dev/null 2>&1; true'"
        )
        alice("systemctl --user stop vmvsock")
        assert "vsock-host" not in out, f"a zone's program reached the host over vsock: {out}"
