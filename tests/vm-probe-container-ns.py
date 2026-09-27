"""tests/vm.nix, continued: stage 0 of the container design (2026-09-27).

Executed by the main test script with exec(), in its globals (machine,
server, alice, STATE, rzpid, PROBE and what the earlier subtests defined):
the script is handed to the driver's build in one environment variable, and
the kernel takes 128 KiB there (MAX_ARG_STRLEN).

The mechanisms a container instance will rest on, proved on this kernel
with this passt before any product code uses them (tests/vm-probe-helper.py
does the VM's side):

  (a) a sibling user+net namespace goes out by the zone's tunnel through a
      `passt --fd` started in the zone's app namespace and `vpn-zone-core
      frame-relay` pumping its tap: TCP, UDP, DNS through the constant
      forwarders, ICMP and IPv6;
  (b) passt killed: the relay ends, its tap with it, only lo is left;
  (c) SOCK_DESTROY in a user-owned namespace: ECONNABORTED on an
      established TCP socket and a connected UDP one;
  (e) procfs mounted in a user-owned pid namespace shows its own processes;
  (f) a delegated unit's program cgroups: made, moved into, frozen, moved
      between, emptied — by the user;
  (d) an nft `socket cgroupv2` rule in a user-owned namespace passes the
      sockets born in one cgroup and drops the others, one born before its
      process moved in included;
  (g) informative only: pasta instead of passt, handed the tap itself.

Every verdict is printed as a `PROBE VERDICT` line (and all of them at the
end): whether the modules these need were autoloaded from a user namespace
or had to be loaded first is what the later stages' NixOS tier needs to know.
"""

import ipaddress
import json
import re
import shlex

PROBE_VERDICTS = {}


def verdict(key, value):
    PROBE_VERDICTS[key] = value
    print(f"PROBE VERDICT {key}: {value}")


def helper(*args):
    return f"{PROBE['py']} {PROBE['helper']} " + " ".join(shlex.quote(str(a)) for a in args)


def last_json(out):
    return json.loads(out.strip().splitlines()[-1])


def loaded(names):
    """Which of these kernel modules are in."""
    out = machine.succeed(
        "for m in " + " ".join(names) + "; do test -d /sys/module/$m && echo $m; done; true"
    )
    return set(out.split())


def in_probe(pid, cmd):
    """As root of a probe namespace, in its network: alice's uid is its 0,
    and nsenter's setgroups would be refused there (`unshare -r`)."""
    return alice(f"nsenter --preserve-credentials -U -n -t {pid} -- {cmd}")


def hold():
    return int(alice(helper("hold")).strip().splitlines()[-1])


with subtest("probe (a): a sibling namespace goes out by the zone through passt --fd and frame-relay"):
    a4, a6 = "10.254.3.4", "fd63:656c:6c77::abcd:1"
    relay = last_json(
        alice(helper("relay", PROBE["passt"], rzpid, a4, a6, "10.99.0.1", "fd99::1"))
    )
    sib = relay["holder"]
    links = in_probe(sib, "ip -o link show")
    assert len(links.strip().splitlines()) == 2 and ": awg0" in links, links
    out = in_probe(sib, "socat -T10 - TCP:10.99.0.1:8080")
    assert "peer=10.99.0.2" in out, f"TCP: {out}"
    out = in_probe(sib, "dig +time=5 +tries=2 +short leaktest.internal @10.99.0.1")
    assert "10.99.0.9" in out, f"UDP: {out}"
    for forwarder in ["10.254.255.253", "fd63:656c:6c77::53"]:
        out = in_probe(sib, f"dig +time=5 +tries=2 +short leaktest.internal @{forwarder}")
        assert "10.99.0.9" in out, f"DNS through {forwarder}: {out}"
    out = in_probe(sib, "ping -c1 -W5 10.99.0.1")
    assert " 0% packet loss" in out, out
    out = in_probe(sib, "socat -T10 - TCP6:[fd99::1]:8081")
    seen = re.search(r"peer=\[?([0-9a-fA-F:]+)\]?", out)
    assert seen and ipaddress.ip_address(seen.group(1)) == ipaddress.ip_address(
        "fd99::2"
    ), f"TCP over IPv6: {out}"
    out = in_probe(sib, "ping -6 -c1 -W5 fd99::1")
    assert " 0% packet loss" in out, out
    verdict(
        "relay path",
        "works: TCP, UDP, DNS through D4 and D6, ICMP and IPv6 through passt --fd "
        "in the zone's app namespace and frame-relay in a sibling namespace",
    )

with subtest("probe (b): passt killed, the relay ends and its tap goes: only lo is left"):
    machine.succeed(f"kill -KILL {relay['passt']}")
    machine.wait_until_fails(f"kill -0 {relay['relay']}", timeout=30)
    links = in_probe(sib, "ip -o link show")
    assert len(links.strip().splitlines()) == 1 and ": lo:" in links, links
    in_probe(sib, "sh -c '! timeout 5 socat -T3 - TCP:10.99.0.1:8080'")
    machine.succeed(f"kill {sib}")
    verdict("relay end", "passt's end ends the relay; the tap is not persistent and goes with it")

with subtest("probe (c): SOCK_DESTROY in a user-owned namespace aborts TCP and connected UDP"):
    DIAG = ["inet_diag", "tcp_diag", "udp_diag"]

    def try_abort():
        pid = hold()
        try:
            return last_json(in_probe(pid, helper("abort")))
        finally:
            machine.succeed(f"kill {pid}")

    before = loaded(DIAG)
    got = try_abort()
    after = loaded(DIAG)
    if (got["tcp"], got["udp"]) != ("ECONNABORTED", "ECONNABORTED"):
        missing = sorted(set(DIAG) - after)
        machine.succeed("modprobe -a " + " ".join(DIAG))
        verdict(
            "sock_diag modules",
            f"loaded before: {sorted(before)}; after a try from a user namespace: "
            f"{sorted(after)} (not autoloaded: {missing}; first try tcp={got['tcp']} "
            f"udp={got['udp']} ss={got['ss']} {got['err']}); preloaded for the second",
        )
        got = try_abort()
    else:
        verdict(
            "sock_diag modules",
            f"loaded before: {sorted(before)}; autoloaded from a user namespace: "
            f"{sorted(after - before) or 'none was missing'}",
        )
    assert (got["tcp"], got["udp"]) == ("ECONNABORTED", "ECONNABORTED"), got
    verdict(
        "INET_DIAG_DESTROY",
        "available: ss -K as root of a user-owned netns gives ECONNABORTED to an "
        "established TCP socket and to a connected UDP one",
    )

with subtest("probe (e): a user-owned pid namespace mounts a procfs of its own"):
    out = alice(
        "unshare -U -r -p -f -m --mount-proc sh -c "
        "'echo self=$$; ls /proc | grep -cxE \"[0-9]+\"; cat /proc/1/comm'"
    )
    words = out.split()
    assert words[0] == "self=1", out
    assert int(words[1]) <= 4, f"more processes than its own in its /proc: {out}"
    assert words[2] in ("sh", "bash"), out
    verdict("procfs in a user-owned pid namespace", "mounts; only its own processes show")

with subtest("probe (f): a delegated unit's program cgroups: made, moved into, frozen, moved, emptied"):
    code, _ = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; systemd-run --user --unit=vzprobe "
            "-p Delegate=yes -p DelegateSubgroup=infra sleep infinity"
        )
    )
    if code == 0:
        verdict("DelegateSubgroup", "settable on a transient unit")
    else:
        verdict("DelegateSubgroup", "refused on a transient unit; Delegate=yes alone")
        alice("systemd-run --user --unit=vzprobe -p Delegate=yes sleep infinity")
    cg = alice("systemctl --user show -p ControlGroup --value vzprobe.service").strip()
    assert cg.startswith("/user.slice/"), cg
    base = f"/sys/fs/cgroup{cg}"
    alice(f"mkdir {base}/e1 {base}/e2")
    # A process of alice's manager that is no unit's main process: the
    # shell's child.
    alice("systemd-run --user --unit=vzprobe-prog sh -c 'sleep infinity & wait'")
    main = alice("systemctl --user show -p MainPID --value vzprobe-prog.service").strip()
    machine.wait_until_succeeds(f"pgrep -P {main} -x sleep")
    prog = machine.succeed(f"pgrep -P {main} -x sleep").strip()
    alice(f"echo {prog} > {base}/e1/cgroup.procs")
    machine.succeed(f"grep -qx 'populated 1' {base}/e1/cgroup.events")
    alice(f"echo 1 > {base}/e1/cgroup.freeze && echo 1 > {base}/e2/cgroup.freeze")
    machine.wait_until_succeeds(f"grep -qx 'frozen 1' {base}/e1/cgroup.events", timeout=30)
    alice(f"echo {prog} > {base}/e2/cgroup.procs")
    machine.succeed(f"grep -qx 'populated 0' {base}/e1/cgroup.events")
    machine.succeed(f"grep -qx 'populated 1' {base}/e2/cgroup.events")
    alice(f"echo 0 > {base}/e2/cgroup.freeze")
    machine.wait_until_succeeds(f"grep -qx 'frozen 0' {base}/e2/cgroup.events", timeout=30)
    alice(f"rmdir {base}/e1")
    verdict(
        "delegated cgroups",
        "a unit's subgroups are made, frozen, moved between and emptied by its user, "
        "with populated/frozen in cgroup.events",
    )

with subtest("probe (d): a socket cgroupv2 rule in a user-owned namespace passes one cgroup's sockets only"):
    rel = cg.lstrip("/") + "/e2"
    level = len(rel.split("/"))
    nft = alice("command -v nft").strip()
    nsenter = alice("command -v nsenter").strip()
    pid = hold()

    def try_rule():
        return last_json(
            alice(
                "systemd-run --user --wait --pipe --collect -q -E PATH=\"$PATH\" -- "
                f"{nsenter} --preserve-credentials -U -n -t {pid} -- "
                + helper("cgroup", nft, rel, level, f"{base}/e2/cgroup.procs")
            )
        )

    before = "nft_socket" in loaded(["nft_socket"])
    got = try_rule()
    if got["loaded"]:
        verdict(
            "nft_socket",
            "loaded before the probe" if before else "autoloaded from a user namespace",
        )
    else:
        assert not before, f"nft_socket is loaded and the rule was refused: {got}"
        machine.succeed("modprobe nft_socket")
        verdict(
            "nft_socket",
            f"not autoloaded from a user namespace ({got['err']}); loaded for the second try",
        )
        got = try_rule()
    assert got["loaded"] and got["got"] == ["member"], got
    machine.succeed(f"kill {pid}")
    verdict(
        "socket cgroupv2",
        f"loads in a user-owned netns (level {level}); passes the cgroup's sockets, drops "
        "the others, and a socket born before its process moved in stays outside",
    )
    alice("systemctl --user stop vzprobe.service vzprobe-prog.service")

with subtest("probe (g), informative: pasta instead of passt, handed the tap itself (J4)"):
    code, out = machine.execute(
        "su -l alice -c "
        + shlex.quote(
            "export XDG_RUNTIME_DIR=/run/user/1000; "
            + helper("pasta-fd", PROBE["pasta"], "10.254.3.5")
            + " 2>&1"
        ),
        timeout=180,
    )
    verdict("pasta-mode --fd (informative)", f"exit {code}: {out.strip()[-700:]}")

print("PROBE VERDICTS " + json.dumps(PROBE_VERDICTS))
