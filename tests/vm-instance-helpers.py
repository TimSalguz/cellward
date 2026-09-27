"""tests/vm.nix, continued: helpers for containers' instances (the container
design of 2026-09-27). Executed by the main test script with exec(), in its
globals (machine, alice, json, shlex), before any subtest: the script is
handed to the driver's build in one environment variable, and the kernel
takes 128 KiB there (MAX_ARG_STRLEN).

Since stage 2 a launch into a zone runs in its container's instance: what a
program sees is looked at in the instance (`in_inst`, entered as a launch
enters it), what the zone is — its transport — in the zone (`in_zone`).
"""

CORE = alice("command -v vpn-zone-core").strip()


def ikey(id_):
    """The instance's key (rust/src/instance.rs `key`): FNV-1a of its id —
    its directory's name and its Wayland sockets'."""
    h = 0xCBF29CE484222325
    for b in id_.encode():
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"i-{h:016x}"


def instance(id_):
    """The running instance `id_` as `cellward status --json` says it, or None."""
    out = json.loads(alice("cellward status --json"))
    return next((i for i in out["instances"] if i["id"] == id_), None)


def in_inst_cmd(id_, net, cmd):
    return f"{CORE} container-enter --instance {id_} --network {net} -- {cmd}"


def in_inst(id_, net, cmd):
    """A command in a running instance, entered as a launch enters it."""
    return alice(in_inst_cmd(id_, net, cmd))


def in_inst_q(id_, net, cmd):
    """The same as a shell line, for machine.wait_until_…."""
    return "su -l alice -c " + shlex.quote(
        "export XDG_RUNTIME_DIR=/run/user/1000; " + in_inst_cmd(id_, net, cmd)
    )
