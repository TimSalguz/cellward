"""tests/vm.nix, continued: resolve1 over the system bus (docs/THREAT-MODEL.md D3).

Executed by the main test script with exec(), in its globals (machine, alice,
STATE, `bus` of the subtest before): the script is handed to the driver's
build in one environment variable, and the kernel takes 128 KiB there.
"""

with subtest("system bus in a zone: resolve1 refused, it names in the host's network"):
    # getaddrinfo does not go there, but a program that wants to can: resolved
    # looks names up in the HOST's network. The host first, so that a refusal
    # in the zone is the filter's.
    resolve = (
        "call org.freedesktop.resolve1 /org/freedesktop/resolve1 "
        "org.freedesktop.resolve1.Manager ResolveHostname isit 0 localhost 0 0"
    )
    code, out = bus(resolve, zone=False)
    assert code == 0, f"resolve1 does not answer on the host either: {out}"
    code, out = bus(resolve)
    assert code != 0, f"resolve1 answered in the zone: {out}"
