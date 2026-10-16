# The channels of a container's program

`docs/channels.toml` maps what a program of a container reaches and through
what: processes, resources (namespaces, mounts, descriptors, paths) and the
places it must not reach unasked — the host's network, a process of the host
that acts for it, another container, the machine's identity, the whole
screen. Each edge says what guards it and which test checks that.

`tests/channels-check.py` walks every route from the program to the outside
and fails on one with no guard on it, or a guard with no test; a route through
an edge marked `known` is an open item (its ROADMAP or LEAK-MODEL entry) and
is listed, not failed. CI runs it.

A new channel — a socket, a mount, a descriptor handed to a launch, a helper on
the host — is an edge here first. Looking for a leak is looking for a route
the map lacks.
