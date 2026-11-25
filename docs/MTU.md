# MTU diagnostics

`cellward mtu [<zone>…] [--json]` reports every hop of the selected route from
the inner zone to the outer one. With no zone it inspects every configured
route.

Each row separates:

- `configured_mtu`: the effective value from the resolved configuration,
  including the WG/AWG or OpenConnect default;
- `effective_mtu`: the value reported by `ip link` inside the running hop's
  namespace, or `null`/`down` when the hop is down;
- `interface` and `up`.

A borrowed system namespace points to the following hop instead of pretending
to have a separate tunnel. Host-network and host-interface cases are identified
rather than given a fabricated default. Invalid configs and failed `ip link`
inspection are errors, never a fallback to another route.

The command sends no packets, starts no zone and changes neither interface MTU
nor routes. It is a read-only diagnostic baseline for a later active path-MTU
probe and any automatic adjustment.
