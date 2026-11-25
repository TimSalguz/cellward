# Transport adapters

Cellward has three built-in adapters: WireGuard (`wg`), AmneziaWG (`awg`) and
OpenConnect. External adapters use the same inventory but are not granted a
route merely by being installed.

This first slice is deliberately read-only: `cellward transport list [--json]`
shows the inventory and `cellward transport check <file>` validates one
manifest. Neither command executes the adapter.

## Manifest

Place an external manifest in `~/.config/vpn-zones/transports/<name>.conf`:

```ini
[Transport]
Name = reticulum
Run = /absolute/path/to/adapter
Channel = datagram
IPv4 = yes
IPv6 = yes
Asymmetric = yes
Multiplex = yes
MTU = 1200
```

- `Name`: 1–64 ASCII letters, digits, `.`, `_` or `-`; built-in names are
  reserved.
- `Run`: an absolute executable path. It is metadata in this slice, never a
  shell command and never executed by `list` or `check`.
- `Channel`: `datagram`, `stream` or `application`.
- `IPv4` defaults to yes; the other booleans default to no except `Multiplex`,
  which defaults to yes. At least one address family is required.
- `Asymmetric` means the adapter protocol can select independent uplink and
  downlink paths. It does not mean Cellward gives that capability to an
  ordinary VPN automatically.
- `MTU` is the adapter's declared value, not a measurement. Automatic changes
  require separate path diagnostics.

Unknown keys, invalid values, duplicate names and an unreadable manifest make
the whole external inventory fail closed. Built-ins remain visible in the
error-free configuration only.

## Frame/session boundary

`rust/src/transport.rs` also defines the common `Frame` (`session_id`,
`sequence`, payload), `AdapterSession` and a deterministic `LoopbackSession`.
The fake adapter is for scheduler and VM tests, including MTU rejection. It is
not a network transport.

A later lifecycle adapter must run the external program in a separate sandbox
with only explicitly issued capabilities. It must not inherit permission to
change host routes, firewall or DNS. Publication, start, health checks and
consumer access remain separate decisions, and adapter death closes the
consumer path. No external program is started by this document's current
implementation.
