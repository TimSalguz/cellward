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

## Sandboxed lifecycle selftest

`cellward transport selftest <name>` starts an external adapter in bwrap with
`--unshare-all`: no host network, real home, host routes, firewall or DNS are
granted. The process gets a fresh empty home/runtime and read-only Nix/store and
`/etc`. Closing the control channel stops it.

The stdio protocol is a big-endian `u32` length, then `session_id` and
`sequence` as big-endian `u64`, then at most 1 MiB of payload. An adapter must
first return session/sequence zero with payload `ready`. Startup and response
timeouts are three seconds; malformed frames and a closed channel are errors.

For the deterministic end-to-end fixture, `Fake = yes` appends the hidden
`_transport-fake` command to `Run` (normally the Cellward core binary). It sends
`ready` and echoes each frame. This is a lifecycle test, not a network route:

```ini
[Transport]
Name = fake
Run = /nix/store/…-cellward/bin/vpn-zone-core
Channel = datagram
Fake = yes
MTU = 1200
```

`selftest` sends session 42, sequence 1 and requires the same frame back. It
publishes nothing and grants no consumer access. A production adapter still
needs a separately reviewed network capability, health checks and publication;
adapter death must close that consumer path.
