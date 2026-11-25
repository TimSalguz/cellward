# Transport adapters

Cellward has three built-in adapters: WireGuard (`wg`), AmneziaWG (`awg`) and
OpenConnect. External adapters use the same inventory but are not granted a
route merely by being installed.

This first slice is deliberately read-only: `cellward transport list [--json]`
shows the inventory and `cellward transport check <file>` validates one
manifest. Neither command executes the adapter.

## SOCKS5 and HTTP CONNECT zones

A `[Proxy]` zone turns one explicitly configured proxy into a full-tunnel
network through sing-box. Its client runs unprivileged in the uplink, with only
`CAP_NET_ADMIN` for the pre-created TUN; the uplink firewall accepts only the
configured proxy address and port. The TUN moves into the application
namespace, and client death takes the whole zone down without a direct-route
fallback.

```ini
[Interface]
Address = 10.200.0.2/32
DNS = 1.1.1.1
MTU = 1380

[Proxy]
Type = socks5
Server = 192.0.2.10
Port = 1080
; Username = optional
; Password = optional
```

`Type` is `socks5` or `http`. `Server` must be a literal unicast IPv4/IPv6
address, never a hostname, so creating or chaining a route cannot silently use
the host resolver. `[Interface]` accepts only `Address`, `DNS` and `MTU`; one
IPv4 address is required and one IPv6 address is optional. HTTP CONNECT is
explicitly TCP-only. SOCKS5 UDP support depends on the proxy server; no UDP
support is inferred for HTTP. Credentials stay in the private generated
sing-box configuration and do not enter argv or the environment.

The same section works in a pooled node and as the inner hop of a chain. The
outer route must provide the address family of the proxy server. GUI-only VPN
clients can use this backend by exposing a local SOCKS5 endpoint inside their
adapter's uplink; the GUI application itself is not implicitly trusted as a
full-tunnel route.

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
