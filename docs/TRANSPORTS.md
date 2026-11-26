# Transport adapters

Cellward has three built-in adapters: WireGuard (`wg`), AmneziaWG (`awg`) and
OpenConnect. External adapters use the same inventory but are not granted a
route merely by being installed.

`cellward transport list [--json]` shows the inventory and `cellward transport
check <file>` validates one manifest. Neither command executes the adapter;
`selftest`, explicitly requested below, is the exception.

## SOCKS5 and HTTP CONNECT zones

A `[Proxy]` zone turns one explicitly configured proxy into a full-tunnel
network through sing-box. Its client runs unprivileged in the uplink, with only
`CAP_NET_ADMIN` for the pre-created TUN; the uplink firewall accepts only TCP
to the configured proxy address and port (plus UDP for a SOCKS5 endpoint). The
TUN moves into the application
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

`cellward mtu <zone> [--json]` reports configured and effective MTU for every
published hop without changing an interface or sending probe packets. Proxy
zones support IPv4 and an optional IPv6 address; an IPv6-only peer can be
reached through the proxy even when the proxy's own endpoint is IPv4.

The same section works in a pooled node and as the inner hop of a chain. The
outer route must provide the address family of the proxy server. GUI-only VPN
clients can use this backend by exposing a local SOCKS5 endpoint inside their
adapter's uplink; the GUI application itself is not implicitly trusted as a
full-tunnel route.

An application adapter declares that endpoint in its manifest:

```ini
[Transport]
Name = vendor-gui
Run = /absolute/path/to/provider
Channel = application
Proxy = socks5
ProxyPort = 1080
GUI = yes
```

`Proxy` and `ProxyPort` are required together. `GUI` defaults to no and is
meaningful only with a published proxy. Select the provider explicitly in the
zone and use the same endpoint:

```ini
[Interface]
Address = 10.200.0.2/32
DNS = 1.1.1.1
MTU = 1380

[Proxy]
Type = socks5
Server = 127.0.0.1
Port = 1080
Adapter = vendor-gui
```

The endpoint must be loopback and agree with the manifest. The provider runs as
the user in the uplink, with no capabilities there, and is the explicitly
trusted part allowed to make its own VPN connections. sing-box stays a separate
unprivileged client pinned to the published proxy. The provider receives only
its name, endpoint type/address/port and GUI flag through `CELLWARD_PROVIDER`,
`CELLWARD_PROXY_TYPE`, `CELLWARD_PROXY_SERVER`, `CELLWARD_PROXY_PORT` and
`CELLWARD_PROVIDER_GUI`; credentials are not put into its environment or argv.
Provider death stops the zone, and stopping the zone kills the provider.

`rust/src/provider.rs` implements the readiness check: SOCKS5 method and
optional username/password negotiation, or a bounded HTTP CONNECT response with
optional Basic authentication. A refused CONNECT to loopback port 1 proves HTTP
protocol readiness without resolving a name or sending application traffic;
authentication refusal and malformed responses are errors, and credentials are
never included in error text.

With `GUI = yes`, the uplink opens the compositor as the real user before
covering the runtime with a private tmpfs. It passes that one descriptor to
`wl-sandbox --require-proxy`, never `WAYLAND_DISPLAY` or the host socket path.
The sandbox registers a security-context connection and consumes the original
descriptor before the provider starts. The provider sees only the restricted
Wayland socket; missing compositor support, nesting or proxy startup failure
prevents the zone from coming up rather than allowing an unrestricted fallback.

## Scoped access to a zone

`cellward zone-proxy set <zone> <port> <zone|deny|host> [rules…]` enables a
loopback-only SOCKS5 and HTTP CONNECT listener on `127.0.0.1:<port>`. Only TCP
CONNECT is supported. The listener starts with the zone and stops with it;
`show` prints its non-secret configuration and `off` disables it.

A rule is an exact domain (`example.com`), a subdomain suffix
(`.example.com`), an IP or an IP network (`192.0.2.0/24`). Matched connections
always go through the zone. Domain names are classified before resolution and
resolved inside the selected network, not reclassified from the resulting IP.
The default controls unmatched connections:

- `zone`: everything goes through the zone;
- `deny`: unmatched connections are refused, never sent through the host;
- `host`: unmatched connections deliberately use the host network. This weakens
  isolation and is shown with a warning. Matched connections still have no
  direct fallback when the zone is down.

Example for FoxyProxy, with only selected sites through `nl` and the rest direct:

```sh
cellward zone-proxy set nl 1080 host youtube.com .googlevideo.com
```

Use `deny` instead of `host` to refuse every unmatched connection. The proxy is
an explicit convenience boundary, not a reason to expose the zone's whole
network namespace to host applications.

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
