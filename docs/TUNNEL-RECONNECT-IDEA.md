# Automatic tunnel reconnection (idea, not implemented)

Offer an explicit checkbox per published route/network: reconnect when its
tunnel stops responding, immediately or after a configurable grace period.

- Distinguish idle WireGuard handshakes from a tunnel that is actually down;
  use a deliberate liveness probe through the allowed route, not a host-side
  check that can expose a forbidden endpoint.
- Keep fail-closed throughout detection/reconnect. Do not fall back to direct
  host networking, another VPN or a shorter chain.
- Bound retry frequency with backoff, and make status/reason/next retry visible.
- Respect manual disconnect, manual/demand/always lifecycle and shared chain
  prefixes. Never reconnect a deliberately stopped or unpublished route.
- Handle sleep/resume and a lost host uplink without a restart storm. Define
  whether reconnecting a hop also restarts downstream hops and drops flows.
