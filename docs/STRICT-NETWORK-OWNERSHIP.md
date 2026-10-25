# Strict egress ownership: kernel-queue foundation

Status (2026-10-25): **implemented and kernel-probed foundation, not enabled
for application launches**. There is no new user setting that silently turns
this on. The existing relay/firewall remains unchanged. This is the next stage
after [the procfs-independent lookup fix](NETWORK-OWNERSHIP.md).

## Invariant and mechanism

The useful invariant is not “an observer eventually names every process”. It
is: **every application packet allowed out has a trusted launch identity;
otherwise it is dropped, never attributed by guessing**.

This claim is scoped to the instance's controlled IP egress, not all host
services/side channels or a new isolation boundary between cooperating apps
sharing a container. Uncontrolled inherited network descriptors and raw/L2
bypasses must be excluded before making the claim in production.

A candidate path uses the existing socket birth-cgroup boundary at the
kernel's OUTPUT hook. The controller reserves a nonreused launch token before
exec, installs the cgroup-to-token classification rule and waits for its
kernel acknowledgement. Only then may it activate the token and release the
child. OUTPUT clears application-controlled packet marks before classifying.
NFQUEUE holds the packet and exports that token to the trusted collector.
The packet identity therefore does not depend on a subsequent process/fd scan.

This is supported by the Linux implementations of
[nft socket cgroupv2 at LOCAL_OUT](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nft_socket.c)
and [NFQUEUE metadata/verdict handling](https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nfnetlink_queue.c).
Wire definitions follow the
[kernel UAPI](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/netfilter/nfnetlink_queue.h).
These references inform the implementation; tests on the actual kernel are
still required, not replaced by reading source.

Tokens describe a **Cellward launch and its inherited birth-cgroup**, not
proof of the exact executable currently holding a descriptor. A passed socket
keeps its creator's launch identity. A program started raw inside a terminal
inherits that launch unless explicitly launched through a separately registered
Cellward launch. These semantics must be visible in permission wording.

Do not authorize through the relay's tuple-only lookup once this path becomes
authoritative: reuseport and tuple reuse must not share allowances across
launch tokens. The NFQUEUE packet identity is the decision target; tuple/DNS
information is display/logging data, not the identity.

## Implemented components

- `rust/src/netqueue.rs`: bounded launch/ticket state. Reservation is distinct
  from activation; an unactivated token cannot hold an authorizable packet.
  Registrations retain immutable program and generation data after process
  death. Tokens are never reused within a session. Limits are 4096 launch
  records and 1024 pending packets, with explicit capacity failures, no eviction
  into another identity and no automatic approval.
- A fresh controller-supplied session generation, network epoch, policy revision
  and request nonce bind decisions. Stale/forged tickets cannot consume a newer
  request. Policy/epoch transitions return pending packets to drop; old socket
  tokens cannot authorize traffic in a new network epoch. Replay or wrap of
  kernel packet IDs closes the model session; production must close the queue
  too, not just reset an integer and reuse old identifiers.
- `rust/src/netqueue/wire.rs`: bounded, atomic netlink/NLA parser; kernel sender
  checks, truncation/overrun refusal, critical-attribute validation, native vs
  network byte-order handling, individual ACCEPT/DROP verdicts, and bounded
  COPY_META queue configuration with FAIL_OPEN explicitly disabled. Attribution
  marks are cleared in verdicts rather than leaked into routing decisions.
- `rust/src/netqueue/socket.rs`: explicit nonblocking, close-on-exec
  NETLINK_NETFILTER adapter. The peer identity comes from recvmsg sockaddr_nl,
  not a user-supplied nlmsg header. No firewall rule is installed by opening it.
  Metadata only is retained; packet payloads are not archived.

None of these APIs makes UI-provided tokens/generations authoritative. They
are trusted-controller building blocks. A `Decision` is preliminary until the
runtime validates its current binding/policy and successfully sends/ACKs it.
Unexpected messages, failed verdict delivery and ENOBUFS/truncation/overrun
must close the queue, invalidate pending UI replies and surface one bounded
operational error. There must be no bypass/default allow fallback.

## Verification performed

21 unit tests pass, including token reservation/activation, stale sessions,
policies/epochs, replay/wrap, bounded capacity, malformed messages and byte
orders. They can be compiled without rebuilding the rest of core:

```sh
rustc --edition 2021 --test rust/src/netqueue.rs \
  --extern libc=/absolute/path/to/matching/liblibc.rlib -o /tmp/netqueue-tests
/tmp/netqueue-tests --test-threads=1
```

`tests/netqueue-kernel-probe.rs` and `tests/netqueue-kernel-smoke.py` exercise
the actual kernel, separately for IPv4 and IPv6. Each run creates fresh user
and network namespaces, then private mount/cgroup namespaces with a read-only
cgroupfs view. No host cgroup is created/moved/written, no host firewall rule
is installed, and no VM is started. Firewall setup in the outer network namespace,
a non-disposable UID mapping or a namespace with extra interfaces is refused.

Four cases passed for **both** families:

1. Reap a short UDP process before receiving its queued packet. The cgroup
   token still names the launch; an individual ACCEPT delivers the held data.
2. Set SO_MARK in the sender. The trusted classification overwrites it; an
   individual DROP prevents delivery.
3. Install an intentionally unregistered test token. The model rejects it,
   and the adapter's DROP prevents delivery instead of selecting another app.
4. Close the collector with a packet held, then send another packet with no
   queue listener. Neither is delivered; no fail-open or queue bypass occurs.

The probe uses one cgroup (the test namespace's cgroup root), not distinct
production launch cgroups. Thus it proves the short-UDP/kernel mechanism and
failure behaviour, **not** multi-application production integration. Peak
sampled userspace RSS was about 25 MiB; kernel resources were small and bounded.
Compile and run sequentially beneath `tests/run-memory-guard.py`.

## Required before strict mode can be offered

1. Trusted registration IPC: resolve the launch in the host supervisor, pin its
   instance/process generations and its dedicated cgroup, reserve the token,
   install the mapping atomically, verify the precise kernel ACK, activate it,
   then release exec. Lost registration, parent death/EOF and failed cgroup
   placement must stop startup, not execute in an unregistered fallback group.
   Fix lock ordering explicitly: the current enter path holds the instance's
   shared lock, so a registration handler must not deadlock waiting for it
   exclusively before answering.
2. A production classification table whose unmatched packets DROP. The probe's
   narrow UDP rule and otherwise-accepting loopback test table are **not** this
   policy. Use dedicated per-launch cgroups, correct cgroup-namespace levels and
   proper nft string escaping for systemd's literal backslashes. Preserve the
   existing epoch/deny wall after queue reinjection. Never trust SO_MARK alone.
3. Handle DNS, trusted infrastructure traffic, kernel-generated ICMP/NDP,
   fragments/GSO, inherited and transferred sockets explicitly. Do not add a
   broad exemption for traffic whose identity was missing. Keep isolated
   application namespaces distinct from “without isolation”; do not apply an
   experimental policy to the host network namespace.
4. Collector lifecycle, ACK correlation (including request-sequence exhaustion)
   and bounded UI integration, with per-launch quotas so one unanswered app
   cannot occupy the entire queue. Queue
   configuration currently copies metadata only: destination display needs
   separately designed bounded header/conntrack metadata, not guessed tuple
   ownership or indiscriminate payload archiving. Tie approvals to token/session
   generations and handle policy/network switches before releasing old traffic.
5. Implement safe session rotation before token, record or packet-ID exhaustion.
   No tombstone may be deleted while delayed kernel messages, held packets or
   old UI replies could refer to it. Restarts do not reuse a live queue's old
   identity. Capacity/unsupported-kernel conditions are startup/operational
   failures, not an “unknown application, allow?” modal per connection.
6. Multi-launch namespace/VM regression tests: two actual birth cgroups, same
   tuples/reuseport, rapid UDP, TCP/QUIC, DNS, passed FDs, network switches,
   policy changes, startup races and collector crashes. Existing mode remains
   the default until these pass. Do not label this foundation a finished fix.
