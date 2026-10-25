# Strict egress ownership

Status (2026-10-26): **strict ownership is the default for new instances**.
No extra enable option is needed. Running
legacy instances must be stopped/restarted: they cannot acquire strict identity
retroactively. Explicit `cellward defaults set strict-network off` or
`programs.cellward.defaults.permissions.strictNetwork = false` selects the
legacy compatibility backend; a failed strict startup
never selects it automatically. Do not stop somebody's active apps implicitly.

Requirements: Linux 6.5+ (`SO_PEERPIDFD`), delegated launch cgroups,
`nft socket cgroupv2`, NFQUEUE and a host-managed launch with a live registry
generation. Unsupported/missing prerequisites refuse startup. `status --json`
reports `network_ownership`; `doctor` reports strict availability. After collector
failure its sticky required marker prevents an unregistered fallback launch.
Launches must originate below the delegated user manager. CLI launches from
outside it now automatically hand off through a transient user service. A
host-authenticated Unix socket transfers byte-exact argv/environment, the cwd
descriptor and optional window notification pipe. Standard I/O is checked
before delegation; failure refuses startup rather than sharing an identity.
This extends [the procfs-independent lookup fix](NETWORK-OWNERSHIP.md).

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
  death. Tokens are never reused within a session. The live cache holds 4096
  launch records; a private append-only archive restores evicted identities
  without re-reading a dead process. Pending identities cannot be evicted.
  Archive storage and kernel mappings still consume resources; this is not an
  unlimited lifetime guarantee. Pending packets are bounded by 1024 and a
  smaller kernel queue limit derived from the actual receive buffer.
  A single launch may retain at most 64 pending packets, independently of the
  instance-wide 1024 limit. Rejection does not evict another launch's identity;
  deciding or draining a packet restores its launch's quota.
- A fresh controller-supplied session generation, network epoch, policy revision
  and request nonce bind decisions. Stale/forged tickets cannot consume a newer
  request. Policy/epoch transitions return pending packets to drop; old socket
  tokens cannot authorize traffic in a new network epoch. Replay or wrap of
  kernel packet IDs closes the model session; production must close the queue
  too, not just reset an integer and reuse old identifiers.
- `rust/src/netqueue/wire.rs`: bounded, atomic netlink/NLA parser; kernel sender
  checks, truncation/overrun refusal, critical-attribute validation, native vs
  network byte-order handling, individual ACCEPT/DROP verdicts, and bounded
  metadata-only or bounded-header queue configuration with FAIL_OPEN explicitly disabled. Attribution
  marks are cleared in verdicts rather than leaked into routing decisions.
- `rust/src/netqueue/socket.rs`: explicit nonblocking, close-on-exec
  NETLINK_NETFILTER adapter. The peer identity comes from recvmsg sockaddr_nl,
  not a user-supplied nlmsg header. No firewall rule is installed by opening it.
  The live driver transiently copies at most 4096 packet-prefix bytes to decode
  addresses/protocol/ports; only those fields survive parsing. Payload bytes are
  not archived. The metadata-only codec remains available for kernel probes.
- `rust/src/netqueue/driver.rs`: socket-owning runtime adapter. Binding and
  individual verdicts require exact outstanding sequence ACKs; unexpected,
  failed or missing ACKs close the actual transport and invalidate the model.
  Sequences never wrap. Before counter exhaustion, a fail-closed egress fence
  permits queue replacement with a fresh ticket generation, retaining archived
  launch identity and completed grants but cancelling pending questions.
  Normal traffic uses bounded rounds with individual asynchronous verdict ACKs;
  policy transitions still synchronously acknowledge their DROP barrier.
  Packets arriving while awaiting an ACK are retained
  under the same bounds, not ignored. Unknown/unarmed/old-epoch identities are
  dropped without presenting an ownerless permission question. Policy/epoch
  changes acknowledge DROP of outstanding tickets; late UI callbacks cannot
  authorize them or close a healthy successor. External egress fencing and
  policy/route installation remain the integrating supervisor's responsibility.
- `rust/src/netqueue/gate.rs`: inherited CLOEXEC socketpair pre-exec barrier,
  with consuming prepared/release transitions. EOF, timeout or malformed replies
  abort the child's wait, never authorize execution. No public socket pathname.
  `enter::run` uses it in strict mode and drops opposite fork endpoints before
  waiting. The trusted controller checks child membership before registration.
- `epoch::Epoch::place_launch_strict`: dedicated, newly created launch cgroup
  placement with no fallback to a shared epoch or denied group. Existing
  cgroups are refused rather than silently reusing identity. The legacy
  `place_launch` remains for explicitly selected legacy mode only. Strict mode
  also refuses host IP/packet/control sockets inherited through standard I/O;
  higher descriptors are close-on-exec. Existing Unix logging/IPC channels are
  not claimed as isolated IP traffic.
- `netask::Asker<netqueue::Ticket>`: typed UI adapter using the actual packet
  ticket, never reconstructing a verdict target from destination tuples.
  Question/session allowances are scoped to queue session, network epoch,
  policy revision and launch token. Two launches named `firefox` remain distinct.
  At most eight strict question workers can exist, including cancelled workers
  still exiting; packet/request retention has the queue's total/per-launch caps.
  `cancel_all` invalidates replies **before** persistence, so an obsolete
  "always" cannot rewrite a successor policy. It also wakes blocked panel
  reads and kills/reaps its own separate question windows. Pollable cancellation
  uses CLOEXEC pipes, not a polling timer that expires unanswered permissions.
  Panel connections with a recorded generation validate kernel-pinned peer PID
  and start time before sending the question. A reused numeric PID is refused.
  Inner supervisor/proxy panels and typing requests use a nonwrapping 64-bit
  sequence (not the previous wrapping 8-bit value). Fragmented replies are
  buffered up to their bounded frame length and cannot consume the next control
  opcode. High generation bits survive question, reply and cancellation.
  The explicitly selected legacy relay uses `Asker<flows::Key>`. In strict
  instances its tuple-based authorization gate is disabled, avoiding both an
  accidental second allowance source and duplicate permission questions.
- `strict_network::Runtime`: owns the live driver, registered cgroup mappings,
  typed question queue and policy/epoch transitions. Registration authenticates
  the kernel-pinned Unix peer, global `.running/.started` generation, unique
  launcher key, direct-child relation and exact epoch-root launch cgroup. It
  does NOT depend on ptrace-protected namespace symlinks hidden by non-dumpable
  waiters. Apps cannot create an epoch-root sibling: cgroupfs is covered and a
  cgroup namespace they can mount is rooted below their own launch group.
  Diagnostic launches have an explicit always-IP-denied registration, not a
  guessed application or automatic network permission.
- A distinct nft table clears application marks, classifies registered socket
  birth cgroups, queues them, and drops unmatched egress. Loopback and the
  existing link-only NDP infrastructure exemption are preserved. Registration
  appends one rule and waits for nft's kernel transaction success before token
  activation/releasing exec. It never re-resolves swept archived directories;
  existing rules retain their kernel identities. Network renewal happens while
  fenced/frozen, drains old tickets and registers new cgroups before attachment.
  Supervisor lock acquisition is nonblocking: a switch cannot deadlock against
  an entering launch that is waiting for registration while holding LOCK shared.

None of these APIs makes UI-provided tokens/generations authoritative. They
are trusted-controller building blocks. A `Decision` is preliminary until the
runtime validates its current binding/policy and successfully sends/ACKs it.
Unexpected messages, failed verdict delivery and ENOBUFS/truncation/overrun
must close the queue, invalidate pending UI replies and surface one bounded
operational error. There must be no bypass/default allow fallback.

## Verification performed

The clean commit tree passed **1087 core unit tests** (six explicit platform/
kernel tests ignored by the ordinary run). The working tree, including separate
clipboard work, passed 1099. The production nft classifier's explicit native
preflight and both IPv4/IPv6 queue smoke suites passed as well.

`tests/vm-strict-network.nix` passed in two disposable NixOS VMs under QEMU TCG
(Linux 6.18.56). It checks real registered HTTP egress, refusal of an unregistered
process in the same network namespace, an observed connection denial before
granting a running process access, subsequent revocation/re-grant, diagnostic
registration, and host/offline/host network transitions. This is a focused
headless integration test, not a complete browser/GUI or protocol stress suite.

The expanded 2026-10-26 default-path run passed in 166 seconds, without an
explicit `strictNetwork = true`: private DNS, 2.4 MB TCP download/upload,
57 KB UDP echo, a fresh queue capped by `rmem_max = 212992`, distinct program
allow/deny rules within one container, and two queue rotations with a running
client and a real PTY CLI handoff were added to the scenarios above.
The native IPv4/IPv6 failure suites
and nft preflight also passed. Neither test writes the real host firewall.

Queue/barrier/header unit tests cover token reservation/activation, stale sessions,
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

Seven cases passed for **both** families:

1. Reap a short UDP process before receiving its queued packet. The cgroup
   token still names the launch; an individual ACCEPT delivers the held data.
2. Set SO_MARK in the sender. The trusted classification overwrites it; an
   individual DROP prevents delivery.
3. Install an intentionally unregistered test token. The model rejects it,
   and the adapter's DROP prevents delivery instead of selecting another app.
4. Close the collector with a packet held, then send another packet with no
   queue listener. Neither is delivered; no fail-open or queue bypass occurs.
5. Use the runtime driver to bind, hold a packet with immutable launch identity,
   and acknowledge an individual ACCEPT.
6. Change policy with a packet held. It is dropped; its old UI ticket cannot
   authorize it, and a subsequent valid request still works.
7. Change epoch: old identities are automatically denied without a question.
   Register/map a fresh token; explicit driver close drops its held packet and
   leaves no bypass for later sends.

The probe uses one cgroup (the test namespace's cgroup root), not distinct
production launch cgroups. Thus it proves the short-UDP/kernel mechanism and
failure behaviour, **not** multi-application production integration. Peak
sampled userspace RSS was about 25 MiB; kernel resources were small and bounded.
Compile and run sequentially beneath `tests/run-memory-guard.py`.

## Limits and remaining coverage

1. The bounded decoder handles IPv4 options, checked IPv6 extension chains and
   atomic fragment headers. Unsupported/truncated fragmentation drops rather
   than guessing. Other IP protocols retain launch identity and require explicit
   policy, not the legacy automatic protocol allowance. Broader GSO and DNS
   integration stress still need dedicated tests; destination-level approval
   is not promised by launch ownership.
2. Queue rotation is implemented before packet/verdict sequence exhaustion.
   Archive token exhaustion and finite disk/kernel resources still fail closed;
   no tombstone is reused for a different owner. Capacity/unsupported-kernel
   conditions are operational failures, not ownerless permission questions.
3. Expand multi-launch namespace/VM regression tests: two actual birth cgroups, same
   tuples/reuseport, rapid UDP, TCP/QUIC, DNS, passed FDs, network switches,
   policy changes, startup races and collector crashes. The focused
   `tests/vm-strict-network.nix` exercises actual supervisor registration,
   registered/unregistered egress, permission changes on a running process,
   doctor and host/offline/host transitions; that focused run passed as recorded
   above, with default selection, DNS, large transfers, constrained buffers and
   queue rotation covered too. The broader adversarial matrix remains ongoing
   regression work, not a claim that every protocol/browser is proven correct.
4. Preserve the distinction between a launch identity (including terminal
   descendants) and an exact currently executing binary. The legacy monitor's
   tuple/procfs display is not a strict authorization source. Host Unix services
   and cooperating processes in the same container remain outside this IP-egress
   identity boundary. This backend is never applied to the real host namespace.
