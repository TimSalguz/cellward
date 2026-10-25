# Network ownership: evidence, retained identity and remaining gaps

## What changed (2026-10-25)

The keeper used to match every socket through `/proc/<space>/net/*`, even
when falling back to the kernel's `sock_diag` cgroup information. An
inaccessible procfs table therefore disabled both lookup paths. Kernel socket
endpoints are now an independent input: TCP/UDP local ports, remote endpoints,
inodes and birth-cgroup IDs are obtained through the instance's diagnostic
socket. They do not need a readable procfs socket table.

The keeper snapshots proven birth-cgroup-to-launch associations and retains
them while the socket/cgroup evidence remains. A partial/failed kernel dump
does not count as proof that a socket disappeared. This cache is bounded to
twice the flow-table capacity; it is not an unlimited process archive.

An already-attributed flow retains its program after socket/process exit.
Its key includes the flow's first-seen value, so reusing a port/tuple does not
inherit the old flow's allowance. A historical numeric PID is not used to
address a new window: archived flow records clear that destination, and a
cached cgroup origin checks the waiter's start time before addressing it.

The old heuristic “all unreadable processes belong to one launch, so this
unheld socket must be theirs” has been removed. It did not prove ownership:
process enumeration itself can be incomplete. Likewise, multiple distinct
sockets matching the same relay key (e.g. reuseport) are ambiguous, not an
excuse to select the first application.

`cellward doctor <network>` now includes `network-owner` per running instance.
Its private `owner-status` file contains last-round counters only: procfs/kernel
socket counts, diagnostic-channel availability, failed kernel dumps, cached
origins, flows and unresolved programs. It contains no payload or destination.
Missing data is “not checked”, not a success. The keeper clears the report on
startup so an older instance's result is not reported as the new one's.

## What “archive” currently means

The instance's `owners` file and the keeper's `found` map retain **observed,
proven** flow identities. The connection journal has its own documented
retention/size limits (`connlog`), not infinite retention. Neither is a trace
of every kernel socket creation, every process, nor every descriptor transfer.
Process and socket metadata never collected cannot be recovered merely by
retaining subsequent observations longer.

The attribution priority is: retained identity for that flow generation,
kernel birth-cgroup identity, then directly observed descriptor holder. Those
are evidence sources, not guarantees that every possible packet has a known
launcher. The existing unknown-flow firewall policy is unchanged; no shared
allowance or guessed permanent application rule has been introduced.

## The stronger invariant still requires a separate implementation

To claim that every outgoing connection is attributable by construction:

1. Register a trusted launch identity before its program can create sockets.
2. Associate socket creation and egress with that identity in a trusted
   mechanism, not a delayed procfs scan. Bind identities to generations and
   socket cookies, not reusable process IDs or tuple strings alone.
3. Keep metadata until held traffic and all required consumers have finished,
   even if the originating process/socket has already exited.
4. Detect unsupported mechanisms, lost events, exhausted maps and ambiguous
   ownership. Fail closed with a visible diagnostic rather than silently
   assigning another application or pretending collection was complete.
5. Verify rapid UDP exit, TCP, QUIC, multiple browsers, reuseport, descriptor
   transfer, network switching, PID/port reuse and collector restart in actual
   namespaces. Define inherited/shared-socket policy explicitly.

This document does not select or enable a privileged kernel collector. Such
a collector's authority, availability on supported kernels and failure modes
must be designed before it is installed. The present fixes are useful and
tested, but are **not** that complete creation-time mechanism and must not be
advertised as “unknown application is logically impossible”.
