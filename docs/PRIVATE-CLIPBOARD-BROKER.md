# Independent active clipboard: implementation checkpoint

The currently shipped desktop clipboard is still global. Separating history
directories or hiding MIME ownership markers does not stop a trusted host
clipboard manager such as CopyQ from recording ordinary focused copies.
Windowless X11 copies have a verified launch-local fallback, but that is not
the general instance broker described here.

## Implemented, without changing desktop behavior

`clip/src/broker.rs` stores independent CLIPBOARD and PRIMARY selections in
memory, keyed by opaque instance handles allocated by the trusted controller.
Replacement invalidates the old revision. Defaults: 64 instances, 64 MiB per
instance for both selections together, 128 MiB total, 64 MIME types, 256 bytes
per type. Rejections preserve the previous selection; there is no host fallback.

`clip/src/broker_transport.rs` now provides real Unix socket-pair endpoints.
The controller binds each server endpoint to one instance before giving the
other FD to a launch proxy. A request cannot supply an instance name, list
instances, register a scope, or transfer between scopes. Knowing another
selection's revision does not grant access. The trusted controller has a
separate `transfer_explicit` method, absent from the wire protocol.

The adapter is nonblocking and fair per tick (64 KiB in/out per connection).
It caps connections at 128, I/O buffers at 128 MiB globally and approximately
64 MiB per instance; these budgets are separate from retained selections.
Headers are checked before allocating, buffer capacity is charged, incomplete
requests/blocked responses expire after 5 seconds. There can also be bounded
temporary copies during decoding/serialization, up to roughly two maximum
payloads beyond the retained-selection and queued-I/O budgets. This is not
zero-copy transport. Allocation/limit failures do not export data elsewhere.
The caller can poll borrowed socket FDs and the next deadline without spinning.

Disconnecting one launch does not remove its instance's current selections.
Ending the actual instance revokes all its endpoints and wipes its buffers.
Payload-bearing transport and selection allocations are wiped with volatile
writes through their full capacity, including truncated spare bytes. No
history key, history file, Wayland global, public listener or network service
is opened by this component. It works without initializing history. This is
not a claim that OS paging/swap is disabled; that needs a daemon-level policy.

## Evidence

Real socket-pair tests exercise same-instance sharing, cross-instance read
denial with a known revision, forged trailing identifiers, separate PRIMARY,
source replacement, launch/instance lifetimes, partial frames, timeout/fairness,
oversized headers, budget rejection, explicit controller-only transfer, and
erasure of truncated secrets. Additional malformed frames are checked against
another instance containing a synthetic secret. Existing store/CLI tests also
remain green. These tests exercise the transport, not graphic protocol adapters.
On 2026-10-25 the full library run passed 45 tests (one large benchmark ignored),
plus 3 CLI tests; compilation and execution used one job/thread and peaked at
approximately 0.5 GiB sampled process-group RSS.

## Integration still required

### FD client checkpoint, 2026-10-26

`shared/clipboard_client.rs` is now compiled by both the core and clipboard
crates. It accepts only an already-scoped Unix stream: no instance name,
registration command, socket discovery or host fallback. It supports typed
CLIPBOARD/PRIMARY types/set/read/clear requests, bounded nonblocking I/O,
complete reply validation, one in-flight operation and a five-second deadline.
Protocol/transport failure closes the endpoint. A valid broker refusal is
returned explicitly, never translated to a host read. Payload buffers erase
their entire capacity and are freed after exchange; Debug redacts payloads.

An interoperability test uses the real server transport and client, including
a 300 KB binary image plus text, another launch in the same scope, a foreign
scope, stale revisions and independent PRIMARY. Fragmented replies, malformed
lengths, timeouts and request validation are also tested. This is **not** the
Wayland/X11 adapter and does not yet change active desktop selections.

The manager's interim copy action is now available from frame history as well
as the tray, including images and while character-typing controls are shown.
It explicitly says **desktop clipboard** because it still exports to the
shared selection. Password confirmation remains separate. This is not the
final “copy into the selected container” operation.

The final manager UI must identify a **live instance**, not infer it from a
history tab: a history can outlive its instance or aggregate several instances.
Copy to that instance must not paste into a window or publish to the host.
Host export/import must be a separate explicit action. Opening/switching tabs
must never change any selection; absent instances must not start implicitly.

Verification of this checkpoint: 1112 core tests, 51 clipboard-library tests,
4 clipboard-command tests and 72 window tests passed. Production Nix builds
of the core/window integration and clipboard package passed. Headless Wayland
smokes from tray and frame history click Copy, verify the explicit `copy`
request without target insertion or closing, then exercise character input
and theme preservation. The fake history daemon used by these UI smokes does
not implement the actual compositor selection; daemon unit tests separately
verify preserving image/text MIME payloads without recording a paste.

1. Run a hardened host controller independently of `clipboard.history`. Its
   registration/UI endpoint must be hidden from containers; same Unix uid
   alone is not proof of a trusted host supervisor. Mint scoped application
   FDs only on trusted registration, and bind to a stable live instance, not
   a VPN name or history tab. Do not reset the clipboard on a network switch.
2. Pass scoped FDs only to the restricted proxy, preserve them through its
   FD cleanup, and add readiness handling to its poll loop. Do not give a
   container a controller/admin FD or a path for choosing another scope.
3. Consume all ordinary Wayland CLIPBOARD and PRIMARY writes locally,
   regardless of keyboard serial. Fetch source payloads asynchronously with
   bounded pipes/timeouts; announce the new revision only after acceptance.
   Source failure must not trigger a direct compositor write or silent fallback.
4. Deliver current offers/revisions to every proxy of the instance, including
   unfocused/windowless Satellite connections. Cover PRIMARY's windowless
   X11 publication as well as CLIPBOARD. Keep stale offer reads pinned to their
   revision, never accidentally reading a newer password.
5. Subscribe the optional recorder directly to instance copies (otherwise
   removing global publication would also stop history). Honor per-container
   recording preferences. Active selections must work when history is off.
6. Connect the host manager to explicit import/export/transfer operations;
   do not make tab switching or opening a window publish any selection.
   Intended policy: ordinary Ctrl+V uses only the container's clipboard, with
   host imports through the manager. An additional explicit host-import
   shortcut is a separate future convenience. No implicit focus-based import.
7. Verify two real instances, multiple launches per instance, host CopyQ-like
   data-control observer, restart/exit, history on/off, both selections and
   text/images. Neither application clipboard writes nor focus changes may
   update the host. Then enable the behavior and update the doctor/UI text.

The older fallback ladder in `wl-sandbox` must also be reviewed before enabling
private mode: failure to start its proxy currently can fall back to a compositor
security-context connection. That connection cannot enforce private clipboards.
Private mode must fail closed instead, with an explanation to the user.
