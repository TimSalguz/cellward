# Central authority for initial target selection

Status: implementation design, not an available security feature.

The current proxy binds Select/Type/Cancel continuations to a live process and
random token, but initial Select is not independently authorized. Do not mark
that audit issue closed. An unrestricted host process of the user's UID is
outside a container boundary; hiding a socket alone cannot isolate it.

## Rejected approach: one consent per launch

A guarded prompt before Select was prototyped in the supervisor, including
kernel-derived requester executable/PID, a fresh generation after approval,
cancellation and owner-death handling. It passed the existing 1140 unit tests,
which did not cover the new behavior. The prototype was removed before commit:
`window/src/clip_type.rs::select` broadcasts Select to up to 128 supervisors.
Per-launch authorization would create a pile of prompts and break point picking
from the tray. Existing tests being green is insufficient to accept that flow.

## Required replacement

Use the always-available host clipboard/input controller for a single selection
lease, independent of clipboard history. Authorization is once per live manager
operation, before broadcasting any Select. The trusted prompt names the process
from kernel peer credentials plus pinned pidfd, not a self-reported app name.
A clipboard manager may share this path with a future explicitly authorized
agent; executable-name lists are not the authority model.

After guarded human consent, issue an unguessable operation capability bound to:

- the exact requesting process, held by pidfd;
- the operation (select a target, not approve security questions);
- its permitted target scope and short expiry;
- cancellation/generation and single final surface selection.

A supervisor validates the capability through the live controller using the
actual peer's pidfd, never a PID provided in the wire payload. The existing
`shared/clipboard_endpoint.rs` transport already carries an owner FD and enforces
host user/PID/mount namespaces; extend an explicitly versioned controller
operation rather than trusting a token file in a same-UID-readable directory.
Controller failure/exit, dead requester, wrong principal/scope, stale generation
or expiry deny the request. A capability can be reused across the intended
broadcast's proxies only during selection; after the physical point choice,
Type authority belongs to that exact surface and owner. Keep current token and
continuation checks too. No host clipboard content is transferred implicitly.

The controller must not block its clipboard event loop while asking: retain a
bounded pending operation and poll the prompt result/owner liveness. Cancellation
must close/retract its prompt, release pending ownership and reject late replies.
A newer operation cannot be finalized by a duplicate approval of an old one.
No fallback to the old unauthenticated Select endpoint on an updated manager.

The manager UI should explain the two actions clearly: authorize selection once,
then click the target. Old/new protocol compatibility must fail explicitly, not
interpret binary control bytes as an ordinary permission question. A request to
name an arbitrary executable or to inject a secret is not itself consent.

## Acceptance

- One operation from the tray with many launches creates one prompt, then the
  normal target overlays, and types only into the clicked target.
- Same UID plus socket/token knowledge does not authorize another process;
  sibling containers and unconfined launches cannot forge a capability.
- Owner exit/PID reuse, controller restart, expiry, wrong scope and stolen
  capability all fail closed. Document the unrestricted host trust limit.
- Cancel during consent, point picking and typing is idempotent; release does
  not let a stale request act on a new surface or block another manager.
- Synthetic input cannot answer the authorization prompt. Verify real prompt
  keyboard/mouse guards, fullscreen, focus elsewhere and multiple windows.
- Update graphical typing regression, not only pure parser/owner tests; verify
  history on/off and both frame-launched and tray-launched managers.
