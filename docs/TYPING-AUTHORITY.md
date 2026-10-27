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

## Implemented foundation (not wired authorization)

`clip/src/input_authority.rs` contains a bounded volatile lease store: 256-bit
getrandom capabilities, held pidfd principal, two-minute selection lifetime,
repeatable validation for a broadcast, principal-bound revocation and removal
on owner death/expiry. A fresh controller has no old capabilities. Tokens are
redacted in Debug. Only trusted completed consent may call `issue`; the module
is not a public control socket operation and is not yet called by the input
proxy/manager. The audit item remains open. Tests passed: 58 clip library tests,
one unrelated ignored, including foreign process with a known token, dead owner,
expiry, controller restart, arbitrary non-pidfd and revocation.

Next integration steps:

1. Extend the clipboard controller with a separately versioned authorization
   operation. Capture the real requesting socket's peer pidfd (not an owner
   descriptor supplied by that requester). Obtain the trusted window path from
   the Nix service configuration. Keep the default API denied without that path.
2. Poll one bounded consent prompt asynchronously, with owner-death and client
   disconnect cancellation, guarded safe-first answers and fresh generations.
   Do not block clipboard service; the existing 3-second control deadline must
   not be reused as the human-consent deadline.
3. Add capability validation/revocation RPC using an actual held subject pidfd
   captured by a trusted target supervisor. All decisions fail closed.
4. Add versioned authorized Select wire encoding; require authority on the
   supervisor before sending any selection overlay. Preserve Type/Cancel live
   owner binding and explicit newline policy. No legacy Select fallback.
5. Manager obtains one lease before broadcasting to candidate supervisors, then
   revokes it on selection/cancel. No prompt per target. Adapt graphical smoke
   tests for actual centralized consent, including tray and frame managers.

The clipboard controller now holds the authority registry, polls lease-owner
pidfds and expiry deadlines, and exposes versioned V/1 validation and X/1
revocation operations. Validation receives the supervisor-held subject pidfd;
revocation pins the actual host socket peer. The shared transport captures a
held host principal via `host_owner` while preserving namespace checks. There
is still no public mint operation or consent prompt wired into this controller,
and no input proxy/manager use of these validation methods yet. The new RPC
therefore does not close initial-Select authorization. Clip tests: 61 passed,
one unrelated ignored; real socket regression includes a foreign same-UID test
process trying to revoke a known capability.
