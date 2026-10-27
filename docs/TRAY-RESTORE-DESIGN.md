# Restore a selected running instance from the tray

Status: implemented and integration-tested, 2026-10-27.

Previously `Again::There` only searched for an existing compositor window.
It did not activate a hidden tray item and could select a launch from another
environment. The picker now restores only the selected network/container launch,
reports failure, and never starts another application copy as a fallback.

## Scoped activation

1. Select the exact live launch for the dialog's network/container, pin its PID
   with pidfd and verify registry start identity. Focus immediately if a window
   exists. Do not silently pick another instance with the same program key.
2. Discover StatusNotifierItems on the host session bus. Prefer both watcher's
   RegisteredStatusNotifierItems lists (including custom object paths); add
   well-known StatusNotifierItem names at /StatusNotifierItem as fallback.
   Resolve names to unique owners on the same live D-Bus connection; no persistent
   name-to-process cache or bus-restart identity ambiguity.
3. A private incoming method `org.cellward.Tray.ActivateIfOwned` can carry a
   bounded array of pidfds for the selected launch's live descendant processes.
   A host descriptor, interpreted in the namespace of the filter's procfs mount,
   refers to the same kernel process even when host and app PID numbers differ.
4. The session bus filter retains its actual client peer pidfd. Intercept the
   private method before it reaches the application. Compare the live client
   against the passed live pidfds (exact equality in the same procfs view); reject malformed requests, non-pidfds,
   dead peers and other launches. Never let applications self-report identity.
   Close all received pidfds; never forward them to the application.
5. Only on a match, rewrite the request to ordinary SNI Activate(0,0) on that
   connection's own object path, without Unix FD header/body. Preserve caller,
   call/reply correlation. A nonmatch returns a bounded NotOwner error.
   This operation grants no authority beyond ordinary SNI activation; it is not
   an input-channel lease and cannot approve a Cellward security question.
6. Serialize upstream writes in the bus filter as well as downstream writes:
   synthetic NotOwner replies and normal app messages must not interleave.
7. After activation, wait for and focus only a window of the pinned launch.
   Return/notify meaningful failure if unsupported; never report success for a
   vanished/reused process or unrelated window. No second app copy as fallback.

## Implementation notes

- A small host D-Bus client can reuse dbus_wire framing/fields and Unix FD
  helpers, with AUTH EXTERNAL, NEGOTIATE_UNIX_FD, BEGIN, Hello, bounded reads,
  per-call/global deadlines and reply serial validation. Avoid spawning a helper
  that drops received pidfds or parsing unbounded busctl output.
- Add bounded as / variant-as readers to dbus_wire rather than ad-hoc indexing.
- Candidates come from a live, verified launch tree (bounded breadth-first),
  not process names or titles. Hold process references while checking ancestry.
- Conn retains the original Peer as well as Who. OwnConn, registration and
  synthetic response writes share upstream serialization.
- Host/unproxied SNI services may not implement the private method. Do not claim
  their identity from untrusted SNI Id/title strings. Report unsupported instead
  of activating arbitrary other applications.
- Integrate scope into both Again::There and post-handover raising.

## Acceptance

- Hidden fake SNI app remaps a real window on Activate; selected launch focuses.
- Visible app focuses without unnecessary activation or another window.
- Two instances/containers, other app in same container, dead/reused peer, malformed
  or excessive FD array, arbitrary FD, changed bus owner and missing SNI.
- Prove descriptor closure and no pidfd reaches the app; parallel bus replies stay
  whole. Cover custom SNI paths and both namespace PID numberings.
- Native protocol tests first, then headless compositor/VM integration. Existing
  1128 core tests and 76 GUI tests must remain green; cargo uses -j1.

Kernel reference: [pidfd_show_fdinfo](https://code.googlesource.com/linux/torvalds/linux/+/dab01c597f6bd40e0efe7da967b8374ca1971b79/fs/pidfs.c).
Its PID is relative to the procfs mount, not necessarily the filter's active PID
namespace. Compare both held pidfds in that same view; do not compare fdinfo PID
to SO_PEERCRED PID or feed it to pidfd_open in a different namespace. Invisible
references (0), exited references (-1) and arbitrary non-pidfds cannot match.

## Validation and limits

`tests/tray-restore-smoke.py` passed on a private headless Sway compositor and
session bus, with the real `xdg-dbus-proxy` and each app/filter in separate
user/mount/PID namespaces. The Wayland supervisor remains outside those
namespaces as in a normal container launch. It verifies custom SNI paths,
restoring the selected hidden instance despite another container being inserted
after the dialog opens, focusing a visible instance without activation or a
second window, and repeated hide/restore. The fake application rejects any
received Unix descriptors; process references never reach it. This is a native
integration check, not a NixOS VM run or a Telegram/AyuGram-specific test.

Protocol tests cover malformed arrays, foreign owners, arbitrary descriptors,
reply sender checks, message bounds, FD negotiation and transport. Missing or
unproxied tray items fail explicitly. Apps without SNI are unsupported; existing
containers must be stopped and started after updating their bus filter. No
application-name heuristics or unverified activation fallback are used.
