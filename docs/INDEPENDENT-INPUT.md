# Independent input channels

Requested 2026-10-27. This is a design and acceptance checklist, not a claim that
all devices or locking modes already exist.

## Existing foundation

The clipboard manager can select a particular window and inject text into that
window's Wayland connection while real keyboard focus is elsewhere. A live target
token identifies the surface; focus movement alone does not cancel typing.
During that run real keys/modifiers for the target keyboard are suppressed and
Escape cancels. This is scoped synthetic input, not a complete virtual seat.
Physical pointer motion/buttons are not yet a complete independent locked channel.
Selection continuations are now bound to the live requesting process and token
(pidfd); newline entry requires an explicit wire-level opt-in. Initial selection
authorization remains open; the centralized lease design and a rejected
per-launch-prompt approach are recorded in [TYPING-AUTHORITY.md](TYPING-AUTHORITY.md). See [typing control ownership](CLIPBOARD.md#typing-control-ownership-2026-10-27).

For windows handled by Cellward's frame, the `always_focused` policy already
maintains application-facing activation and focus state (`cellward container set NAME always-focused on|off|default`, Nix
`programs.cellward.containers.NAME.alwaysFocused`). It is read at launch; a live frame button still
needs implementation. This does not acquire real compositor focus or authorize
input injection. Application-visible activation and input ownership are different
settings and must remain independently understandable.

## Intended model

A container/window can have independent logical input channels: human, clipboard
entry, an explicitly authorized agent, and eventually virtual mouse, keyboard and
gamepad devices. A person can work in one window while an agent operates another.
No global host virtual-keyboard/pointer capability or raw host `/dev/uinput` is
handed to a container. A host-side broker routes input only to the authorized
live container and surface. Low-level evdev/gamepad backends must expose private
validated devices, not create arbitrary host input devices on a client's behalf.

The current trust boundary remains the container. This is not a claim that two
mutually hostile programs sharing one X server/container cannot affect each other.
Stronger per-program boundaries require separate containers/X servers or a further
application boundary.

Each active channel has a visible owner and an exclusive, revocable lease for its
target. Normal agent leases authorize application client-area input, not
answers to Cellward permission questions, clipboard imports, lease changes or
host settings. Synthetic events must not count as physical human authorization
in activation-token and permission-guard bookkeeping; administrative control
requires separate explicit authority.

Human keyboard focus, an agent's logical focus, application-visible
activation, cursor position, pressed keys/buttons, modifiers and keyboard layout
are separate state. Agent activity must not move the person's host cursor,
change their keyboard layout/modifiers, or type into another surface after focus
changes. Mouse coordinates belong to the target client area with explicit handling
of scaling, movement, resize and surface replacement.

While an agent/clipboard channel owns the target, optional/required-by-policy
physical-input exclusion suppresses real motion, hover, buttons, releases,
scroll, gestures and keys for that target. Other windows and host shortcuts keep
working. It must not merely swallow the press and leak its release, allow a real
click to change the target's text field, or leave a key stuck during hand-off.
A visible frame indication identifies the channel/owner, with Pause/Release and
a host emergency cancellation that works without focusing the target. Leases
expire or revoke on owner death, timeout, window destruction or broker failure;
no late events may reach a replacement window with a recycled identifier.

## First click only activates

User-facing name: **First click only activates the window**.
When the real pointer clicks an inactive protected window, focus moves there but
the complete initial button gesture is withheld from the client. It is not a
click, double-click component or drag start inside the application. A later
intentional click is delivered if the human channel owns the target. With an
agent lease, activation alone never overrides that lease. Define scroll/touch and
trusted frame-control behavior explicitly rather than accidentally inheriting it.
The actual compositor focus state must be used even when the application is told
it is always active. Host-wide behavior for windows outside Cellward additionally
requires compositor support; Cellward can enforce this for its proxied windows.

## Implementation sequence and checks

1. Fix keyboard ownership of embedded permission questions, including fullscreen
   and restoring normal delivery after answer/cancel.
2. Introduce the common lease/ownership state and adapt clipboard typing to it;
   add a visible busy indication and target-only physical-input exclusion.
3. Add a live “Keep application active” frame toggle, independently of ownership.
4. Add “First click only activates”; verify complete press/release suppression,
   double-click/drag handling, and first clicks during an active lease.
5. Add authenticated per-window mouse/keyboard channels for agents and virtual
   devices, then restricted gamepad/evdev compatibility for Wine/Proton/Steam.

Tests must run simultaneous channels in different containers, different clients, and
different windows of the same client connection: human
input stays with the human; agent input stays with its target. Cover Wayland and
X11, focus changes, overview, fullscreen, scale/movement/resize, held modifiers,
mouse buttons/scroll, owner crash, stale tokens, timeout and emergency cancel.
No agent event may reach the host or a different target, and exclusion must never
freeze input to unrelated windows. Do not advertise general independent devices
until these tests pass.
