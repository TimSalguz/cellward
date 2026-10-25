# Window modes and firewall follow-up

## Window modes

Keep these independent: compositor fullscreen, application fullscreen inside
its existing window, and ordinary maximize/restore. A compositor can tile or
maximize a window with square corners without changing application fullscreen.
Do not infer a fourth application mode just from its corners. Verify niri's
actual configure states and geometry before changing its behaviour.

The frame editor has ordinary/fullscreen tabs. Fullscreen border width, title
visibility (including hover), and entry notice are independently editable.
Title/style/button/interaction choices have leased live previews; Save persists
them, Cancel or editor termination invalidates the preview. Zone/container
colours and global frame enable/disable still need the same preview treatment;
do not label the entire editor fully live yet. Separate fullscreen corner and
hover-edge overrides are also not implemented by these tabs.

Verification for this batch: 1106 core tests and 71 window tests passed.
The wire-level test checks that the new maximize button emits set_maximized,
not set_fullscreen. A live-watch test checks independent fullscreen updates and
Cancel rollback. These checks do not certify niri's visual behaviour on the
owner's desktop. A nested-niri smoke also passed for 1/4 px borders in
always/hover title modes: close-button hit testing, menu dismissal and no
click-through after the extra button changed the row width.
The production Nix build and its release checks passed. The VM driver was
built, but this batch was not separately executed in a VM.

## Paranoid firewall: required UI and semantics (not implemented yet)

Two views are required, not one:

1. Connection journal: allowed, blocked and pending attempts; timestamp,
   container, program/launch identity, current network, destination IP/port,
   protocol, observed DNS names with provenance, and deciding rule/reason.
   Include blocks that never establish a connection. Bound storage and expose
   retention/clearing controls; journal data is sensitive browsing history.
2. Rules: allow/deny, scope, creation/expiry, and enabled state. Edit, disable,
   delete or change any permanent decision. Offer the same operations from a
   journal entry. Rule edits affect new attempts; explicitly offer terminating
   established flows separately rather than implying they disappeared.

Prompt choices: this connection only, until program exit, for a selected
duration, permanently; and corresponding deny choices. “This connection” means
a kernel flow (UDP included), not each packet or HTTP request. Deduplicate
prompts and cap pending flows; cancellation/timeout/overflow must fail closed.
Pending questions must re-evaluate after a rule is changed, not overwrite a
newer decision with a stale answer.

Program/container is mandatory rule scope by default. Destination scope can
be IP or an explicitly selected exact hostname/subdomain/domain. DNS names
are observations, not a trustworthy reverse identity for arbitrary shared
IPs: define handling of shared hosting, DNS expiry, encrypted DNS and IP-only
flows before promising domain rules. Display the effective matching rule and
deterministic precedence, including conflicting allow/deny rules. Timers must
expire in the enforcement layer, not depend on the settings window being open.

Current program-level allow/deny/forget is a foundation, not this feature.
Strict launch ownership does not itself implement destination-level policy or
a complete allowed/blocked journal.
