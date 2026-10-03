# Permission input and network policy review

## Input

Selecting a network chooses a container's route. The per-program network
question separately authorizes new connections. Choosing a VPN therefore does
not itself answer a later program permission question.

The in-window panel previously required a quiet hover before **both** buttons
worked. Clicking earlier restarted the delay, without visible feedback. A
normal series of repeated clicks could keep the buttons unresponsive.

“Allow…” now accepts an ordinary press/release and opens the separate guarded
question. The proxy still cannot grant permission. Persistent denial retains
its hover guard and protection against application popups. The separate window
still requires keyboard focus and a quiet interval before accepting an answer.

After 15 seconds without a panel answer, the supervisor retracts it and hands
the request to the guarded window. It includes the original Wayland display,
even if the keeper's systemd environment names no display or a different one.
Late panel replies cannot answer a retracted question. The supervisor's poll
can add up to two seconds; the overall configured question timeout still
applies, so a shorter timeout may expire before this handoff.

This covers network, microphone and camera panels through their common
supervisor. Closing the final question still denies access. It does not
automatically grant access, create an allow rule or extend the question's
overall deadline.

## Network policy

An allowing answer is rechecked against the current policy before the keeper
releases held connections or writes an allow rule. A newly installed denial
wins over an answer to an older question.

Remaining boundaries found in this review:

- `relay::gated` gates TCP/UDP, but exempts DNS to the instance's forwarder and
  non-TCP/UDP frames. A program-level “deny” is not equivalent to the offline
  network. The question's existing “no network” wording overstates this rule.
  Complete network isolation uses the offline namespace. Changing the DNS
  exception requires per-program DNS attribution and its own leak tests.
- An answer without a persistent rule is cached for the container instance's
  lifetime. Closing and reopening one application may leave that instance
  alive. A specific explicit rule is checked before this cache on new flows;
  removing a rule does not clear an existing session answer.
  For a known program, `cellward container net <container> allow <program>`
  explicitly permits its new connections; `<program>` is the launcher ID.
  This is a targeted recovery option for an existing stuck session, subject
  to a stricter Nix policy. It does not change the container's chosen route.
- Unidentified programs share the `None` identity in the current asker. A
  temporary answer for one can affect other unidentified programs in the same
  instance. These rules do not isolate programs from each other inside a
  container; use separate containers for that boundary.
- Rule changes are evaluated for new flows. They do not revoke an already
  authorized connection. The stale-question fix also checks connections that
  were held waiting for a decision.

## Regression checks

Rust tests cover immediate handoff versus protected denial, fallback display
preservation, and denial installed while an allowing answer is pending.
`tests/vm-niri.nix` exercises real pointer input through nested niri, both panel
buttons, unattended handoff, and a real TCP request to a second VM: it must not
reach the HTTP server before permission, must reach it after explicit approval,
and must remain blocked when the question is closed. Sway's existing panel test
also checks the ordinary handoff click.

Screenshots are copied through the guest console, avoiding a guest netfs/9p
write-collector panic observed during repeated screenshot transfers under TCG.
