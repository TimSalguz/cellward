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

A panel stays on the program's window until it is answered there. The
guarded window asks only where there is no window to show a panel on: the
program has none (a tray or background program), none appeared within five
seconds, or its windows closed while the question was open. It opens on the
original Wayland display, even if the keeper's systemd environment names no
display or a different one. Late panel replies cannot answer a retracted
question.

Network and camera questions have no deadline: held connections wait, and a
camera shows black frames, until the person answers or the program ends.
The microphone keeps its 25 seconds, under libpulse's own 30: a later "yes"
would open the microphone for a stream the program has abandoned. Closing a
question still denies access; nothing is granted by time.

Each program has its own network question, on its own window; several on one
window are shown one after another.

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

## Launch interface and capability limits

The launch window already treats the container and the network as independent
choices. A container owns its home and permissions; the network only chooses
where its packets go. The unchecked permission boxes are suggestions from the
program preset, not a complete permission editor. The complete granular editor
is still the `cellward container set|devices|grant|net` and `cellward trust`
CLI. Choosing
“No isolation” is the explicit way to give a program everything the host user
has while retaining the selected network and its anti-bypass policy.

Some powers intentionally are not ordinary grants. A Nix daemon configured
with the user in `trusted-users`, writable host startup/configuration paths,
the host session bus, and all devices can each amount to host control. PAM's
privileged password helper is not granted to containers at all. Noctalia stays
in the session core on the host until a narrow trusted authentication broker
exists.

Assigning a program to another container changes future launches, but does not
copy its existing files from the real home. `container merge` also deliberately
rejects the real home. A future import must ask for explicit source paths, keep
the originals, refuse cellward/session/credential state, and report conflicts;
silently guessing one application's profile is not safe migration.

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
