# Links, source environments and shared workspaces

Status: implementation plan, 2026-10-27. This document does not claim the new
link chooser or workspace creation flow is implemented.

## Observed gap

The link broker identifies its source container, selects a handler through the
system AppChooser, then calls `ask_window` with `--from-zone` only. The picker
cannot present that verified container as the explicit source environment.
The unconfined/host opener path also needs tracing: it must not manufacture a
container identity from application-supplied environment variables.

## Intended link flow

One Cellward window, with two steps and persistent Back/Cancel controls:

1. Choose a handler (browser/application), with the current default first.
2. Choose where: **source environment**, **handler's own environment**, or
   **another/new workspace**. Show container, network and isolation together.

Keep the URI, chosen handler and environment selections when moving back.
Do not silently join a container, change its network, reuse a browser in another
container, or fall through to the host after cancellation/failure. A saved
handler choice skips only step 1. Saving a destination must be a separate,
explicit source-container + scheme + handler rule. Show a warning when a link
leaves its source environment; locked routes remain enforced by the broker.

Source environment means the exact live instance, including temporary
containers. Revalidate its holder identity before launching. If gone, report it
and offer a new choice. Unconfined means explicitly no isolation; it is not the
host-network isolated container. Selecting an already running handler in a
different environment must not silently hand off the URI there.

For Syncthing and other localhost dashboards, show that localhost belongs to the
chosen network namespace. A browser in another namespace cannot necessarily
reach that listener. Do not expose a listener to the host as an automatic fix.

## Container model

A container is a data/permission/runtime/network identity. Its applications
share that identity; a container is not intrinsically a single application.
An own-app container is merely a default assignment, not an extra security
boundary between processes already inside it.

Offer three distinct actions:

- **Run here once**: join the selected existing container after explicit consent
  to sharing its home, clipboard and allowed IPC. Do not persist an assignment.
  Files written there persist according to that container's storage policy.
- **Use this workspace by default**: persist the application assignment, with
  its scope and a way to remove it in settings.
- **New shared workspace**: create a named private identity for the selected
  applications. Start empty by default; offer explicit import of selected data.
  Original app containers remain unchanged.

Do not stack two arbitrary application homes into a new OverlayFS lowerdir
list. File precedence is not a profile merge: .config names, browser databases,
credentials, whiteouts and IPC paths can conflict. OverlayFS is a storage/view
mechanism inside an identity, not a definition of trust between identities.

The existing offline `container merge` is a separate migration operation. It
copies nonconflicting data, retains conflicts separately, requires stopped
containers, and does not merge permissions. Keep it separate from “open link”
and “run together”. Never describe that migration as a reversible session join.

For collaboration without a shared identity, prefer explicit folder grants,
clipboard transfer and narrowly scoped broker services. Stronger per-program
isolation inside a workspace is future nested isolation, not a property of the
current shared container.

## Implementation sequence and acceptance

1. Trace launcher, portal, direct xdg-open and unconfined link paths. Pass a
   verified source context from broker to picker; it remains a proposal until
   the user confirms, never authority derived from URI/command/environment.
2. Replace system AppChooser for links with the Cellward handler step, retaining
   MIME/default discovery. Preserve choices on Back and keep the footer visible
   at small sizes and fractional scales.
3. Add exact-source / own-handler / other-workspace choices and broker-side
   validation, including no-escape constraints and live instance identity.
4. Add explicit once/default assignment semantics and new-empty-workspace flow.
   Add selected-data import separately; no automatic merging.
5. Test source and target in different containers/networks, unconfined, temporary
   source, source exit during question, existing browser, no handler, rejection,
   localhost listener reachability, and malicious forged source metadata.
6. Graphical checks at 100/125/150/175/200% with small viewports, long translated
   labels, keyboard-only navigation and Back preserving all choices.
