# Wayland / X11 clipboard diagnosis (2026-10-25)

## Confirmed observations

The user's screenshot advertised `image/png` through Wayland. At the same
time, the current X11 display advertised only text targets. Only format lists
were inspected; the screenshot itself was not read or changed.

`tests/clipboard-bridge-smoke.py` reproduces the relevant distinction on a
private headless sway with a virtual keyboard, Satellite 0.8.3 and an actual
mapped X11 window. It uses synthetic payloads, never the desktop clipboard.

Both directly and behind Cellward's Wayland proxy:

- A focused X11 window receives text, `image/png` and an arbitrary binary MIME.
- Synthetic bytes offered as `image/png` are transferred unchanged. This tests
  transport, not PNG decoding.
- While a native Wayland terminal has focus, copying a new image leaves X11's
  advertised selection stale. Focusing the X11 window restores the image offer.
- Behind Cellward, reading a foreign payload without a paste gesture is denied;
  Ctrl+V delivered to the X11 window permits the transfer.

Thus the observed format mismatch does **not** establish that Cellward strips
PNG or that Satellite cannot transfer images. A CLI can connect to X11 without
having an X11 window: its native Wayland terminal owns keyboard focus instead.
The same stale-selection case exists without Cellward in this test.

The installed Codex binary contains both X11 and Wayland clipboard libraries.
That alone does not establish which backend its failed paste selected. Backend
selection and the user's CopyQ interaction still need a targeted trace.

## Relevant boundaries

Cellward forwards ordinary clipboard and primary-selection MIME offers except
its private ownership markers. Foreign **payload** reads require a recent paste
gesture; it does not grant background host clipboard access.

Satellite 0.8.3 uses the ordinary Wayland data-device and primary-selection
protocols. See its [selection implementation](https://github.com/Supreeeme/xwayland-satellite/blob/v0.8.3/src/server/selection.rs).
There are also upstream reports of stale or stuck bridging, but they are not
proof of that specific failure in this session:
[upstream issue 485](https://github.com/Supreeeme/xwayland-satellite/issues/485).

`ext_data_control_manager_v1` and `zwlr_data_control_manager_v1` are deliberately
hidden by Cellward. Unhiding the host globals to make a CLI clipboard library
work would expose background clipboard access and is not a safe fix.

The current active compositor selection is global, even though Cellward's
history/password shelves are separated by container. A trusted host clipboard
manager such as CopyQ can therefore record copies made inside containers.
History separation is **not** independent active clipboard storage.

## Correct direction, not implemented here

Implementation progress: `clip/src/broker.rs` now supplies the bounded volatile
selection model (independent CLIPBOARD/PRIMARY, per-instance scopes, revisions,
explicit transfer, and payload erasure on replacement/drop). Unit tests cover
the model, **not** compositor integration. No Wayland/X11 transport uses it yet;
the active desktop clipboard and CopyQ behaviour are therefore unchanged.

History file exposure was addressed separately: see the storage section of
`CLIPBOARD.md`. Restarting the updated daemon migrates the old store and key into
the existing container-masked state. This does not itself fix active clipboard
compatibility.

Provide an instance-scoped clipboard broker with private active CLIPBOARD and
PRIMARY selections, including MIME payloads and images. X11 and native Wayland
clients of that instance must see the same selections. Import/export with the
host and other instances must be explicit, not automatic mirroring.

If a virtual data-control interface is provided for terminal CLI libraries or
Satellite, it must be served by that broker with instance-only data, never
forwarded to the host compositor. Paste authorization must account for a CLI's
terminal and its bridge being different connections, without turning any
container gesture into blanket access to the host's current selection.

Regression coverage must include native-terminal/X11-CLI focus, both selection
types, images, delayed reads, bridge ownership changes, CopyQ on the host, and
two instances. Until then, the clipboard compatibility problem is not fixed.
