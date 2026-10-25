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

## Implemented X11 paste compatibility

The launch proxy now relays the current **CLIPBOARD offer** between its native
Wayland and Satellite connections (`rust/src/wl_frame/clipboard_relay.rs`). A
CLI's X11 connection therefore sees current MIME types without a mapped X11
window or X11 keyboard focus. Contents are still fetched lazily from the
original offer, subject to its ownership/paste-gesture check. A gesture in a
different launch grants nothing here. Neither host data-control global is
exposed. The relay is bounded to 128 devices and 64 MIME types of at most 256
bytes, and works without a cosmetic frame too.

Authorization now uses proxy-wide offer identities: wl-proxy's unique_id is
only unique within one connection and cannot safely identify offers in the
launch-wide drag/history authorization state. Both clipboard and primary
offers receive fresh internal ids, including offers used by the relay.

The `--relay` regression covers a **windowless Xlib clipboard reader** while
a native terminal keeps focus, with and without a frame. It checks actual
valid PNG bytes, including a changed second image, foreign background-read
denial, and denial after a paste gesture in another launch. The helper is
an Xlib probe, not the actual Codex binary. `--alacritty` selects the user's
terminal implementation instead of foot.
Both shared-launch cases passed with the installed Alacritty on the private
headless display, with software rendering and no user desktop clipboard access.

This fixes the reproduced Wayland-terminal -> X11-CLI **paste** scenario in
one launch. It does not implement the reverse direction for a windowless
X11 copier, PRIMARY synchronization, independent active storage across
launches, or host CopyQ exclusion. An unconfined host launch does not use
this proxy and is unchanged.

## Full private broker: remaining integration

Implementation progress: `clip/src/broker.rs` now supplies the bounded volatile
selection model (independent CLIPBOARD/PRIMARY, per-instance scopes, revisions,
explicit transfer, and payload erasure on replacement/drop). Unit tests cover
the model, **not** compositor integration. No Wayland/X11 transport uses it yet;
the global active desktop selection and CopyQ recording are therefore unchanged.

History file exposure was addressed separately: see the storage section of
`CLIPBOARD.md`. Restarting the updated daemon migrates the old store and key into
the existing container-masked state. This does not itself fix active clipboard
privacy. The narrower forward-paste compatibility fix above is active.

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
