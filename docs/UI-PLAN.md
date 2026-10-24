# Interface, languages, and application appearance

The interface is the next product track, alongside the network-safety work in
[`NEXT-STEPS.md`](../NEXT-STEPS.md). A colour scheme must never change what a
zone colour means, and an application's appearance must never grant it access
to the host's configuration or desktop services.

## Window themes

The panel can choose System, Light, Dark, or one of the built-in iced palettes
(including Catppuccin, Nord, Gruvbox, Solarized and Tokyo Night). The choice is
stored as `theme=<key>` in `$XDG_CONFIG_HOME/cellward/appearance.conf` (or
`~/.config/cellward/appearance.conf`). Both the panel and subsequent launch
windows and the clipboard manager use it. System reads actual colours from
`$XDG_CONFIG_HOME/cellward/palette.json`, KDE `kdeglobals`, or GTK 4/3 named
colours (GNOME prefers GTK). Missing or invalid palettes fall back to iced's
system light/dark detection. The bounded reader is adapted from stillconf,
without reading stillconf's private state or preferences.

The optional JSON palette requires `background` and `text`; optional keys are
`accent`, `success`, `danger`, and `warning`, with hex colour values. File changes
are checked every two seconds, waking open windows only when something changes.
The manager keeps the selected theme after hiding for point selection. Zone
colours remain separate; desktop-specific contrast checks remain on the roadmap.

The frame editor previews thickness and inner/outer radius changes as the
sliders move. Save commits local cosmetic overrides, Cancel drops the preview
and restores the previous effective values. Hover-trigger depth and resize-corner
span preview when selected too; other controls still apply on Save.
This mechanism never previews or overrides isolation permissions.

The launch screen's permission rows are authoritative. Camera, microphone,
screen capture and X11 do not reappear as preset resource checkboxes; the home
choice is not duplicated either. Files and other resources contains only the
remaining optional preset grants. Hidden or stale offers are removed from the
window's answer before applying it; existing container permissions are not reset.

## Languages

English should be the source language and fallback, with Russian as the first
complete translation. A shared English/Russian catalogue now covers the launch
window's own controls, and its wire protocol can carry an explicit `lang` tag.
The core still emits Russian by default; this is a migration boundary, **not**
the finished language feature. Do not expose an English/Russian selector until **all**
user-facing strings in the launch window, panel, permission prompts and the
core-generated window protocol have translations. Otherwise an English
selection would silently show Russian security decisions. Technical IDs,
configuration keys and protocol tags stay stable; only display text changes.

Implementation order:

1. Give every displayed message a stable key with English source text and
   parameters. Localize the core's messages before it serializes a window
   request (the window must not translate protocol tags or parse prose).
2. Move panel and launch-window literals into the same catalogue. Keep the
   security-relevant wording, durations, host/domain/IP, port and scope exact.
3. Provide English and Russian catalogues, test key/placeholder parity and
   escaped/untrusted arguments, then switch the default to English. Detect
   `LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG` at startup; unknown/C locales
   fall back to English. A manual language choice overrides detection, is
   persisted, and changes an open panel immediately.
4. Translate CLI output and documentation separately. A scriptable CLI mode
   must keep machine-readable output stable; do not localize data fields.

## Appearance of applications in containers

This is **not** the window theme. The sandbox already passes selected host
appearance files read-only (`rust/src/fs_sandbox.rs::appearance`) and allows
the desktop Settings portal; it deliberately does not pass all of dconf or the
host's application configuration. Keep that boundary.

Offer per-container `Follow desktop` (default), `Light`, `Dark`, and later
`Custom` appearance. `Follow desktop` may use read-only, allow-listed GTK/Qt
settings, fonts, icons and cursor assets and the filtered Settings portal.
For overrides, build a small generated appearance snapshot **inside the
container**; do not bind the whole host `~/.config`, expose a raw session bus,
or write the host's theme settings. Propagate a colour-scheme change through
the existing filtered portal or an explicitly scoped update, then verify GTK3,
GTK4/libadwaita, Qt and Chromium/Firefox separately. Apps may ignore a theme,
and `GTK_THEME`/`QT_STYLE_OVERRIDE` are fallback compatibility controls, not a
universal live-theme API. Make that limitation visible in the UI.

Acceptance tests: a custom container does not acquire additional host paths
or sockets; Light/Dark survives container restart; an open app updates where
its toolkit supports it; changing a Cellward window theme alone does **not**
silently change the appearance of unrelated apps.
