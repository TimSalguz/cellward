# Picker startup latency

Set `CELLWARD_TRACE_STARTUP=1` when invoking `vpn-zone-pick` to log opt-in
milestones to stderr. Normal launches remain quiet. Milestones contain timings,
not program arguments, clipboard contents or connection destinations.

The picker reports tool loading, launch-state loading, request preparation,
process spawn and request delivery. The GUI reports request parsing and initial
font/layout preparation. Spawn and delivery are **not** first-frame timestamps;
waiting for the user's answer is not startup time. Container startup happens
after the launch choice, not before showing this dialog.

For a disposable real-compositor check, build `tests/vm-window.nix -A driver`
with `--arg startupOnly true`. The guest measures process spawn to a surface
mapped in Sway, three times, and verifies that dismissing it starts nothing.
It adds 1000 user font entries and checks that the GUI's font configuration
still resolves only its explicit store fonts. Mapping includes polling overhead
and is not a GPU presentation timestamp. Keep writable VM state off tiny tmpfs.

## 2026-10-26 result

The old `makeFontsConf` configuration indirectly included `/etc/fonts/conf.d`,
XDG and profile fonts: 1244 fonts were visible on the development desktop.
The explicit GUI configuration exposes 23 fonts, preserving sans, serif,
monospace and emoji without loading the desktop collection on every invocation.

Under QEMU TCG, the fixed guest with 1000 user font entries mapped in 2008,
715 and 655 ms. Warm font/layout preparation took 69–87 ms. A prior run of the
old configuration mapped in 2303, 838 and 844 ms without the stress entries.
These are environment-specific observations, not a universal speedup guarantee;
hardware, caches and scheduling affect the result. The corrected VM test passed
in 122 seconds; all 68 GUI package tests passed too.
