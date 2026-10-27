# Protocol fuzzing

Separate, locked package: production dependencies and release binaries do not
include libFuzzer. `libfuzzer-sys` is pinned to 0.4.13; wl-proxy uses the same
0.1.4 version and feature union as the production core.

Targets:

- `dbus`: framing, header/signatures, portal arguments, property arrays,
  notification/screencast rewriting and tray argument readers.
- `pulse`: frame descriptor, commands, tag payloads, property filtering and
  recording-source policy.
- `typing`: untrusted request parser, accepted-request encode/parse stability,
  text-to-keymap plan.
- `wayland`: the production wl-proxy decoder via a private socket pair and
  standalone registry with compositor/shm/seat globals. No host display is
  opened. This covers decoding and object dispatch, not all Cellward frame,
  clipboard, authorization or real-FD policies.

Run in the normal core build environment (C++ compiler, font and libseccomp as
required by the main crate):

```sh
CARGO_TARGET_DIR=/path/to/disk-backed/fuzz-target rust/fuzz/run.sh 30
```

The script builds with one Cargo job and runs targets sequentially, each with a
1 GiB libFuzzer RSS limit and 64 KiB sample limit. Wayland further caps each
sample at 4096 bytes and eight dispatches. Corpus generation uses synthetic
`.invalid` addresses and no real user data. Retain corpus/artifacts on disk, not
in a RAM-backed /tmp. A crash exits nonzero and retains the reproducer; reduce it
and add a normal regression test before fixing the crash.

The provided stable-toolchain runner was tested with rustc 1.99.1, LLVM
SanitizerCoverage instrumentation and libFuzzer 0.4.13. Check the log includes
loaded counters and growing coverage: an uninstrumented binary printing “no
interesting inputs” is not a coverage-guided run. It does **not** enable
AddressSanitizer. For ASan use a pinned compatible nightly and cargo-fuzz on
this package; record their exact versions. Miri is a different check, not
replaced by these targets.

Native initial coverage runs (2026-10-27), ten seconds per target:
D-Bus 201533, Pulse 176805, typing 168308 and Wayland 50672 executions, no crashes.
These are short smoke runs, not exhaustive security validation. Longer campaigns,
FD-bearing/cross-connection stateful cases and sanitizer runs remain required.

`cargo-audit`/Miri are not installed in the current development environment.
Attempting to obtain pinned nixpkgs cargo-audit 0.22.1 failed because the Nix
builder could not resolve repository/cache hosts. No dependency audit or Miri
pass is claimed. When available, audit both production locks (`rust/Cargo.lock`,
`window/Cargo.lock`) and this tooling lock; retain the database revision/date and
machine-readable reports. Do not treat an unavailable/stale advisory database
as a clean result.
