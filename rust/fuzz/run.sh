#!/usr/bin/env bash
set -euo pipefail
fuzz_root=$(cd -- "$(dirname -- "$0")" && pwd)
fuzz_seconds=${1:-30}
case "$fuzz_seconds" in ''|*[!0-9]*) echo 'usage: run.sh [seconds per target]' >&2; exit 2;; esac
if (( fuzz_seconds < 1 || fuzz_seconds > 86400 )); then
  echo 'seconds must be 1..86400' >&2
  exit 2
fi
fuzz_triple=$(rustc -vV | sed -n 's/^host: //p')
: "${CARGO_TARGET_DIR:=$fuzz_root/target}"
export CARGO_TARGET_DIR CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
# --target keeps these flags out of host build scripts/procedural macros.
# These LLVM flags enable coverage guidance, not AddressSanitizer or Miri.
export RUSTFLAGS='-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares'
cargo build --manifest-path "$fuzz_root/Cargo.toml" --target "$fuzz_triple" --offline --locked -j1
fuzz_data="$CARGO_TARGET_DIR/corpus"
fuzz_artifacts="$CARGO_TARGET_DIR/artifacts"
mkdir -p -- "$fuzz_artifacts"
python3 "$fuzz_root/make-corpus.py" "$fuzz_data"
for fuzz_target in dbus pulse typing wayland; do
  "$CARGO_TARGET_DIR/$fuzz_triple/debug/$fuzz_target" "$fuzz_data/$fuzz_target" \
    "-max_total_time=$fuzz_seconds" -max_len=65536 -rss_limit_mb=1024 \
    "-artifact_prefix=$fuzz_artifacts/" 2>&1 | tee "$CARGO_TARGET_DIR/$fuzz_target.log"
done
