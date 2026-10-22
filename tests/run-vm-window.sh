#!/usr/bin/env bash
# Run the window VM with its writable disk on a sufficiently large filesystem.
# The Nix test driver otherwise uses XDG_RUNTIME_DIR, which may be a tiny tmpfs.
set -euo pipefail

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
screenshots_only=false
if [[ ${1:-} == --screenshots-only ]]; then
  screenshots_only=true
  shift
fi
output_dir=${1:-/tmp/cellward-vm-window}
mkdir -p -- "$output_dir"

vm_runtime_dir=$(mktemp -d /tmp/cellward-vm-runtime.XXXXXX)
cleanup() {
  # Only the private directory just returned by mktemp is ever removed.
  if [[ -d $vm_runtime_dir && ! -L $vm_runtime_dir && $vm_runtime_dir == /tmp/cellward-vm-runtime.* ]]; then
    rm -r -- "$vm_runtime_dir"
  fi
}
trap cleanup EXIT

driver=$(nix-build "$test_dir/vm-window.nix" -A driver \
  --arg screenshotsOnly "$screenshots_only" --no-out-link)
XDG_RUNTIME_DIR=$vm_runtime_dir "$driver/bin/nixos-test-driver" -o "$output_dir"
