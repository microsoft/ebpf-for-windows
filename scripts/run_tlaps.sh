#!/usr/bin/env bash

# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

# Run TLAPS (tlapm) on any proof modules under models/**.
#
# Convention:
# - only files matching *Proof*.tla are considered proof entrypoints
# - if there are no proof modules, exit successfully

shopt -s nullglob globstar

proof_files=(models/**/**/*Proof*.tla models/**/*Proof*.tla)

# De-dup while preserving order.
unique_proof_files=()
for f in "${proof_files[@]}"; do
  if [[ -f "$f" ]]; then
    already=false
    for u in "${unique_proof_files[@]}"; do
      if [[ "$u" == "$f" ]]; then
        already=true
        break
      fi
    done
    if [[ "$already" == false ]]; then
      unique_proof_files+=("$f")
    fi
  fi
done

if [[ ${#unique_proof_files[@]} -eq 0 ]]; then
  echo "No TLAPS proof modules found (models/**/*Proof*.tla)."
  exit 0
fi

command -v tlapm >/dev/null 2>&1 || {
  echo "tlapm not found on PATH" >&2
  exit 1
}

echo "Running TLAPS on ${#unique_proof_files[@]} proof module(s)."

for tla in "${unique_proof_files[@]}"; do
  echo "=== TLAPS: ${tla} ==="
  # Ensure module dependencies can be found regardless of current working directory.
  # TLAPS searches the current directory plus any -I include paths.
  proof_dir="$(dirname "${tla}")"

  # --cleanfp avoids stale fingerprint caches in CI.
  tlapm -I "${proof_dir}" --method smt --cleanfp "${tla}"
done
