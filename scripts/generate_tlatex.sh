#!/usr/bin/env bash

# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

# Generate TLATeX (.tex) outputs for all models under models/*.
#
# By default this script uses ./tla2tools.jar (as downloaded by CI).
# You can override with TLA2TOOLS_JAR=/path/to/tla2tools.jar
#
# Note: TLATeX runs LaTeX to compute alignment. If LaTeX is not installed,
# the tool still usually writes the .tex file but exits non-zero.
# We tolerate only the specific "latex not found" failure; everything else fails.

TLA2TOOLS_JAR="${TLA2TOOLS_JAR:-tla2tools.jar}"

if [[ ! -f "${TLA2TOOLS_JAR}" ]]; then
  echo "tla2tools.jar not found at: ${TLA2TOOLS_JAR}" >&2
  echo "Set TLA2TOOLS_JAR or download it (CI downloads it automatically)." >&2
  exit 1
fi

shopt -s nullglob

for model_dir in models/*/ ; do
  tla_files=("${model_dir}"*.tla)
  if [[ ${#tla_files[@]} -eq 0 ]]; then
    continue
  fi
  if [[ ${#tla_files[@]} -ne 1 ]]; then
    echo "${model_dir}: expected exactly one .tla file, found ${#tla_files[@]}" >&2
    printf '  %s\n' "${tla_files[@]}" >&2
    exit 1
  fi

  tla="${tla_files[0]}"
  spec_root="$(basename "${tla}" .tla)"
  out_dir="${model_dir%/}/tlatex"
  mkdir -p "${out_dir}"

  echo "Generating TLATeX for ${tla} -> ${out_dir}/${spec_root}.tex"

  log_file="${out_dir}/${spec_root}.tlatex.log"

  set +e
  java -cp "${TLA2TOOLS_JAR}" tla2tex.TLA -metadir "${out_dir}" "${tla}" >"${log_file}" 2>&1
  status=$?
  set -e

  if [[ ! -f "${out_dir}/${spec_root}.tex" ]]; then
    echo "TLATeX did not produce ${out_dir}/${spec_root}.tex" >&2
    cat "${log_file}" >&2
    exit 1
  fi

  # TLATeX may emit trailing whitespace which trips pre-commit hooks.
  # Strip it deterministically.
  sed -i -e 's/[[:space:]]\+$//' "${out_dir}/${spec_root}.tex"

  if [[ ${status} -ne 0 ]]; then
    if grep -q 'Cannot run program "latex"' "${log_file}"; then
      echo "Warning: LaTeX not found; generated .tex but skipping alignment run." >&2
    else
      echo "TLATeX failed for ${tla}" >&2
      cat "${log_file}" >&2
      exit 1
    fi
  fi

  # Keep the committed output clean: remove transient build artifacts if they exist.
  rm -f "${out_dir}/${spec_root}.aux" "${out_dir}/${spec_root}.log" "${out_dir}/${spec_root}.dvi" "${out_dir}/${spec_root}.ps" "${out_dir}/${spec_root}.pdf"
  rm -f "${log_file}"
done
