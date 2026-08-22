#!/usr/bin/env bash

# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

executable=''
output=''
reference=''

usage() {
  echo "usage: $0 --executable PATH --output PATH [--reference PATH]" >&2
  exit 2
}

while (($# > 0)); do
  case "$1" in
    --executable)
      (($# >= 2)) || usage
      executable="$2"
      shift 2
      ;;
    --output)
      (($# >= 2)) || usage
      output="$2"
      shift 2
      ;;
    --reference)
      (($# >= 2)) || usage
      reference="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$executable" && -n "$output" ]] || usage
[[ -x "$executable" ]] || {
  echo "executable not found: $executable" >&2
  exit 1
}

if [[ -n "$reference" && ! -f "$reference" ]]; then
  echo "reference not found: $reference" >&2
  exit 1
fi

result_directory="$(dirname "$output")"
mkdir -p "$result_directory"

temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT

mapfile -t cases < <("$executable" --list)

((${#cases[@]} > 0)) || {
  echo 'no behavior test cases were discovered' >&2
  exit 1
}

declare -A seen_cases=()
: >"$output"

for test_case in "${cases[@]}"; do
  if [[ -n "${seen_cases[$test_case]+present}" ]]; then
    echo "duplicate behavior test: $test_case" >&2
    exit 1
  fi

  seen_cases["$test_case"]=1

  stdout_file="$temporary_directory/stdout"
  stderr_file="$temporary_directory/stderr"

  set +e
  "$executable" "$test_case" >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e

  if ((status != 0)); then
    echo "$test_case failed with exit code $status" >&2
    cat "$stderr_file" >&2
    exit 1
  fi

  if [[ -s "$stderr_file" ]]; then
    echo "$test_case wrote to stderr" >&2
    cat "$stderr_file" >&2
    exit 1
  fi

  mapfile -t output_lines <"$stdout_file"

  if ((${#output_lines[@]} != 1)); then
    echo "$test_case produced ${#output_lines[@]} output lines" >&2
    exit 1
  fi

  line="${output_lines[0]}"
  IFS=$'\t' read -r name result error_number extra <<<"$line"

  if [[
    "$name" != "$test_case" ||
    ! "$result" =~ ^-?[0-9]+$ ||
    ! "$error_number" =~ ^[0-9]+$ ||
    -n "${extra:-}"
  ]]; then
    echo "unexpected output for $test_case: $line" >&2
    exit 1
  fi

  printf '%s\n' "$line" >>"$output"
done

echo "Wrote ${#cases[@]} results to $output"

if [[ -n "$reference" ]]; then
  if ! cmp -s -- "$reference" "$output"; then
    diff -u -- "$reference" "$output" || true
    echo 'Linux behavior differs from the reference' >&2
    exit 1
  fi

  echo 'Linux behavior matches the reference'
fi
