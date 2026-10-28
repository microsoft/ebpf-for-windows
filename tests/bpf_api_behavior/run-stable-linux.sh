#!/usr/bin/env bash

# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

kernel_tree=''
virtme_ng=''
expected_version=''
output=''

usage() {
  echo \
    "usage: $0 --kernel-tree PATH --virtme-ng PATH --expected-version VERSION --output PATH" \
    >&2
  exit 2
}

while (($# > 0)); do
  case "$1" in
    --kernel-tree)
      (($# >= 2)) || usage
      kernel_tree=$2
      shift 2
      ;;
    --virtme-ng)
      (($# >= 2)) || usage
      virtme_ng=$2
      shift 2
      ;;
    --expected-version)
      (($# >= 2)) || usage
      expected_version=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || usage
      output=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n $kernel_tree ]] || usage
[[ -n $virtme_ng ]] || usage
[[ -n $expected_version ]] || usage
[[ -n $output ]] || usage

kernel_tree=$(realpath "$kernel_tree")
virtme_ng=$(realpath "$virtme_ng")
output=$(realpath -m "$output")

test_root=$(
  cd "$(dirname "${BASH_SOURCE[0]}")"
  pwd
)

source_file="$test_root/bpf_api_behavior.c"
test_runner="$test_root/run-tests.sh"
kernel_image="$kernel_tree/arch/x86/boot/bzImage"

for file in \
  "$source_file" \
  "$test_runner" \
  "$kernel_image" \
  "$virtme_ng"
do
  [[ -f $file ]] || {
    echo "required file not found: $file" >&2
    exit 1
  }
done

[[ -x $test_runner ]] || {
  echo "test runner is not executable: $test_runner" >&2
  exit 1
}

[[ -x $virtme_ng ]] || {
  echo "virtme-ng is not executable: $virtme_ng" >&2
  exit 1
}

temporary_directory=$(mktemp -d /tmp/bpf-api-stable.XXXXXX)
trap 'rm -rf "$temporary_directory"' EXIT

executable="$temporary_directory/bpf_api_behavior"

cc \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  $(pkg-config --cflags libbpf) \
  "$source_file" \
  -o "$executable" \
  $(pkg-config --libs libbpf)

mkdir -p "$(dirname "$output")"
rm -f "$output"

(
  cd "$kernel_tree"

  timeout \
    --foreground \
    900s \
    "$virtme_ng" \
      --disable-kvm \
      --rwdir "$(dirname "$output")" \
      -- \
      env \
        BPF_API_EXPECTED_VERSION="$expected_version" \
        BPF_API_EXECUTABLE="$executable" \
        BPF_API_OUTPUT="$output" \
        BPF_API_RUNNER="$test_runner" \
      bash -c '
        set -euo pipefail

        actual_version=$(uname -r)
        echo "guest kernel: $actual_version"

        case "$actual_version" in
          "$BPF_API_EXPECTED_VERSION"|"$BPF_API_EXPECTED_VERSION"-virtme*)
            ;;
          *)
            echo \
              "unexpected guest kernel: $actual_version" \
              >&2
            exit 1
            ;;
        esac

        "$BPF_API_RUNNER" \
          --executable "$BPF_API_EXECUTABLE" \
          --output "$BPF_API_OUTPUT"
      '
)

[[ -s $output ]] || {
  echo "stable Linux result was not produced: $output" >&2
  exit 1
}

expected_count=$("$executable" --list | wc -l)
actual_count=$(wc -l <"$output")

[[ $actual_count -eq $expected_count ]] || {
  echo \
    "expected $expected_count results, found $actual_count" \
    >&2
  exit 1
}

echo "Stable Linux behavior result: $output"
sha256sum "$output"
