#!/usr/bin/env bash

# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# This script accepts either a list of files relative to the current
# working directory, or it will check all files tracked in Git. In
# both cases, it ignores files matching any regular expression listed
# in '.check-license.ignore'.

set -o errexit
set -o pipefail

license=("Copyright (c) eBPF for Windows contributors" "SPDX-License-Identifier: MIT")

root=$(git rev-parse --show-toplevel)

# If we are inside mingw* environment, then we update the path to proper format
if [[ $(uname) == MINGW* ]] ; then
      root=$(cygpath -u "${root}")
fi

ignore_res=()
while IFS=$'\r' read -r i; do
      if [[ $i =~ ^# ]] || [[ -z $i ]]; then # ignore comments
          continue
      fi
      ignore_res+=("$i")
done < "$root/scripts/.check-license.ignore"

should_ignore() {
    for re in "${ignore_res[@]}"; do
        if [[ $1 =~ $re ]]; then
            return
        fi
    done
    false
}

# Create array of files to check, either from the given arguments or
# all files in Git, ignore any that match a regex in the ignore file.
files=()
if [[ $# -ne 0 ]]; then
    for f in "$@"; do
        file=$(realpath "$f")

        if [[ ! -f $file ]]; then # skip non-existent files
            continue
        fi

        file=${file#$root/} # remove the prefix

        if should_ignore "$file"; then
            continue
        fi

        files+=("$file")
    done
else
    # Find all files in Git. These are guaranteed to exist, to not be
    # generated, and to not have the prefix.
    cd "$root"
    while IFS= read -r -d '' file; do
        if should_ignore "$file"; then
            continue
        fi

        files+=("$file")
    done < <(git ls-files -z)
fi

failures=0
for file in "${files[@]}"; do
    for line in "${license[@]}"; do
        # We check only the first four lines to avoid false positives
        # (such as this script), but to allow for a shebang and empty
        # line between it and the license.
        if ! head -n4 "${root}/${file}" | grep --quiet --fixed-strings --max-count=1 "${line}"; then
            echo "${file}"
            failures=$((failures + 1))
            break
        fi
    done
done

exit $failures
