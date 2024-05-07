# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

function copy-precommit
{
    param([string]$file_path)
    $command = "git rev-parse --git-path hooks"
    $destination = Invoke-Expression $command

    Write-Host "Copy $file_path to $destination."
    Copy-Item $file_path $destination
}

copy-precommit $args[0]
