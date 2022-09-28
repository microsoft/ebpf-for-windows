# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# .SYNOPSIS
# Get the version number from the repository.

$content = Get-Content -Path "$PSScriptRoot\..\resource\ebpf_version.h" -Raw -Encoding UTF8

$content = $content.Substring($content.IndexOf("#define EBPF_VERSION") + "#define EBPF_VERSION".Length)
$content = $content.Substring($content.IndexOf("""") + 1)
$content = $content.Substring(0, $content.IndexOf(""""))
$content
