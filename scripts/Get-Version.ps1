# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# .SYNOPSIS
# Get the version number from the repository.

$content = Get-Content -Path "$PSScriptRoot\..\resource\ebpf_version.h" -Raw -Encoding UTF8

# Extract EBPF_VERSION_MAJOR, EBPF_VERSION_MINOR, and EBPF_VERSION_REVISION from ebpf_version.h.

$major_version_prefix = "#define EBPF_VERSION_MAJOR "
$minor_version_prefix = "#define EBPF_VERSION_MINOR "
$revision_version_prefix = "#define EBPF_VERSION_REVISION "

$content -match "$major_version_prefix(\d+)" | Out-Null
$major_version = $matches[1]
$content -match "$minor_version_prefix(\d+)" | Out-Null
$minor_version = $matches[1]
$content -match "$revision_version_prefix(\d+)" | Out-Null
$revision_version = $matches[1]

$version = "$major_version.$minor_version.$revision_version"

Write-Output $version