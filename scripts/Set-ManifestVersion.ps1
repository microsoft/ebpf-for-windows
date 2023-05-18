# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile)

$version = &"$PSScriptRoot\Get-Version.ps1"
$new_version = -join($version, ".0")
$content = Get-Content $InputFile
$content = $content.Replace("{version}", $new_version)
set-content $OutputFile $content