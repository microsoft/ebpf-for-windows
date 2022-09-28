# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile)

$version = &"$PSScriptRoot\Get-Version.ps1"
$content = Get-Content $InputFile
$content = $content.Replace("{version}", $version)
set-content $OutputFile $content