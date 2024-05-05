# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile, [parameter(Mandatory=$false)]$VCToolsRedistDir)

$version = &"$PSScriptRoot\Get-Version.ps1"
$content = Get-Content $InputFile
$content = $content.Replace("{version}", $version)
$content = $content.Replace("{VCToolsRedistDir}", $VCToolsRedistDir)
set-content $OutputFile $content
