# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile, [parameter(Mandatory=$false)]$VCToolsRedistDir)

# The git commit ID is in the include directory and is in the format:
# #define GIT_COMMIT_ID "some commit id"
$git_commit_id = Get-Content -Path "$PSScriptRoot\..\include\git_commit_id.h" -Raw -Encoding UTF8
$git_commit_id = $git_commit_id[0].Split('"')[1]

$version = &"$PSScriptRoot\Get-Version.ps1"
$content = Get-Content $InputFile
$content = $content.Replace("{version}", $version)
$content = $content.Replace("{VCToolsRedistDir}", $VCToolsRedistDir)
$content = $content.Replace("{git_commit_id}", $git_commit_id)
set-content $OutputFile $content
