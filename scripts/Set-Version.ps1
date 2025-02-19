# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile, [parameter(Mandatory=$false)]$VCToolsRedistDir, [parameter(Mandatory=$false)]$architecture, [parameter(Mandatory=$false)]$configuration)

# The git commit ID is in the include directory and is in the format:
# #define GIT_COMMIT_ID "some commit id"
$git_commit_id = Get-Content -Path "$PSScriptRoot\..\include\git_commit_id.h" -Raw -Encoding UTF8
$git_commit_id = $git_commit_id.Split('"')[1]

$content = Get-Content -path "$PSScriptRoot\..\Directory.Build.props" -Raw -Encoding UTF8

# Parse the XML content
[xml]$xml = $content

$VersionPropertyGroup = $xml.Project.PropertyGroup | Where-Object {$_.PSObject.Properties.Name -contains "Label" -and $_.Label -eq "Version"}

# Get the version number
$version = ""
$version += $VersionPropertyGroup.EbpfVersion_Major + "."
$version += $VersionPropertyGroup.EbpfVersion_Minor + "."
$version += $VersionPropertyGroup.EbpfVersion_Revision

$content = Get-Content $InputFile
$content = $content.Replace("{version}", $version)
$content = $content.Replace("{VCToolsRedistDir}", $VCToolsRedistDir)
$content = $content.Replace("{git_commit_id}", $git_commit_id)
$content = $content.Replace("{architecture}", $architecture)
if ($configuration -match "Release") {
    $content = $content.Replace("{configuration}", "")
} else {
    $content = $content.Replace("{configuration}", ".$configuration")
}
set-content $OutputFile $content
