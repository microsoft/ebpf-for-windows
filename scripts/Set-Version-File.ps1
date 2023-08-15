# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ($InputFile)

$version = &"$PSScriptRoot\Get-Version.ps1"
$file = Get-Item $InputFile

Rename-Item -Path $InputFile -NewName "$file.Basename.$version.$file.Extension"
