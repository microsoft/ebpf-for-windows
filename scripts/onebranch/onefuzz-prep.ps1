# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
This script copies all the files required by the OneFuzz system to an output directory.

.EXAMPLE
    onefuzz-prep.ps1 -BuildPath "C:\path\to\build" -OneFuzzDirectory "C:\path\to\onefuzz" -OneFuzzConfigFile "C:\path\to\onefuzz.json"
#>

param(
    [Parameter(Mandatory=$true)] [string] $BuildPath,
    [Parameter(Mandatory=$true)] [string] $OneFuzzDirectory,
    [Parameter(Mandatory=$true)] [string] $OneFuzzConfigFile
)

$onefuzzconfig = Get-Content $OneFuzzConfigFile | ConvertFrom-Json

mkdir $OneFuzzDirectory -ErrorAction SilentlyContinue

Copy-Item -Path $OneFuzzConfigFile -Destination $OneFuzzDirectory

$onefuzzconfig.Entries | ForEach-Object {
    $_.JobDependencies | ForEach-Object {
        $source = Join-Path $BuildPath $_
        $destination = Join-Path $OneFuzzDirectory $_
        Copy-Item -Path $source -Destination $destination -Recurse
    }
}
