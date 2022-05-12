# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory = $true)][uri] $URL,
    [parameter(Mandatory = $true)][string] $PackageHash,
    [parameter(Mandatory = $false)][string] $PackageName,
    [parameter(Mandatory = $true)][string] $PackageRoot)


$FileName = $Url.Segments[$Url.Segments.Count - 1]

mkdir -path $PackageRoot\downloads -ErrorAction SilentlyContinue

$FileExists = Test-Path $PackageRoot\downloads\$FileName
if ($FileExists -ne $true) {
    Invoke-WebRequest -Uri $URL -OutFile $PackageRoot\downloads\$FileName -ErrorAction SilentlyContinue
}

$DownloadHash = (Get-FileHash -Path $PackageRoot\downloads\$FileName).Hash
if ($DownloadHash -ne $PackageHash) {
    throw "Downloaded copy of " + $PackageName + " hash wrong hash"
}

$PackageInstalled = Test-Path $PackageRoot\$PackageName
if ($PackageInstalled -ne $true) {
    Expand-Archive -Path $PackageRoot\downloads\$FileName -DestinationPath $PackageRoot
}
