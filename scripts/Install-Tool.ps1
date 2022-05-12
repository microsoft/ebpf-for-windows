# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory = $true)][uri] $URL,
    [parameter(Mandatory = $true)][string] $PackageHash,
    [parameter(Mandatory = $false)][string] $PackageName,
    [parameter(Mandatory = $true)][string] $PackageRoot)


$FileName = $Url.Segments[$Url.Segments.Count - 1]

Write-Host "Creating folder " $PackageRoot\downloads
mkdir -path $PackageRoot\downloads -ErrorAction SilentlyContinue

Write-Host "Checking for " $PackageRoot\downloads\$FileName
$FileExists = Test-Path $PackageRoot\downloads\$FileName
if ($FileExists -ne $true) {
    Write-Host "Downloading file " $URL
    Invoke-WebRequest -Uri $URL -OutFile $PackageRoot\downloads\$FileName -ErrorAction SilentlyContinue
}

Write-Host "Checking hash of file " $PackageRoot\downloads\$FileName
$DownloadHash = (Get-FileHash -Path $PackageRoot\downloads\$FileName).Hash
if ($DownloadHash -ne $PackageHash) {
    throw "Downloaded copy of " + $PackageName + " hash wrong hash"
}

Write-Host "Checking tool folder " $PackageRoot\$PackageName
$PackageInstalled = Test-Path $PackageRoot\$PackageName
if ($PackageInstalled -ne $true) {
    Write-Host "Expanding file " $PackageRoot\downloads\$FileName
    Expand-Archive -Path $PackageRoot\downloads\$FileName -DestinationPath $PackageRoot
}
