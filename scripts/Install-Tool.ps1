# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory = $true)][uri] $URL,
    [parameter(Mandatory = $true)][string] $PackageHash,
    [parameter(Mandatory = $false)][string] $PackageName,
    [parameter(Mandatory = $true)][string] $PackageRoot)

Function Get-FileHashTSO([String] $FileName, $HashName = "SHA256") {
    $FileStream = New-Object System.IO.FileStream($FileName, [System.IO.FileMode]::Open)
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash($FileStream) | % { [Void]$StringBuilder.Append($_.ToString("x2")) }
    $FileStream.Close()
    $StringBuilder.ToString()
}


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
$DownloadHash = (Get-FileHashTSO -FileName $PackageRoot\downloads\$FileName)
if ($DownloadHash -ne $PackageHash) {
    throw "Downloaded copy of " + $PackageName + " hash wrong hash"
}

Write-Host "Checking tool folder " $PackageRoot\$PackageName
$PackageInstalled = Test-Path $PackageRoot\$PackageName
if ($PackageInstalled -ne $true) {
    Write-Host "Expanding file " $PackageRoot\downloads\$FileName
    Expand-Archive -Path $PackageRoot\downloads\$FileName -DestinationPath $PackageRoot
}
