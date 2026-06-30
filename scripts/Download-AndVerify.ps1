# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Downloads a file and verifies its SHA256 hash, with retry and exponential backoff.

.PARAMETER Url
    The URL to download.

.PARAMETER DestinationPath
    The local file path to save the download to.

.PARAMETER ExpectedHash
    The expected SHA256 hash of the downloaded file.

.PARAMETER MaxRetries
    Maximum number of retry attempts. Default is 5.

.PARAMETER InitialBackoffSeconds
    Initial delay in seconds before the first retry. Doubles on each subsequent retry. Default is 2.
#>

param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string]$DestinationPath,
    [Parameter(Mandatory = $true)][string]$ExpectedHash,
    [int]$MaxRetries = 5,
    [int]$InitialBackoffSeconds = 2
)

$ErrorActionPreference = 'Stop'

# Use exponential backoff for retries
$backoff = $InitialBackoffSeconds
for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
    Write-Host "Download attempt ${attempt}: $Url"

    # Remove any partial file from a previous failed attempt.
    if (Test-Path $DestinationPath) {
        Remove-Item -Path $DestinationPath -Force
    }

    curl.exe --location --fail --show-error `
        --connect-timeout 30 --max-time 300 `
        --retry 3 --retry-delay 5 --retry-all-errors --retry-connrefused `
        -o $DestinationPath $Url
    if ($LASTEXITCODE -eq 0) {
        break
    }

    if ($attempt -gt $MaxRetries) {
        throw "curl.exe failed after $($MaxRetries + 1) attempts (last exit code: $LASTEXITCODE)"
    }

    Write-Host "Attempt ${attempt} failed (exit code $LASTEXITCODE). Retrying in ${backoff} seconds..."
    Start-Sleep -Seconds $backoff
    $backoff *= 2
}

$downloadedHash = (Get-FileHash -Path $DestinationPath -Algorithm SHA256).Hash
if ($downloadedHash -ne $ExpectedHash) {
    throw "Checksum mismatch for ${DestinationPath}: expected $ExpectedHash, got $downloadedHash"
}

Write-Host "Download verified: $DestinationPath (SHA256: $downloadedHash)"
