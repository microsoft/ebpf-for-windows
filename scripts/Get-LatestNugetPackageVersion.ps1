# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [string]$packageName
)

<#
.SYNOPSIS
Get the latest version of a NuGet package.

.DESCRIPTION
Queries the NuGet package manager for the latest version of a package.

.PARAMETER packageName
The name of the package to query.

.NOTES
This function requires the 'nuget' command to be available in the PATH.
#>

function Get-LatestNugetPackageVersion(
    [string]$packageName
) {
    if ([string]::IsNullOrWhiteSpace($packageName)) {
        throw "Package name cannot be empty"
    }

    try {
        $package = nuget list $packageName
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to retrieve package information"
        }
        $packageLine = $package | Where-Object { $_ -match $packageName }
        if (-not $packageLine) {
            throw "Package '$packageName' not found"
        }
        if ($packageLine -is [array]) {
            $packageLine = $packageLine[0]
        }
        $version = $packageLine -replace "$packageName\s+", ""
        return $version
    } catch {
        throw "Failed to retrieve version of package '$packageName': $_"
    }
}

# Get the latest version of the Microsoft.Windows.WDK.x64 package
Get-LatestNugetPackageVersion $packageName