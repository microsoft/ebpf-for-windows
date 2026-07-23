# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Updates the WDK version in all relevant files.

.DESCRIPTION
This script updates the WDK version in all relevant files. It queries the NuGet package manager for the version of the
'Microsoft.Windows.WDK.x64' package and updates the version number in the following files:
- wdk.props
- tools\bpf2c\templates\kernel_mode_bpf2c.vcxproj
- tools\bpf2c\templates\user_mode_bpf2c.vcxproj
- scripts\setup_build\packages.config

The script creates a backup of each file before updating it. If an error occurs during the update, the script rolls back
all changes.

The script requires the 'nuget' command to be available in the PATH.

.PARAMETER None
This script does not take any parameters.

.NOTES
This script is intended to be run from the root of the repository.
#>

function Get-PackageVersion(
    [string]$packageName
) {
<#
.SYNOPSIS
Get the version of a NuGet package.

.DESCRIPTION
Queries the NuGet package manager for the version of a package.

.PARAMETER packageName
The name of the package to query.

.EXAMPLE
Get-PackageVersion "Microsoft.Windows.WDK.x64"

.NOTES
This function requires the 'nuget' command to be available in the PATH.
#>
    if ([string]::IsNullOrWhiteSpace($packageName)) {
        throw "Package name cannot be empty"
    }

    try {
        $package = nuget list $packageName
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to retrieve package information"
        }
        $packageRegex = "^$([regex]::Escape($packageName))\s+"
        $packageLines = $package | Where-Object { $_ -match $packageRegex }
        if (-not $packageLines) {
            throw "Package '$packageName' not found"
        }
        # Extract versions and sort to find the latest
        $versions = @()
        if ($packageLines -is [array]) {
            $versions = $packageLines | ForEach-Object { ($_ -replace $packageRegex, "").Trim() }
        } else {
            $versions = @(($packageLines -replace $packageRegex, "").Trim())
        }
        # Filter valid versions and sort by System.Version to get the latest
        $latestVersion = $versions |
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [System.Version]$_ } -Descending |
            Select-Object -First 1
        if (-not $latestVersion) {
            throw "No valid version found for package '$packageName'"
        }
        if ($versions.Count -gt 1) {
            Write-Warning "Multiple versions found. Using the latest: $latestVersion"
        }
        return $latestVersion
    }
    catch {
        throw "Failed to get package version: $_"
    }
}

function Update-VersionInVsFile(
    [string]$vs_file_path,
    [string]$version_number
) {
<#
.SYNOPSIS
Updates the WDK version in a Visual Studio file.

.DESCRIPTION
Updates the WDK version in a Visual Studio file by replacing the existing version number with the specified version
number. Only the first <WDKVersion> and <WindowsTargetPlatformVersion> elements are updated (the canonical "latest"
values used for x64); platform-specific overrides such as <WDKVersionArm64> / <WindowsTargetPlatformVersionArm64> are
intentionally left untouched so they can stay pinned independently.

.PARAMETER vs_file_path
The path to the Visual Studio file to update.

.PARAMETER version_number
The new version number to set in the file.

.NOTES
This function creates a backup of the file before updating it. If an error occurs during the update, the function rolls
back the changes.
#>
    if ([string]::IsNullOrWhiteSpace($vs_file_path)) {
        throw "File path cannot be empty"
    }
    if (-not ($version_number -match '^\d+\.\d+\.\d+\.\d+$')) {
        throw "Invalid version format: $version_number"
    }
    if (-not (Test-Path $vs_file_path)) {
        throw "File not found: $vs_file_path"
    }
    # The Windows target platform version is the WDK version with the build revision reset to 0
    # (e.g. WDK 10.0.28000.1839 -> target platform 10.0.28000.0).
    $target_platform_version = $version_number -replace '\.\d+$', '.0'
    try {
        # Read the contents of the file
        $vs_file_content = Get-Content $vs_file_path

        # Transition guard: while VS 2022 and VS 2026 are both supported, the WDK version is expressed
        # with conditional "<WDKVersion Condition=...>...</WDKVersion>" entries (one per toolset) that this
        # simple replacement cannot safely update. If there is no unconditional "<WDKVersion>" element,
        # skip and warn instead of silently leaving the version stale. This guard becomes inert once VS 2022
        # support is removed and the files return to a single unconditional "<WDKVersion>" element.
        if (-not ($vs_file_content -match "<WDKVersion>[^<]*</WDKVersion>")) {
            Write-Warning "No unconditional <WDKVersion> element found in $vs_file_path (VS 2022 + VS 2026 transition state); skipping automatic update. Update the WDK version manually until VS 2022 support is removed."
            return
        }

        # Create backup
        $backup_path = "$vs_file_path.bak"
        Copy-Item $vs_file_path $backup_path -Force
        # Read the contents of the file
        $vs_file_content = @(Get-Content $vs_file_path)
        # Replace only the first occurrence of each tag so that platform-specific overrides
        # (e.g. <WDKVersionArm64>) are preserved.
        $wdk_version_updated = $false
        $target_version_updated = $false
        for ($i = 0; $i -lt $vs_file_content.Length; $i++) {
            if (-not $wdk_version_updated -and $vs_file_content[$i] -match "<WDKVersion>.*</WDKVersion>") {
                $vs_file_content[$i] = $vs_file_content[$i] -replace "<WDKVersion>.*</WDKVersion>", "<WDKVersion>$version_number</WDKVersion>"
                $wdk_version_updated = $true
            }
            if (-not $target_version_updated -and $vs_file_content[$i] -match "<WindowsTargetPlatformVersion>.*</WindowsTargetPlatformVersion>") {
                $vs_file_content[$i] = $vs_file_content[$i] -replace "<WindowsTargetPlatformVersion>.*</WindowsTargetPlatformVersion>", "<WindowsTargetPlatformVersion>$target_platform_version</WindowsTargetPlatformVersion>"
                $target_version_updated = $true
            }
        }
        # Write the updated contents back to the file
        Set-Content $vs_file_path $vs_file_content
        # Print success message
        Write-Output "Updated WDK version in $vs_file_path to $version_number"
    }
    catch {
        if ($backup_path -and (Test-Path $backup_path)) {
            Copy-Item $backup_path $vs_file_path -Force
            Remove-Item $backup_path
        }
        throw "Failed to update version in file: $vs_file_path"
    }
}

function Update-TemplateFile(
    [string]$template_file_path,
    [string]$output_file_path,
    [string]$version_number
) {
<#
.SYNOPSIS
Updates the WDK version in a template file.

.DESCRIPTION
Updates the WDK version in a template file by replacing the existing version number placeholder with the specified
version number.

.PARAMETER template_file_path
The path to the template file to update.

.PARAMETER output_file_path
The path to the output file to write the updated contents.

.PARAMETER version_number
The new version number to set in the file.

.NOTES
This function creates a backup of the output file before updating it. If an error occurs during the update, the function
rolls back the changes.
#>

    if ([string]::IsNullOrWhiteSpace($template_file_path) -or [string]::IsNullOrWhiteSpace($output_file_path)) {
        throw "File paths cannot be empty"
    }
    if (-not ($version_number -match '^\d+\.\d+\.\d+\.\d+$')) {
        throw "Invalid version format: $version_number"
    }
    if (-not (Test-Path $template_file_path)) {
        throw "Template file not found: $template_file_path"
    }
    try {
        # Create backup if output file exists
        $backup_path = $null
        if (Test-Path $output_file_path) {
            $backup_path = "$output_file_path.bak"
            Copy-Item $output_file_path $backup_path -Force
        }

        # Read the contents of the file
        $template_file_content = Get-Content $template_file_path
        # Replace the version number in the file
        $template_file_content = $template_file_content -replace "\$\(WDKVersion\)", $version_number
        # Write the updated contents back to the file
        Set-Content $output_file_path $template_file_content
        # Print success message
        Write-Output "Updated WDK version in $output_file_path to $version_number"
    }
    catch {
        if ($backup_path -and (Test-Path $backup_path)) {
            Copy-Item $backup_path $output_file_path -Force
            Remove-Item $backup_path
        }
        throw "Failed to update template file: $_"
    }
}

# List of files updated by the script used for rollback.
$files_updated = @()

# Main script logic
try {
    # Paths relative to the root of the repository
    $vs_files_to_update = @(
        "wdk.props",
        "tools\bpf2c\templates\kernel_mode_bpf2c.vcxproj",
        "tools\bpf2c\templates\user_mode_bpf2c.vcxproj"
    )

    # Get the current WDK version
    $wdk_version_number = Get-PackageVersion "Microsoft.Windows.WDK.x64"

    # Print the version number
    Write-Output "Found WDK version: $wdk_version_number"

    # Replace version in each VS file
    foreach ($vs_file in $vs_files_to_update) {
        Write-Host "Updating WDK version in $vs_file"
        $vs_file = $PSScriptRoot + "\..\" + $vs_file
        Update-VersionInVsFile $vs_file $wdk_version_number
        $files_updated += $vs_file
    }

    # Generate the new packages.config file.
    # Transition guard: while VS 2022 and VS 2026 are both supported, packages.config intentionally pins
    # two WDK versions (one per toolset). The single-version template cannot represent that, so regenerating
    # it here would silently drop the second toolset's packages and break that build. If the existing file
    # already pins more than one distinct version, skip regeneration and warn. This guard becomes inert once
    # VS 2022 support is removed and packages.config returns to a single WDK version.
    $packages_config_path = "$PSScriptRoot\..\scripts\setup_build\packages.config"
    $distinct_versions = @()
    if (Test-Path $packages_config_path) {
        $distinct_versions = @(Select-String -Path $packages_config_path -Pattern '<package\b[^>]*\bversion="([0-9.]+)"' -AllMatches |
            ForEach-Object { $_.Matches } |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique)
    }
    if ($distinct_versions.Count -gt 1) {
        Write-Warning "packages.config pins multiple WDK versions ($($distinct_versions -join ', ')); skipping auto-regeneration to preserve the VS 2022 + VS 2026 multi-toolset configuration. Update packages.config manually until VS 2022 support is removed."
    } else {
        Update-TemplateFile -template_file_path "$PSScriptRoot\..\scripts\setup_build\packages.config.template" -output_file_path $packages_config_path -version_number $wdk_version_number
        $files_updated += $packages_config_path
    }

    # Print success message
    Write-Output "Updated WDK version in all files"
}
catch {
    # Rollback all changes
    for ($i = $files_updated.Length - 1; $i -ge 0; $i--) {
        $file = $files_updated[$i]
        if (Test-Path "$file.bak") {
            # Rolling back changes
            Write-Host "Rolling back changes in $file"
            Copy-Item "$file.bak" $file -Force
            Remove-Item "$file.bak"
        }
    }

    # Print error message
    Write-Error $_
    exit 1
}