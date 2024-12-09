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
        $packageLine = $package | Where-Object { $_ -match $packageName }
        if (-not $packageLine) {
            throw "Package '$packageName' not found"
        }
        if ($packageLine -is [array]) {
            Write-Warning "Multiple versions found. Using the first one."
            $packageLine = $packageLine[0]
        }
        $packageVersion = $packageLine -replace "$packageName\s+", ""
        if (-not ($packageVersion -match '^\d+\.\d+\.\d+\.\d+$')) {
            throw "Invalid version format: $packageVersion"
        }
        return $packageVersion
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
number.

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
    try {
        # Create backup
        $backup_path = "$vs_file_path.bak"
        Copy-Item $vs_file_path $backup_path -Force
        # Read the contents of the file
        $vs_file_content = Get-Content $vs_file_path
        # Replace the version number in the file
        $vs_file_content = $vs_file_content -replace "<WDKVersion>.*</WDKVersion>", "<WDKVersion>$version_number</WDKVersion>"
        # Write the updated contents back to the file
        Set-Content $vs_file_path $vs_file_content
        # Print success message
        Write-Output "Updated WDK version in $vs_file_path to $version_number"
    }
    catch {
        if (Test-Path $backup_path) {
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

    # Generate the new packages.config file
    Update-TemplateFile -template_file_path "$PSScriptRoot\..\scripts\setup_build\packages.config.template" -output_file_path "$PSScriptRoot\..\scripts\setup_build\packages.config" -version_number $wdk_version_number
    $files_updated += "$PSScriptRoot\..\scripts\setup_build\packages.config"

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