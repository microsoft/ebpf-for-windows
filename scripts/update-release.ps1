# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ($version)

# Check if the version number is in the format X.Y.Z
if ($version -match '^\d+\.\d+\.\d+$') {

    if (Test-Path -Path ".\ebpf-for-windows.sln") {
        # Set the new version number in the ebpf_version.h file.
        $ebpf_version_file = "$PSScriptRoot\..\resource\ebpf_version.h"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ebpf_version_file' file..."
        (Get-Content $ebpf_version_file -Raw -Encoding UTF8) -replace 'EBPF_VERSION "\d+\.\d+\.\d+"', "EBPF_VERSION `"$version`"" | Set-Content $ebpf_version_file
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$version' in $ebpf_version_file"

        # Update the version number in the Wix installer file.
        $ebpf_installer_file = "$PSScriptRoot\..\installer\Product.wxs"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ebpf_installer_file' file..."
        (Get-Content $ebpf_installer_file -Raw -Encoding UTF8) -replace 'Version="\d+\.\d+\.\d+"', "Version=`"$version`"" | Set-Content $ebpf_installer_file
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$version' in $ebpf_installer_file"

        # Rebuild the solution, so to regenerate the '.o' files with the new version number.
        Write-Host -ForegroundColor DarkGreen "Rebuilding the solution, please wait..."
        $msbuildExitCode = msbuild.exe .\ebpf-for-windows.sln /p:Configuration=Debug /p:Platform=x64 /t:Rebuild
        if ($msbuildExitCode -ne 0) {
            Write-Host -ForegroundColor Red "msbuild failed with exit code $msbuildExitCode. Aborting script."
            Write-Host -ForegroundColor DarkYellow "Please rebuild the solution in 'x64/Debug' with VS or msbuild to debug the issue."
            exit 1
        }

        # Regenerate the expected `bpf2c` output (i.e. the corresponding "`.c`" files for all the solution's test/demo "`.o`" files).
        Write-Host -ForegroundColor DarkGreen "Regenerating the expected `bpf2c` output..."
        .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\
        Write-Host -ForegroundColor DarkGreen "Expected `bpf2c` output regenerated."

        $majorMinor = $version -replace '\.\d+$'
        Write-Host -ForegroundColor DarkYellow "Please verify all the changes then submit the pull-request into the release/$majorMinor branch."
    } else {
        Write-Host -ForegroundColor Red "'ebpf-for-windows.sln' not found in the current path."
        Write-Host -ForegroundColor DarkYellow "Please run this script from the root directory of the repository, within a Developer Poweshell for VS 2022."
    }
} else {
    Write-Host -ForegroundColor Red "Invalid version number format. Please enter the version number in the format 'X.Y.Z'."
}
