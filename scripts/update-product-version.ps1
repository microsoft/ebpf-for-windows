# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($majorVersion, $minorVersion, $revisionNumber)

# Check if the version number is in the format X.Y.Z
if ("$majorVersion.$minorVersion.$revisionNumber" -match '^\d+\.\d+\.\d+$') {

    if (Test-Path -Path ".\ebpf-for-windows.sln") {
        # Set the new version number in the ebpf_version.h file.
        $ebpf_version_file = "$PSScriptRoot\..\Directory.Build.props"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ebpf_version_file' file..."
        # Replace <EbpfVersion_Major>0</EbpfVersion_Major> with <EbpfVersion_Major>$majorVersion</EbpfVersion_Major>

        $newcontent = (Get-Content $ebpf_version_file -Raw -Encoding UTF8) `
                        -replace '(?<=<EbpfVersion_Major>)\d+', $majorVersion `
                        -replace '(?<=<EbpfVersion_Minor>)\d+', $minorVersion `
                        -replace '(?<=<EbpfVersion_Revision>)\d+', $revisionNumber

        $newcontent | Set-Content $ebpf_version_file -NoNewline
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$majorVersion.$minorVersion.$revisionNumber' in $ebpf_version_file"

        # Rebuild the solution, so to regenerate the NuGet packages and the '.o' files with the new version number.
        Write-Host -ForegroundColor DarkGreen "Rebuilding the solution, please wait..."
        $res = & msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln /t:Clean,Build
        if ($LASTEXITCODE -ne 0) {
            Write-Host -ForegroundColor Red "msbuild failed with exit code [$LASTEXITCODE] (res=$res). Aborting script."
            Write-Host -ForegroundColor DarkYellow "Please rebuild the solution in 'x64/Debug' with Visual Studio or MsBuild to debug the issue."
            exit 1
        }

        # Regenerate the expected 'bpf2c' output (i.e. the corresponding '.c' files for all the solution's test/demo '.o' files).
        Write-Host -ForegroundColor DarkGreen "Regenerating the expected 'bpf2c' output..."
        .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\
        Write-Host -ForegroundColor DarkGreen "Expected 'bpf2c' output regenerated."
    } else {
        Write-Host -ForegroundColor Red "'ebpf-for-windows.sln' not found in the current path."
        Write-Host -ForegroundColor DarkYellow "Please run this script from the root directory of the repository, within a Developer Poweshell for VS 2022."
    }
} else {
    Write-Host -ForegroundColor Red "Invalid version number format. Please enter the version number in the format 'X Y Z', e.g.:"
    Write-Host
    Write-Host -ForegroundColor DarkGreen "   PS> .\scripts\update-product-version.ps1 0 9 0"
    Write-Host
}
