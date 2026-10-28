# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [parameter(Mandatory=$true)] $majorVersion,
    [parameter(Mandatory=$true)] $minorVersion,
    [parameter(Mandatory=$true)] $revisionNumber,
    [parameter(Mandatory=$false)]$modifier = "")

# Check if the version number is in the format X.Y.Z
if ("$majorVersion.$minorVersion.$revisionNumber" -match '^\d+\.\d+\.\d+.*$') {
    # Update the version number in version.json.
    ('{{ "major": {0}, "minor": {1}, "patch": {2} }}' -f $majorVersion, $minorVersion, $revisionNumber) |
        Set-Content ".\version.json"

    if (Test-Path -Path ".\ebpf-for-windows.sln") {
        # Set the new version number in Directory.Build.props.
        $ebpf_version_file = "$PSScriptRoot\..\Directory.Build.props"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ebpf_version_file' file..."
        # Replace <EbpfVersion_Major>0</EbpfVersion_Major> with <EbpfVersion_Major>$majorVersion</EbpfVersion_Major>

        $newcontent = Get-Content $ebpf_version_file -Raw -Encoding UTF8

        $newcontent = $newcontent `
                        -replace '(?<=<EbpfVersion_Major>)\d+', $majorVersion `
                        -replace '(?<=<EbpfVersion_Minor>)\d+', $minorVersion `
                        -replace '(?<=<EbpfVersion_Revision>)\d+', $revisionNumber
        if ($modifier -ne "") {
            $newcontent = $newcontent -replace '<EbpfVersion_Modifier\s*/>', "<EbpfVersion_Modifier>$modifier</EbpfVersion_Modifier>"
            $newcontent = $newcontent -replace '(?<=<EbpfVersion_Modifier>)(.*?)(?=</EbpfVersion_Modifier>)', $modifier
            $newcontent = $newcontent -replace '(?<=<EbpfVersion>)(.*?)(?=</EbpfVersion>)', "$majorVersion.$minorVersion.$revisionNumber-$modifier"
        } else {
            $newcontent = $newcontent -replace '(?<=<EbpfVersion_Modifier>)(.*?)(?=</EbpfVersion_Modifier>)', ''
            $newcontent = $newcontent -replace '(?<=<EbpfVersion>)(.*?)(?=</EbpfVersion>)', "$majorVersion.$minorVersion.$revisionNumber"
        }

        $newcontent | Set-Content $ebpf_version_file -NoNewline
        $version_string = "$majorVersion.$minorVersion.$revisionNumber"
        if ($modifier -ne "") {
            $version_string += "-$modifier"
        }
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$version_string' in $ebpf_version_file"

        $ebpf_version_file = "$PSScriptRoot\..\include\ebpf_version.h"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ebpf_version_file' file..."
        $newcontent = Get-Content $ebpf_version_file -Raw -Encoding UTF8
        $newcontent = $newcontent `
                        -replace '(?<=#define EBPF_VERSION_MAJOR )\d+', $majorVersion `
                        -replace '(?<=#define EBPF_VERSION_MINOR )\d+', $minorVersion `
                        -replace '(?<=#define EBPF_VERSION_REVISION )\d+', $revisionNumber `
                        -replace '(?<=#define EBPF_VERSION ")[^"]*', $version_string
        $newcontent | Set-Content $ebpf_version_file -NoNewline
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$version_string' in $ebpf_version_file"
    } else {
        Write-Host -ForegroundColor Red "'ebpf-for-windows.sln' not found in the current path."
        Write-Host -ForegroundColor DarkYellow "Please run this script from the root directory of the repository."
    }
} else {
    Write-Host -ForegroundColor Red "Invalid version number format. Please enter the version number in the format 'X Y Z', e.g.:"
    Write-Host
    Write-Host -ForegroundColor DarkGreen "   PS> .\scripts\update-product-version.ps1 0 9 0"
    Write-Host
}
