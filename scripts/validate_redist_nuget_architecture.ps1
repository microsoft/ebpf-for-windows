# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory = $true)]
    [string]$NugetPackagePath,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string]$ExpectedArchitecture
)

function Extract-NuGetPackage {
    param (
        [string]$PackagePath,
        [string]$DestinationFolder
    )

    if (-Not (Test-Path $PackagePath)) {
        throw "NuGet package not found at path: $PackagePath"
    }

    if (-Not (Test-Path $DestinationFolder)) {
        New-Item -ItemType Directory -Path $DestinationFolder | Out-Null
    }

    # Copy / rename file to a .zip
    $ZipPackagePath = [System.IO.Path]::GetFileNameWithoutExtension($PackagePath) + ".zip"
    Copy-Item -Path $PackagePath -Destination $ZipPackagePath

    Expand-Archive -Path $ZipPackagePath -DestinationPath $DestinationFolder -Force
}

function Get-PEArchitecture {
    param (
        [string]$FilePath
    )

    $stream = [System.IO.File]::OpenRead($FilePath)
    $reader = New-Object System.IO.BinaryReader($stream)

    try {
        # Read DOS header to find PE header offset
        $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $reader.ReadInt32()

        # Seek to PE header
        $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSignature = $reader.ReadBytes(4)

        if (-not ($peSignature[0] -eq 0x50 -and $peSignature[1] -eq 0x45 -and $peSignature[2] -eq 0x00 -and $peSignature[3] -eq 0x00)) {
            throw "Invalid PE signature."
        }

        # Machine type is next
        $machine = $reader.ReadUInt16()

        switch ($machine) {
            0x8664 { return 'x64' }
            0xAA64 { return 'arm64' }
            default { return "unknown(0x{0:X4})" -f $machine }
        }
    }
    finally {
        $reader.Close()
        $stream.Close()
    }
}

# Main
try {
    Write-Host "NuGet Package: $NugetPackagePath"
    Write-Host "Expected Architecture: $ExpectedArchitecture"

    $PackageName = [System.IO.Path]::GetFileNameWithoutExtension($NugetPackagePath)
    $ExtractionPath = Join-Path -Path $env:TEMP -ChildPath "Extracted_$PackageName"

    Write-Host "Extracting package to: $ExtractionPath"
    Extract-NuGetPackage -PackagePath $NugetPackagePath -DestinationFolder $ExtractionPath

    Write-Host "Extraction completed. Verifying architectures..."

    # Exclude vcruntime140_1.dll from validation as its architecture is ARM64EC for ARM64.
    $files = Get-ChildItem -Path $ExtractionPath -Recurse -Include *.dll, *.exe, *.sys -Exclude *vcruntime140_1.dll

    $allMatch = $true

    foreach ($file in $files) {
        $arch = Get-PEArchitecture -FilePath $file.FullName
        Write-Host "$($file.FullName): Detected architecture = $arch"

        if ($arch -ne $ExpectedArchitecture) {
            Write-Error "Mismatch: File '$($file.FullName)' is '$arch' but expected '$ExpectedArchitecture'."
            $allMatch = $false
        }
    }

    if ($allMatch) {
        Write-Host "All files match expected architecture '$ExpectedArchitecture'."
    }
    else {
        throw "Architecture mismatch found in package."
    }

} catch {
    Write-Error "Error: $_"
}