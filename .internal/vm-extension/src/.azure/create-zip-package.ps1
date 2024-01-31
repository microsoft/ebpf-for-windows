
# Usage:
# .\create-zip-package.ps1 -versionNumber "<x.y.z.p>"" -ebpfBinPackagePath "<full path to the eBPF binaries root from the eBPF Redist package>" -zipDestinationFolder "<full path to the destination folder for the ZIP package file>"

param (
    [string]$versionNumber,
    [string]$ebpfBinPackagePath,
    [string]$zipDestinationFolder
)

# Define constants for publisher name and type name
$publisherName = "Microsoft.EbpfForWindows"
$typeName = "EbpfForWindows"

# Create a temporary directory to store the files
$tempDir = [System.IO.Path]::Combine($currentDirectory, [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    # Verify that the specified source path exists
    if (-not (Test-Path -Path $ebpfBinPackagePath -PathType Container)) {
        Write-Host "Error: The source path '$ebpfBinPackagePath' does not exist."
        exit 1
    }

    # Get the current directory where the script is executed
    $currentDirectory = Get-Location

    # Copy the contents of the source directory to a "bin" folder within the temporary directory
    $binFolder = [System.IO.Path]::Combine($tempDir, "bin")
    New-Item -ItemType Directory -Path $binFolder | Out-Null
    Copy-Item -Path (Join-Path -Path $ebpfBinPackagePath -ChildPath "*") -Destination $binFolder -Recurse -Force

    # Copy the "scripts" directory to the temporary directory
    $scriptsPath = Join-Path -Path $PSScriptRoot -ChildPath "..\scripts"
    Copy-Item -Path $scriptsPath -Destination $tempDir -Recurse -Force

    # Copy the "..\HandlerManifest.json" file to the temporary directory
    $manifestPath = Join-Path -Path $PSScriptRoot -ChildPath "..\HandlerManifest.json"
    Copy-Item -Path $manifestPath -Destination $tempDir -Force

    # Create the zip file with the specified version number in the destination folder
    $zipFileName = "$publisherName.$typeName.$versionNumber.zip"
    $zipFilePath = [System.IO.Path]::Combine($zipDestinationFolder, $zipFileName)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $zipFilePath)

    Write-Host "VM Extension ZIP package file '$zipFilePath' created successfully."
}
finally {
    # Clean up: Remove the temporary directory
    Remove-Item -Path $tempDir -Recurse -Force
}
