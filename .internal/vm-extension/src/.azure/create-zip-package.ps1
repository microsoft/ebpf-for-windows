
# Usage:
# .\create-zip-package.ps1 -zipFileName "<publisher>.<extension name>.<version>.zip" -sourcePath "<full path to the eBPF binaries root from the eBPF Redist package>"


param (
    [string]$zipFileName,
    [string]$sourcePath
)

# Verify that the specified source path exists
if (-not (Test-Path -Path $sourcePath -PathType Container)) {
    Write-Host "Error: The 'redist' path '$sourcePath' does not exist."
    exit 1
}

# Get the current directory where the script is executed
$CurrentDirectory = Get-Location

# Create a temporary directory to store the files
$TempDir = [System.IO.Path]::Combine($CurrentDirectory, [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    # Copy the contents of the source directory to a "bin" folder within the temporary directory
    $BinFolder = [System.IO.Path]::Combine($TempDir, "bin")
    New-Item -ItemType Directory -Path $BinFolder | Out-Null
    Copy-Item -Path (Join-Path -Path $sourcePath -ChildPath "*") -Destination $BinFolder -Recurse -Force

    # Copy the "scripts" directory to the temporary directory
    $ScriptsPath = Join-Path -Path $PSScriptRoot -ChildPath "..\scripts"
    Copy-Item -Path $ScriptsPath -Destination $TempDir -Recurse -Force

    # Copy the "..\HandlerManifest.json" file to the temporary directory
    $ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath "..\HandlerManifest.json"
    Copy-Item -Path $ManifestPath -Destination $TempDir -Force

    # Create the zip file in the current directory
    $zipFilePath = [System.IO.Path]::Combine($CurrentDirectory, $zipFileName)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($TempDir, $zipFilePath)

    Write-Host "VM Extension ZIP package file '$zipFilePath' created successfully."
}
finally {
    # Clean up: Remove the temporary directory
    Remove-Item -Path $TempDir -Recurse -Force
}
