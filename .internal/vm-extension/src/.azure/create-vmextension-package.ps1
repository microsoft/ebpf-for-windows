# This script creates the VM Extension package from the eBPF Redist package.
# It is used by the CI/CD pipeline to create the VM Extension package, which will be created in the same directory as the Redist package
# and named as 'Microsoft.EbpfForWindows.EbpfForWindows.<version number in'main'>.1.zip'.
#
# Usage example: create-vmextension-package -redistPackagePath "C:\work\eBPFForWindows\x64\Debug"

param (
    [string]$redistPackagePath
)

# Define the constants for the VM Extension publisher and type names
$publisherName = "Microsoft.EbpfForWindows"
$typeName = "EbpfForWindows"

# Create a temporary working directory
$tempDir = [System.IO.Path]::Combine($PSScriptRoot, [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    # Check if the redist package file exists in the given directory
    if (-not (Test-Path $redistPackagePath)) {
        throw "Redistibutable package path not found at '$redistPackagePath'."
    } 
    $redistFile = Get-ChildItem -Path $redistPackagePath -Filter "eBPF-for-Windows-Redist.*.nupkg" | Select-Object -First 1
    if ($null -eq $redistFile) {
        throw "No 'eBPF-for-Windows-Redist' package found in '$redistPackagePath'."
    }

    # Temporarily rename the .nupkg to .zip
    $redistTempFileName = [System.IO.Path]::ChangeExtension($redistFile.FullName, "zip")
    Rename-Item -Path $redistFile.FullName -NewName $redistTempFileName -Force

    # Extract the entire contents of the zip file to the temporary folder
    $tempExtractionFolder = Join-Path -Path $tempDir -ChildPath "nuget"
    New-Item -ItemType Directory -Path $tempExtractionFolder | Out-Null
    Expand-Archive -Path $redistTempFileName -DestinationPath $tempExtractionFolder -Force

    # Copy only the '\package\bin' subdirectory to the destination path
    Copy-Item -Path "$tempExtractionFolder\package\bin" -Destination $tempDir -Recurse -Force
    Remove-Item -Path $tempExtractionFolder -Recurse -Force

    # Restore the original file name
    Rename-Item -Path $redistTempFileName -NewName $redistFile.FullName -Force

    # Copy the 'scripts' directory to the temporary directory
    $scriptsPath = Join-Path -Path $PSScriptRoot -ChildPath "..\scripts"
    Copy-Item -Path $scriptsPath -Destination $tempDir -Recurse -Force

    # Copy the '..\HandlerManifest.json' file to the temporary directory
    $manifestPath = Join-Path -Path $PSScriptRoot -ChildPath "..\HandlerManifest.json"
    Copy-Item -Path $manifestPath -Destination $tempDir -Force

    # Create the zip file with the specified version number in the destination folder
    $versionNumber = Invoke-Expression "$PSScriptRoot\..\..\..\..\scripts\Get-Version.ps1"
    $zipFileName = "$publisherName.$typeName.$versionNumber.1.zip"
    $zipFilePath = [System.IO.Path]::Combine($redistPackagePath, $zipFileName)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $zipFilePath)

    Write-Host "VM Extension ZIP package file '$zipFilePath' created successfully."
}
catch {
    Write-Host "Error: $_"
    throw $_
}
finally {
    # Clean up: Remove the temporary directory
    Remove-Item -Path $tempDir -Recurse -Force
}