# This function injects a given file into the eBPF Redist package (under \package\.internal\lib\).
# It is used by the CI/CD pipeline to inject common.ps1 script into the redistibutable to be delivered to IMDS,
# which is then used by the Guest Proxy Agent VM extension as a library to deploy eBPF.
#
# Usage example: inject-vmextension-lib-in-redist-package -redistPackagePath "C:\work\eBPFForWindows\x64\Debug" -fileToInjectPath "C:\work\eBPFForWindows\.internal\vm-extension\src\scripts\common.ps1"

param (
    [string]$redistPackagePath,
    [string]$fileToInjectPath
)

try {
    # Check if the file to inject exists
    if (-not (Test-Path $fileToInjectPath)) {
        throw "File to inject not found at '$fileToInjectPath'."
    }

    # Check if the redist package file exists in the given directory
    if (-not (Test-Path $redistPackagePath)) {
        throw "Redistibutable package path not found at '$redistPackagePath'."
    }    
    $redistFile = Get-ChildItem -Path $redistPackagePath -Filter "eBPF-for-Windows-Redist.*.nupkg" | Select-Object -First 1
    if ($null -eq $redistFile) {
        throw "No 'eBPF-for-Windows-Redist' package found at '$redistFile'."
    }

    # Rename the matching file to have a ".zip" extension
    $renamedFileFullName = Join-Path -Path $redistFile.Directory.FullName -ChildPath "$($redistFile.BaseName).zip"
    Rename-Item -Path $redistFile.FullName -NewName "$($redistFile.BaseName).zip" -Force
    $renamedFile = Get-Item -LiteralPath $renamedFileFullName

    # Load the assembly containing the ZipFile class
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Create a ZipArchive object to open the existing zip file
    $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($renamedFile.FullName)

    # Create a new ZipArchive object for the updated zip file
    $updatedRedistFilePath = Join-Path -Path $redistFile.Directory.FullName -ChildPath "$($redistFile.BaseName).nupkg"
    $updatedZipArchive = [System.IO.Compression.ZipFile]::Open($updatedRedistFilePath, [System.IO.Compression.ZipArchiveMode]::Create)

    # Copy the all the contents of the redist-package to the updated zip file
    foreach ($entry in $zipArchive.Entries) {
        $entryStream = $entry.Open()

        # Create a new entry with the same directory structure within the new zip
        $newEntryPath = $entry.FullName
        $newEntry = $updatedZipArchive.CreateEntry($newEntryPath)
        $newEntryStream = $newEntry.Open()

        $entryStream.CopyTo($newEntryStream)

        $entryStream.Close()
        $newEntryStream.Close()
    }

    # Add a new directory "\package\.internal\lib" to the updated zip file
    $newDirectoryPath = "package\.internal\lib\"
    $null = $updatedZipArchive.CreateEntry($newDirectoryPath)

    # Add the common.ps1 library to the updated zip file, within the new directory (to be used by the Guest Proxy Agent VM extension as a library)
    $updatedEntryPath = "$newDirectoryPath$((Get-Item $fileToInjectPath).Name)"
    $updatedEntry = $updatedZipArchive.CreateEntry($updatedEntryPath)
    $updatedEntryStream = $updatedEntry.Open()
    $fileStream = [System.IO.File]::OpenRead($fileToInjectPath)
    $fileStream.CopyTo($updatedEntryStream)
    $fileStream.Close()
    $updatedEntryStream.Close()

    # Close the zip archives
    $zipArchive.Dispose()
    $updatedZipArchive.Dispose()

    # Remove the original archive
    Remove-Item -Path $renamedFile.FullName -Force

    Write-Host "File '$updatedEntryPath' has been injected successfully. Updated package saved as '$updatedRedistFilePath'. Original package deleted."
}
catch {
    Write-Host "Error: $_"
    throw $_
}