# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

$LogFileName = "prepare_1es_artifacts.log"
Import-Module ..\scripts\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

# Replace the placeholder strings in the artifacts.json file with the appropriate values.
Write-Log "Replacing placeholder strings in artifacts.json file."
$images = ('server-2025')
foreach ($image in $images) {
    Write-Log "Replacing placeholder strings for image $image."
    $outFileName = "artifacts_$image.json"
    Copy-Item -Path .\artifacts.json -Destination $outFileName
    # The IMAGETYPE name MUST match the Azure Storage Blob Container that holds the necessary dependencies for configuring the 1ES runner.
    Replace-PlaceholderStrings -Path $outFileName -SearchString 'IMAGETYPE' -ReplaceString $image
}

# Copy any shared scripts into the 1ES folder.
$scripts = @(
    '..\scripts\common.psm1',
    '..\scripts\config_test_vm.psm1'
)
Write-Log "Copying shared scripts into the 1ES folder."
foreach ($script in $scripts) {
    Write-Log "Copying $script into $pwd"
    Copy-Item -Path $script -Destination $pwd -Force
}
