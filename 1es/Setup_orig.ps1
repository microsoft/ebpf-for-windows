# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$False)][string]$VmUsername='Administrator',
    [Parameter(Mandatory=$False)][string]$VmStandardUserName='VMStandardUser',
    [Parameter(Mandatory=$False)][string]$VmPassword='P@ssw0rd',

    [Parameter(Mandatory=$False)][string]$BaseUnattendPath='.\unattend.xml',
    [Parameter(Mandatory=$False)][string]$BaseVhdDirPath='.\',
    [Parameter(Mandatory=$False)][string]$WorkingPath='.\working',
    [Parameter(Mandatory=$False)][string]$OutVhdDirPath='.\exported_vhds',

    [Parameter(Mandatory=$False)][string]$VMCpuCount=4,
    [Parameter(Mandatory=$False)][string]$VMMemory=4096MB
)

$ErrorActionPreference = "Stop"

# Import helper functions
Import-Module .\prepare_vm_helpers.psm1 -Force

if (-not (Test-Path -Path $BaseUnattendPath)) {
    throw "Unattend file not found at $BaseUnattendPath"
}

if (-not (Test-Path -Path $BaseVhdDirPath)) {
    throw "VHD directory not found at $BaseVhdDirPath"
}

Create-VMSwitchIfNeeded -SwitchName 'VMInternalSwitch' -SwitchType 'Internal'
Create-VMSwitchIfNeeded -SwitchName 'VMExternalSwitch' -SwitchType 'External'
# Stored credentials doesn't seem to be working...
# Create-VMStoredCredential -CredentialName "TEST_VM" -Username $VmUsername -Password $VmPassword
# Create-VMStoredCredential -CredentialName "TEST_VM_STANDARD" -Username $VmStandardUserName -Password $VmPassword
Create-DirectoryIfNotExists -Path $WorkingPath

# Unzip any VHDs
$zipFiles = Get-ChildItem -Path $BaseVhdDirPath -Filter *.zip
foreach ($zipFile in $zipFiles) {
    $outDir = Join-Path -Path $BaseVhdDirPath -ChildPath $zipFile.BaseName
    if (-not (Test-Path -Path $outDir)) {
        Expand-Archive -Path $zipFile.FullName -DestinationPath $outDir

        # Move the VHDs to the base directory
        $vhdFiles = Get-ChildItem -Path $outDir -Filter *.vhd -ErrorAction Ignore
        $vhdFiles += Get-ChildItem -Path $outDir -Filter *.vhdx -ErrorAction Ignore
        foreach ($vhdFile in $vhdFiles) {
            Move-Item -Path $vhdFile.FullName -Destination $BaseVhdDirPath
        }
    }
}

# Read the input VHDs
$vhds = @((Get-ChildItem -Path $BaseVhdDirPath -Filter *.vhd))
$vhds += Get-ChildItem -Path $BaseVhdDirPath -Filter *.vhdx
if ($vhds.Count -eq 0) {
    throw "No VHDs found in $BaseVhdDirPath"
}

for ($i = 0; $i -lt $vhds.Count; $i++) {
    try {
        $vhd = $vhds[$i]
        Log-Message -Message "Processing VHD: $($vhd.FullName)"
        $vmName = "runner_vm"
        if ($i -gt 0) {
            $vmName += "_$i"
        }
        $outVMPath = Join-Path -Path $WorkingPath -ChildPath $VMName

        Create-VM `
            -VmName $vmName `
            -VhdPath $vhd.FullName `
            -VmStoragePath $outVMPath `
            -VMMemory $VMMemory `
            -UnattendPath $BaseUnattendPath `
            -VmUsername $VmUsername `
            -VmPassword $VmPassword

        Configure-VM `
            -VmName $vmName `
            -VmUsername $VmUsername `
            -VmPassword $VmPassword `
            -CpuCount $CpuCount

        Log-Message "VM $vmName created successfully"
    } catch {
        Log-Message "Failed to create VM $vmName with error $_"
    }
}

Log-Message "Setup.ps1 complete!"