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
    [Parameter(Mandatory=$False)][string]$ExternalSwitchName='VMExternalSwitch',

    [Parameter(Mandatory=$False)][string]$VMCpuCount=2,
    [Parameter(Mandatory=$False)][string]$VMMemoryStartupBytes=512MB
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
Create-VMStoredCredential -CredentialName "TEST_VM" -Username $VmUsername -Password $VmPassword
Create-VMStoredCredential -CredentialName "TEST_VM_STANDARD" -Username $VmStandardUserName -Password $VmPassword
Create-DirectoryIfNotExists -Path $WorkingPath

# Read the input VHDs
$vhds = @((Get-ChildItem -Path $BaseVhdDirPath -Filter *.vhd))
$vhds += Get-ChildItem -Path $BaseVhdDirPath -Filter *.vhdx
if ($vhds.Count -eq 0) {
    throw "No VHDs found in $BaseVhdDirPath"
}

for ($i = 0; $i -lt $vhds.Count; $i++) {
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
        -ExternalVMSwitchName $ExternalSwitchName `
        -MemoryStartupBytes $VMMemoryStartupBytes `
        -UnattendPath $BaseUnattendPath `
        -VmUsername $VmUsername `
        -VmPassword $VmPassword

    Configure-VM `
        -VmName $vmName `
        -CpuCount $VMCpuCount `
        -VmUsername $VmUsername `
        -VmPassword $VmPassword
}
