# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    This script configures a host environment by creating and configuring VMs required for testing.

.DESCRIPTION
    This script will create and configure VMs based on the provided parameters.
    It is expected that the current working directory contains the necessary files to execute this script.

.PARAMETER BaseUnattendPath
    The path to the base unattend.xml file used for VM creation.

.PARAMETER BaseVhdDirPath
    The path to the base VHD directory used for VM creation.

.PARAMETER WorkingPath
    The working path where the VMs will be created.

.PARAMETER VMCpuCount
    The number of CPUs to assign to each VM. Default is 4.

.PARAMETER VMMemory
    The amount of memory to assign to each VM. Default is 4096MB.

.EXAMPLE
    .\Setup.ps1 -BaseUnattendPath 'C:\path\to\unattend.xml' -BaseVhdDirPath 'C:\path\to\vhd' -WorkingPath 'C:\vms'
#>
param(
    [Parameter(Mandatory=$False)][string]$BaseUnattendPath='.\unattend.xml',
    [Parameter(Mandatory=$False)][string]$BaseVhdDirPath='.\',
    [Parameter(Mandatory=$False)][string]$WorkingPath='C:\vms',
    [Parameter(Mandatory=$False)][string]$VMCpuCount=4,
    [Parameter(Mandatory=$False)][string]$VMMemory=4096MB
)

$ErrorActionPreference = "Stop"

# Import helper functions
Import-Module .\prepare_vm_helpers.psm1 -Force

# Input validation for input paths
if (-not (Test-Path -Path $BaseUnattendPath)) {
    throw "Unattend file not found at $BaseUnattendPath"
}

if (-not (Test-Path -Path $BaseVhdDirPath)) {
    throw "VHD directory not found at $BaseVhdDirPath"
}

# Create working directory used for VM creation.
Create-DirectoryIfNotExists -Path $WorkingPath

# Create internal switch for VM.
$VMSwitchName = 'VMInternalSwitch'
Create-VMSwitchIfNeeded -SwitchName $VMSwitchName -SwitchType 'Internal'

# Fetch the credentials for the VM using the Azure Key Vault.
$AdminUserCredential = Get-AzureKeyVaultCredential -SecretName 'Administrator'
$StandardUserCredential = Get-AzureKeyVaultCredential -SecretName 'VMStandardUser'

# Unzip any VHD files, if needed, and get the list of VHDs to create VMs from.
$vhds = Prepare-VhdFiles -BaseVhdDirPath $BaseVhdDirPath

# Process VM creation and setup.
for ($i = 0; $i -lt $vhds.Count; $i++) {
    try {
        $vhd = $vhds[$i]
        Log-Message -Message "Creating VM from VHD: $($vhd.FullName)"
        $vmName = "runner_vm"
        if ($i -gt 0) {
            $vmName += "_$i"
        }
        $outVMPath = Join-Path -Path $WorkingPath -ChildPath $VMName

        Create-VM `
            -VmName $vmName `
            -AdminUserCredential $AdminUserCredential `
            -StandardUserCredential $StandardUserCredential `
            -VhdPath $vhd.FullName `
            -VmStoragePath $outVMPath `
            -VMMemory $VMMemory `
            -UnattendPath $BaseUnattendPath `
            -VMSwitchName $VMSwitchName

        Configure-VM `
            -VmName $vmName `
            -VmCredential $AdminUserCredential `
            -VMCpuCount $VMCpuCount

        Log-Message "VM $vmName created successfully"
    } catch {
        Log-Message "Failed to create VM $vmName with error $_"
    }
}

Log-Message "Setup.ps1 complete!"