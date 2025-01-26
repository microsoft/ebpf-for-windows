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
$logFileName = 'Setup.log'
Import-Module .\common.psm1 -Force -ArgumentList ($logFileName) -WarningAction SilentlyContinue
$password = New-UniquePassword
$passwordSecureString = ConvertTo-SecureString -String $password -AsPlainText -Force
Import-Module .\config_test_vm.psm1 -Force -ArgumentList('Administrator', $passwordSecureString, 'C:\work', $logFileName) -WarningAction SilentlyContinue

# Create new credentials for the VM.
$AdminUserCredential =  Generate-NewCredential -Username 'Administrator' -Password $password -Target 'TEST_VM'
$StandardUserCredential = Generate-NewCredential -Username 'VMStandardUser' -Password $password -Target 'TEST_VM_STANDARD'

# Create working directory used for VM creation.
Create-DirectoryIfNotExists -Path $WorkingPath

# Create internal switch for VM.
$VMSwitchName = 'VMInternalSwitch'
Create-VMSwitchIfNeeded -SwitchName $VMSwitchName -SwitchType 'Internal'

# Unzip any VHD files, if needed, and get the list of VHDs to create VMs from.
$vhds = Prepare-VhdFiles -InputDirectory $BaseVhdDirPath
$vhdDebugString = $vhds | Out-String

# Process VM creation and setup.
foreach ($vhd in $vhds) {
    try {
        Write-Log "Creating VM from VHD: $vhd"
        $vmName = "runner_vm"
        if ($i -gt 0) {
            $vmName += "_$i"
        }
        $outVMPath = Join-Path -Path $WorkingPath -ChildPath $VMName

        Create-VM `
            -VmName $vmName `
            -UserPassword $password `
            -VhdPath $vhd `
            -VmStoragePath $outVMPath `
            -VMMemory $VMMemory `
            -UnattendPath $BaseUnattendPath `
            -VMSwitchName $VMSwitchName

        Initialize-VM `
            -VmName $vmName `
            -VMCpuCount $VMCpuCount

        Write-Log "VM $vmName created successfully"
    } catch {
        Write-Log "Failed to create VM $vmName with error $_"
        throw "Failed to create VM $vmName with error $_"
    }
}

$vms = Get-VM
if ($vms.Count -eq 0) {
    throw "No VMs were created. Check script execution logs for more details."
    Exit 1
}

Write-Log "Setup.ps1 complete!"