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

.PARAMETER VMPath
    The path where the VMs will be created. Default is C:\vms.

.PARAMETER WorkingDirectory
    The host working directory containing signed drivers and used for VM configuration. Default is C:\work.

.PARAMETER VMCpuCount
    The number of CPUs to assign to each VM. Default is 4.

.PARAMETER VMMemory
    The amount of memory to assign to each VM. Default is 4096MB.

.PARAMETER VMSwitchName
    The name of the internal VM switch. Default is VMInternalSwitch.

.PARAMETER RebootVM
    Reboot the VM after configuration and before creating the baseline checkpoint. Default is $True.

.EXAMPLE
    .\Setup.ps1 -BaseUnattendPath 'C:\path\to\unattend.xml' -BaseVhdDirPath 'C:\path\to\vhd' -VMPath 'C:\vms' -WorkingDirectory 'C:\work'
#>
param(
    [Parameter(Mandatory=$False)][string]$BaseUnattendPath='.\unattend.xml',
    [Parameter(Mandatory=$False)][string]$BaseVhdDirPath='.\',
    [Parameter(Mandatory=$False)][string]$VMPath='C:\vms',
    [Parameter(Mandatory=$False)][string]$WorkingDirectory='c:\work',
    [Parameter(Mandatory=$False)][string]$VMSwitchName='VMInternalSwitch',
    [Parameter(Mandatory=$False)][string]$VMCpuCount=4,
    [Parameter(Mandatory=$False)][string]$VMMemory=4096MB,
    [Parameter(Mandatory=$False)][bool]$RebootVM=$True
)

$ErrorActionPreference = "Stop"

# Import helper functions.
$logFileName = 'Setup.log'
Import-Module .\common.psm1 -Force -ArgumentList ($logFileName) -WarningAction SilentlyContinue
Import-Module .\config_test_vm.psm1 -Force -ArgumentList($WorkingDirectory, $logFileName) -WarningAction SilentlyContinue

# Create working directory used for VM creation.
Create-DirectoryIfNotExists -Path $VMPath

# Create internal switch for VM.
Create-VMSwitchIfNeeded -SwitchName $VMSwitchName -SwitchType 'Internal'

# Unzip any VHD files, if needed, and get the list of VHDs to create VMs from.
$vhds = Prepare-VhdFiles -InputDirectory $BaseVhdDirPath
$vhdDebugString = $vhds | Out-String

# Build list of signed binaries to copy to the VM.
# These are pre-signed native eBPF drivers that need to be available in the VM for testing.
# The signed drivers are downloaded to $WorkingDirectory on the 1ES runner by the CI pipeline.
$signedBinariesToCopy = @()
$vmDestinationPath = 'C:\eBPF'
$signedDriversPath = $WorkingDirectory

# List of signed bindmonitor driver files to look for.
$signedDriverFiles = @(
    'bindmonitor_x64_signed.sys',
    'bindmonitor_x64_debug_signed.sys',
    'bindmonitor_arm64_signed.sys',
    'bindmonitor_arm64_debug_signed.sys'
)

# Look for signed bindmonitor binaries in $WorkingDirectory.
foreach ($fileName in $signedDriverFiles) {
    $filePath = Join-Path -Path $signedDriversPath -ChildPath $fileName
    if (Test-Path $filePath) {
        Write-Log "Found signed binary: $filePath"
        $signedBinariesToCopy += @{
            Source = $filePath
            Destination = Join-Path -Path $vmDestinationPath -ChildPath $fileName
        }
    } else {
        Write-Log "Signed binary not found: $filePath"
    }
}

if ($signedBinariesToCopy.Count -gt 0) {
    Write-Log "Found $($signedBinariesToCopy.Count) signed binary file(s) to copy to VM."
} else {
    throw "Certain signed binaries not found in $signedDriversPath. Signed drivers are required for proof_of_verification tests."
}

# Process VM creation and setup.
foreach ($vhd in $vhds) {
    try {
        Write-Log "Creating VM from VHD: $vhd"
        $vmName = "runner_vm"
        if ($i -gt 0) {
            $vmName += "_$i"
        }
        $outVMPath = Join-Path -Path $VMPath -ChildPath $VMName

        Create-VM `
            -VmName $vmName `
            -VhdPath $vhd `
            -VmStoragePath $outVMPath `
            -VMMemory $VMMemory `
            -UnattendPath $BaseUnattendPath `
            -VMSwitchName $VMSwitchName

        Initialize-VM `
            -VmName $vmName `
            -VMCpuCount $VMCpuCount `
            -FilesToCopy $signedBinariesToCopy `
            -RebootVM $RebootVM

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