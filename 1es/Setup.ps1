# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
# param(
#     [Parameter(Mandatory=$False)][string]$VmUsername='Administrator',
#     [Parameter(Mandatory=$False)][string]$VmPassword='P@ssw0rd',

#     [Parameter(Mandatory=$False)][string]$BaseUnattendPath='.\unattend.xml',
#     [Parameter(Mandatory=$False)][string]$BaseVhdDirPath='.\',
#     [Parameter(Mandatory=$False)][string]$WorkingPath='.\working',
#     [Parameter(Mandatory=$False)][string]$OutVhdDirPath='.\exported_vhds',
#     [Parameter(Mandatory=$False)][string]$ExternalSwitchName='VMExternalSwitch',

#     [Parameter(Mandatory=$False)][string]$VMCpuCount=4,
#     [Parameter(Mandatory=$False)][string]$VMMemoryStartupBytes=512MB
# )

# $ErrorActionPreference = "Stop"

# Import helper functions
Import-Module .\prepare_vm_helpers.psm1 -Force

$hyperV = (Get-WindowsFeature -Name 'Hyper-V').Installed
Log-Message -Message "Hyper-V is installed: $hyperV"

$names = (Get-NetAdapter).Name
Log-Message -Message "Network adapters: $names"

$switches = Get-VMSwitch
Log-Message -Message "VM switches: $switches"



# TODO - eventually, setup_orig will become setup.ps1