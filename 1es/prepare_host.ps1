# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$False)][string]$ExternalSwitchName='VMExternalSwitch'
)

Import-Module .\prepare_vm_helpers.psm1 -Force

Install-HyperVIfNeeded
Create-ExternalSwitchIfNeeded -ExternalSwitchName $ExternalSwitchName

# TODO - Fetch VHDs