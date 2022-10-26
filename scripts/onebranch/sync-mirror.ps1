# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
This script synchronizes a local branch in the current repository from the upstream repo.

.EXAMPLE
    sync-mirror.ps1

.EXAMPLE
    sync-mirror.ps1 -BranchName main
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$BranchName = "main"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Set Git user name.
$email = $env:User + "@microsoft.com"
git config user.name $env:User
git config user.email $email

# Add the GitHub repo as a remote.
git remote add upstream "https://github.com/microsoft/ebpf-for-windows.git"

# Diagnostics
git remote -v

# Checkout the local branch.
git checkout $BranchName

# Reset branch to origin.
git reset --hard origin/$BranchName

# Fetch the changes from upstream.
git fetch upstream

# Merge the changes to local repo.
git merge upstream/$BranchName

# Push the changes to remote.
$url = "https://" + $env:AZDO_PAT + "@mscodehub.visualstudio.com/eBPFForWindows/_git/eBPFForWindows"
git push $url

Write-Host "Successfully mirrored latest changes"
