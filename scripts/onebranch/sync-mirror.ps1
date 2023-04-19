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

<#
.SYNOPSIS
    Find new 'upstream' branches and add them to 'remote' based on
    the provided branch prefix.
#>
function Get-UpstreamBranches
{
    param ([Parameter(Mandatory = $true)][string]$BranchPrefix)

    Write-Output "Syncing new branches with prefix $BranchPrefix"
    $UpstreamPrefix = "upstream/" + $BranchPrefix
    $OriginPrefix = "origin/" + $BranchPrefix
    $Branches = git branch -r
    $UpstreamBranches = $Branches | Select-String -Pattern $UpstreamPrefix -AllMatches
    $LocalBranches = $Branches | Select-String -Pattern $OriginPrefix -AllMatches
    $LocalBranchNames = @()

    for ($i = 0; $i -lt $LocalBranches.Count; $i++)
    {
        $LocalBranchNames += $LocalBranches[$i].Line
    }

    $NewBranchNames = @()
    for ($i = 0; $i -lt $UpstreamBranches.Count; $i++)
    {
        if (-not($LocalBranchNames.Contains($UpstreamBranches[$i].Line)))
        {
            $NewBranchNames += $UpstreamBranches[$i].Line
        }
    }

    # Got the new branches. Create and push local version of these branches.
    for ($i = 0; $i -lt $NewBranchNames.Count; $i++)
    {
        $BranchNames = $NewBranchNames[$i] -split "upstream/"
        $BranchName = $BranchNames[1]
        Write-Output "Syncing new branch $BranchName"
        git checkout $BranchName
        git push -u origin $BranchName
    }
}

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Set Git user name.
$email = $env:User + "@microsoft.com"
git config user.name $env:User
git config user.email $email

$url = "https://" + $env:AZDO_PAT + "@mscodehub.visualstudio.com/eBPFForWindows/_git/eBPFForWindows"

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
git push $url

# Fetch the tags from upstream
git fetch upstream --tags

# Push the tags to remote.
git push --tags $url

# This script is invoked for multiple branches. Check and sync for new release
# branches only when it is invoked for "main".
if ($BranchName -is "main")
{
    Get-UpstreamBranches -BranchPrefix "release/"
}

Write-Output "Successfully mirrored latest changes"
