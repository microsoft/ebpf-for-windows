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
    param ([Parameter(Mandatory = $true)][string]$BranchPrefix,
    [Parameter(Mandatory = $true)][string]$RemoteUrl)

    Write-Output "Syncing new branches with prefix $BranchPrefix"
    $UpstreamPrefix = "upstream/" + $BranchPrefix
    $OriginPrefix = "origin/" + $BranchPrefix
    $Branches = git branch -r
    $UpstreamBranches = $Branches | Select-String -Pattern $UpstreamPrefix -AllMatches
    $LocalBranches = $Branches | Select-String -Pattern $OriginPrefix -AllMatches
    $LocalBranchNames = @()
    $NewBranchNames = @()

    if ($LocalBranches -ne $null)
    {
        if ($LocalBranches -is [array])
        {
            for ($i = 0; $i -lt $LocalBranches.Count; $i++)
            {
                $BranchNameSuffix = $LocalBranches[$i].Line -split "origin/"
                $LocalBranchNames += $BranchNameSuffix[1]
            }
        }
        else
        {
            $BranchNameSuffix = $LocalBranches.Line -split "origin/"
            $LocalBranchNames += $BranchNameSuffix[1]
        }
    }

    if ($UpstreamBranches -ne $null)
    {
        if ($UpstreamBranches -is [array])
        {
            for ($i = 0; $i -lt $UpstreamBranches.Count; $i++)
            {
                $BranchNameSuffix = $UpstreamBranches[$i].Line -split "upstream/"
                if (-not($LocalBranchNames.Contains($BranchNameSuffix[1])))
                {
                    $NewBranchNames += $BranchNameSuffix[1]
                }
            }
        }
        else
        {
            $BranchNameSuffix = $UpstreamBranches.Line -split "upstream/"
            if (-not($LocalBranchNames.Contains($BranchNameSuffix[1])))
            {
                $NewBranchNames += $BranchNameSuffix[1]
            }
        }
    }

    # Got the new branches. Create and push local version of these branches.
    for ($i = 0; $i -lt $NewBranchNames.Count; $i++)
    {
        $BranchName = $NewBranchNames[$i]
        Write-Output "Syncing new branch $BranchName"
        Write-Output "Executing: git checkout $BranchName"
        git checkout $BranchName
        Write-Output "Executing: git push -u origin $BranchName"
        git push -u origin $BranchName
    }

    Write-Output "Done syncing new branches"
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
Write-Output "Fetching changes from upstream"
git fetch upstream

# Merge the changes to local repo.
Write-Output "Merge changes to local repo"
git merge upstream/$BranchName

# Push the changes to remote.
Write-Output "Push changes to remote"
## git push $url
git push

# This script is invoked for multiple branches. Check and sync for new release
# branches only when it is invoked for "main".
if ($BranchName -eq "main")
{
    Get-UpstreamBranches -BranchPrefix "release/" -RemoteUrl $url
}

# Fetch the tags from upstream
Write-Output "Fetching tags from upstream"
git fetch upstream --tags

# Push the tags to remote.
Write-Output "Pushing tags to remote"
Write-Output "Executing: git push --tags"
git push --tags

Write-Output "Successfully mirrored latest changes"
