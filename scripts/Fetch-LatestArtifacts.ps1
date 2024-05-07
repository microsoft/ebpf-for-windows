# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Script to pull artifact from latest scheduled run from a GitHub Actions workflow.

param(
    [Parameter(Mandatory=$true)] [string] $ArtifactName,
    [Parameter(Mandatory=$true)] [string] $OutputPath,
    [Parameter(Mandatory=$true)] [string] $Owner,
    [Parameter(Mandatory=$true)] [string] $Repo,
    [Parameter(Mandatory=$false)] [string] $WorkflowName = "CI/CD",
    [Parameter(Mandatory=$false)] [string] $Branch = "main",
    [Parameter(Mandatory=$false)] [string] $RunId = $null)

if ($null -eq (Get-Command 'gh.exe' -ErrorAction SilentlyContinue)) {
    throw "Unable to locate gh.exe. This command requires GitHub CLI installed and in your path."
}

if (!$runid) {
    # Get the latest run ID for the branch and workflow
    # GitHub REST API for Actions: https://docs.github.com/en/rest/reference/actions
    # It does not support filtering by workflow name, so we have to get all runs and filter locally.
    $run = ((Invoke-WebRequest -Uri  "https://api.github.com/repos/$Owner/$Repo/actions/runs?per_page=10&exclude_pull_requests=true&branch=$Branch&status=completed&event=schedule&conclusion=success").Content | ConvertFrom-Json)
    $run = $run.workflow_runs | Where-Object { $_.name -eq $WorkflowName } | Select-Object -First 1
    $runid = $run.id
}

Write-Output "Using run ID $runid in branch $Branch in repo $Owner/$Repo to fetch artifact $ArtifactName to $OutputPath."

gh run download $runid -R "$Owner/$Repo" -n $ArtifactName -D $OutputPath
