# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $false)]
    [string]$Image = 'ebpfw-tlaps',

    [Parameter(Mandatory = $false)]
    [string]$Dockerfile = 'tools/tlaps/Dockerfile',

    [Parameter(Mandatory = $false)]
    [switch]$Rebuild,

    # Optional override of command run in the container.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Cmd
)

$ErrorActionPreference = 'Stop'

function Test-DockerImageExists {
    param([string]$Name)
    & docker image inspect $Name *> $null
    return ($LASTEXITCODE -eq 0)
}

if ($Rebuild -or -not (Test-DockerImageExists -Name $Image)) {
    Write-Host "Building Docker image '$Image'..."
    & docker build -t $Image -f $Dockerfile .
}

$repoRoot = (Get-Location).Path

$dockerArgs = @(
    'run', '--rm', '-t',
    '-v', "${repoRoot}:/repo",
    '-w', '/repo',
    $Image
)

if ($Cmd -and $Cmd.Count -gt 0) {
    $dockerArgs += $Cmd
} else {
    # Default: run repo proof runner.
    $dockerArgs += @('bash', 'scripts/run_tlaps.sh')
}

& docker @dockerArgs
exit $LASTEXITCODE
