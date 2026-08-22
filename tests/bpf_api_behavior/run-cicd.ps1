# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $false)]
    [string] $LogFileName = "TestLog.log",

    [Parameter(Mandatory = $false)]
    [string] $WorkingDirectory = $pwd.ToString(),

    [Parameter(Mandatory = $false)]
    [string] $TestExecutionJsonFileName = "test_execution.json",

    [Parameter(Mandatory = $false)]
    [string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),

    [Parameter(Mandatory = $false)]
    [int] $TestJobTimeout = (30 * 60)
)

$ErrorActionPreference = "Stop"

Push-Location $WorkingDirectory

try {
    Import-Module `
        "$WorkingDirectory\common.psm1" `
        -Force `
        -ArgumentList $LogFileName `
        -WarningAction SilentlyContinue

    Import-Module `
        "$WorkingDirectory\config_test_vm.psm1" `
        -Force `
        -ArgumentList @($WorkingDirectory, $LogFileName) `
        -WarningAction SilentlyContinue

    $config_path = Join-Path `
        $WorkingDirectory `
        $TestExecutionJsonFileName

    $runner_path = Join-Path `
        $PSScriptRoot `
        "run-tests.ps1"

    $artifact_directory = Join-Path `
        $WorkingDirectory `
        "Artifacts"

    $local_output = Join-Path `
        $artifact_directory `
        "bpf-api-windows.tsv"

    if (-not (Test-Path -LiteralPath $config_path)) {
        throw "Test execution configuration not found: $config_path"
    }

    if (-not (Test-Path -LiteralPath $runner_path)) {
        throw "Behavior test runner not found: $runner_path"
    }

    New-Item `
        -ItemType Directory `
        -Path $artifact_directory `
        -Force |
        Out-Null

    $config = Get-Content `
        -LiteralPath $config_path `
        -Raw |
        ConvertFrom-Json

    $vm_list = $config.VMMap.$SelfHostedRunnerName

    if ($null -eq $vm_list -or @($vm_list).Count -eq 0) {
        throw "No test VM configured for runner: $SelfHostedRunnerName"
    }

    $vm_name = @($vm_list)[0].Name
    $credential = Get-VMCredential -Username "Administrator"
    $session = $null

    Write-Log "Running bpf_api_behavior on VM $vm_name"

    try {
        $session = New-PSSession `
            -VMName $vm_name `
            -Credential $credential

        $remote_paths = Invoke-Command `
            -Session $session `
            -ScriptBlock {
                $root = Join-Path $env:SystemDrive "eBPF"

                [pscustomobject]@{
                    Executable = Join-Path $root "bpf_api_behavior.exe"
                    Runner = Join-Path $root "run-bpf-api-behavior-tests.ps1"
                    Output = Join-Path $root "bpf-api-windows.tsv"
                }
            }

        Copy-Item `
            -LiteralPath $runner_path `
            -Destination $remote_paths.Runner `
            -ToSession $session `
            -Force

        Invoke-Command `
            -Session $session `
            -ScriptBlock {
                param($executable, $runner, $output)

                if (-not (Test-Path -LiteralPath $executable)) {
                    throw "Behavior test executable not found: $executable"
                }

                & $runner `
                    -Executable $executable `
                    -Output $output
            } `
            -ArgumentList @(
                $remote_paths.Executable,
                $remote_paths.Runner,
                $remote_paths.Output
            )

        Copy-Item `
            -LiteralPath $remote_paths.Output `
            -Destination $local_output `
            -FromSession $session `
            -Force
    }
    finally {
        if ($null -ne $session) {
            Remove-PSSession -Session $session
        }
    }

    if (-not (Test-Path -LiteralPath $local_output)) {
        throw "Windows behavior result was not produced: $local_output"
    }

    Write-Log "Windows behavior result: $local_output"
}
finally {
    Pop-Location
}
