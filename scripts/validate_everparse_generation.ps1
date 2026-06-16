# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [string] $RepositoryRoot = ".",
    [string] $ManifestPath = "scripts\everparse_generation.json",
    [string] $Configuration = "Release",
    [string] $Platform = "x64"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Git
{
    param([string[]] $Arguments)

    $output = & git -C $RepositoryRoot @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed: $output"
    }
    return $output
}

function Invoke-BuildTool
{
    param(
        [string] $FilePath,
        [string[]] $Arguments
    )

    Write-Host ">> $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Normalize-RepoPath
{
    param([string] $Path)
    $normalized_path = $Path -replace "\\", "/"
    while ($normalized_path.StartsWith("./")) {
        $normalized_path = $normalized_path.Substring(2)
    }
    return $normalized_path
}

function Write-JsonFile
{
    param(
        [string] $Path,
        [object] $Value,
        [int] $Depth
    )

    $Value | ConvertTo-Json -Depth $Depth | Set-Content -Path $Path -Encoding utf8
}

function Get-AllTriggerPaths
{
    param($Manifest)

    $all_paths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($unit in $Manifest.generation_units) {
        foreach ($path in $unit.trigger_paths) {
            [void]$all_paths.Add((Normalize-RepoPath $path))
        }
    }
    return @($all_paths)
}

function Get-ChangedFiles
{
    param($Manifest)

    $event_name = $env:GITHUB_EVENT_NAME
    if (-not $event_name) {
        return Get-AllTriggerPaths -Manifest $Manifest
    }

    $event = $null
    if ($env:GITHUB_EVENT_PATH -and (Test-Path $env:GITHUB_EVENT_PATH)) {
        $event = Get-Content -Path $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
    }

    switch ($event_name) {
        "pull_request" {
            $base_ref = $event.pull_request.base.ref
            Invoke-Git @("fetch", "--no-tags", "origin", "${base_ref}:refs/remotes/origin/$base_ref") | Out-Null
            $merge_base = (Invoke-Git @("merge-base", "HEAD", "refs/remotes/origin/$base_ref")).Trim()
            return @(Invoke-Git @("diff", "--name-only", $merge_base, "HEAD") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        "push" {
            $before = [string]$event.before
            if ([string]::IsNullOrWhiteSpace($before) -or $before -eq ("0" * 40)) {
                return Get-AllTriggerPaths -Manifest $Manifest
            }
            return @(Invoke-Git @("diff", "--name-only", $before, "HEAD") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        "merge_group" {
            $base_sha = [string]$event.merge_group.base_sha
            if ([string]::IsNullOrWhiteSpace($base_sha)) {
                return Get-AllTriggerPaths -Manifest $Manifest
            }
            return @(Invoke-Git @("diff", "--name-only", $base_sha, "HEAD") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        default {
            return Get-AllTriggerPaths -Manifest $Manifest
        }
    }
}

function Set-ActionOutput
{
    param(
        [string] $Name,
        [string] $Value
    )

    if ($env:GITHUB_OUTPUT) {
        "$Name=$Value" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
    }
}

$repository_root = (Resolve-Path $RepositoryRoot).Path
$manifest_full_path = Join-Path $repository_root $ManifestPath
$manifest = Get-Content -Path $manifest_full_path -Raw | ConvertFrom-Json
$report_root = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } elseif ($env:TEMP) { $env:TEMP } else { $repository_root }
$report_path = Join-Path $report_root "everparse-validation-report.json"

$changed_files = @(Get-ChangedFiles -Manifest $manifest | ForEach-Object { Normalize-RepoPath $_ })
$changed_file_set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($path in $changed_files) {
    [void]$changed_file_set.Add($path)
}

$selected_units = @()
foreach ($unit in $manifest.generation_units) {
    $matched_paths = @($unit.trigger_paths | ForEach-Object { Normalize-RepoPath $_ } | Where-Object { $changed_file_set.Contains($_) })
    if ($matched_paths.Count -gt 0) {
        $selected_units += [pscustomobject]@{
            id = $unit.id
            project = $unit.project
            generated_outputs = @($unit.generated_outputs | ForEach-Object { Normalize-RepoPath $_ })
            matched_paths = $matched_paths
        }
    }
}

$report = [ordered]@{
    changed_files = $changed_files
    selected_units = @()
}

if ($selected_units.Count -eq 0) {
    $report.validation_status = "skipped"
    Write-JsonFile -Path $report_path -Value $report -Depth 6
    Set-ActionOutput -Name "validation_status" -Value "skipped"
    Set-ActionOutput -Name "selected_units" -Value "[]"
    Set-ActionOutput -Name "report_path" -Value $report_path
    if ($env:GITHUB_STEP_SUMMARY) {
        "EverParse validation skipped: no generation units were affected." | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
    }
    exit 0
}

$nuget_path = Get-Command nuget -ErrorAction Stop | Select-Object -ExpandProperty Source
$msbuild_path = Get-Command msbuild -ErrorAction Stop | Select-Object -ExpandProperty Source
$solution_dir = $repository_root
if (-not $solution_dir.EndsWith("\")) {
    $solution_dir += "\"
}

Push-Location $repository_root
try {
    Invoke-BuildTool -FilePath $nuget_path -Arguments @("restore", "ebpf-for-windows.sln")

    $diverged_units = @()
    $infrastructure_error_units = @()

    foreach ($unit in $selected_units) {
        $unit_result = [ordered]@{
            id = $unit.id
            project = $unit.project
            matched_paths = $unit.matched_paths
            generated_outputs = $unit.generated_outputs
            changed_outputs = @()
            missing_outputs = @()
            status = "pass"
        }

        try {
            Invoke-BuildTool -FilePath $msbuild_path -Arguments @(
                "/m",
                "/p:Configuration=$Configuration",
                "/p:Platform=$Platform",
                "/p:HostPlatform=$Platform",
                "/p:SolutionDir=$solution_dir",
                $unit.project
            )

            foreach ($output in $unit.generated_outputs) {
                if (-not (Test-Path (Join-Path $repository_root $output))) {
                    $unit_result.missing_outputs += $output
                }
            }

            if ($unit_result.missing_outputs.Count -gt 0) {
                $unit_result.status = "infrastructure_error"
            } else {
                $status_lines = @(Invoke-Git (@("status", "--porcelain", "--") + $unit.generated_outputs))
                $changed_outputs = @()
                foreach ($line in $status_lines) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        $changed_outputs += ($line.Substring(3).Trim() -replace "\\", "/")
                    }
                }

                if ($changed_outputs.Count -gt 0) {
                    $unit_result.status = "diverged"
                    $unit_result.changed_outputs = $changed_outputs
                }
            }
        } catch {
            $unit_result.status = "infrastructure_error"
            $unit_result.error = $_.Exception.Message
        }

        if ($unit_result.status -eq "diverged") {
            $diverged_units += $unit_result
        } elseif ($unit_result.status -eq "infrastructure_error") {
            $infrastructure_error_units += $unit_result
        }

        $report.selected_units += $unit_result
    }

    if ($diverged_units.Count -gt 0) {
        $report.validation_status = "diverged"
    } elseif ($infrastructure_error_units.Count -gt 0) {
        $report.validation_status = "infrastructure_error"
    } else {
        $report.validation_status = "pass"
    }

    Write-JsonFile -Path $report_path -Value $report -Depth 8

    Set-ActionOutput -Name "validation_status" -Value $report.validation_status
    Set-ActionOutput -Name "selected_units" -Value (($selected_units | ForEach-Object { $_.id } | ConvertTo-Json -Compress))
    Set-ActionOutput -Name "diverged_units" -Value (($diverged_units | ConvertTo-Json -Depth 8 -Compress))
    Set-ActionOutput -Name "report_path" -Value $report_path

    if ($env:GITHUB_STEP_SUMMARY) {
        "## EverParse validation" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
        "" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
        "- Status: $($report.validation_status)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
        "- Selected units: $((@($selected_units | ForEach-Object { $_.id }) -join ', '))" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
        foreach ($unit in $report.selected_units) {
            "- $($unit.id): $($unit.status)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
        }
    }
} finally {
    Pop-Location
}
