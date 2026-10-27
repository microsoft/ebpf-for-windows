# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Starts, stops, or periodically collects eBPF tracing.
.DESCRIPTION
Accepts the original /option value syntax as well as -option value. Run with
-help for options. Requires elevation and bpftool.exe (beside this script or on PATH).
Stopping deletes the trace directory and its contents.
.EXAMPLE
.\ebpf_tracing.ps1 start -trace_path "$env:SystemRoot\Logs\eBPF"
.EXAMPLE
.\ebpf_tracing.ps1 periodic /trace_path "$env:SystemRoot\Logs\eBPF" /compress_rundown_state_files false
#>

$ErrorActionPreference = 'Stop'

function Show-TracingUsage {
    Write-Output @'
Usage: ebpf_tracing.ps1 <start|stop|periodic> -trace_path <path> [options]
Options accept either a '-' or '/' prefix.
  -trace_path path                         Required trace directory (created if missing).
  -trace_name name                         Trace session name (default: ebpf_diag).
  -rundown_period H:mm:ss                  ETL rollover period (default: 0:35:00).
  -max_file_size_mb size                   ETL and rundown size limit (default: 30).
  -max_committed_folder_size_mb size       Committed ETL size limit (default: 200).
  -max_committed_etl_files count           Committed ETL count limit (default: 128, minimum: 1).
  -max_committed_rundown_state_files count  Limit per rundown type (default: 1, minimum: 1).
  -compress_rundown_state_files true|false  Compress rundown files to CAB (default: true).
start configures and starts the WFP/eBPF logman session.
stop stops and deletes the session, then deletes the entire trace directory.
periodic collects WFP and BPF state, commits closed ETLs, and applies retention limits.
'@
}

function Invoke-TracingTool {
    param([string]$FilePath, [string[]]$ArgumentList, [switch]$AllowFailure)

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        $message = "$FilePath $ArgumentList failed with exit code $LASTEXITCODE."
        if ($AllowFailure) {
            Write-Warning $message
        } else {
            throw $message
        }
    }
}

function Save-RundownFile {
    param([string]$SourcePath, [string]$Name)

    $filePath = $SourcePath
    if ($options.compress_rundown_state_files -eq 'true') {
        $filePath = [System.IO.Path]::ChangeExtension($SourcePath, '.cab')
        Invoke-TracingTool makecab.exe @($SourcePath, $filePath)
    }

    $file = Get-Item -LiteralPath $filePath
    if ($file.Length -le $maxFileSizeBytes) {
        $destination = Join-Path $committedPath ("{0}_{1}{2}" -f $Name, $timestamp, $file.Extension)
        Move-Item -LiteralPath $filePath -Destination $destination -Force
    } else {
        Remove-Item -LiteralPath $filePath
    }
}

$command = $null
$options = @{
    trace_path = ''
    trace_name = 'ebpf_diag'
    rundown_period = '0:35:00'
    max_file_size_mb = '30'
    max_committed_folder_size_mb = '200'
    max_committed_etl_files = '128'
    max_committed_rundown_state_files = '1'
    compress_rundown_state_files = 'true'
}

for ($index = 0; $index -lt $args.Count; $index++) {
    $argument = [string]$args[$index]
    if ($argument -in @('-help', '/help', '-?', '/?')) {
        Show-TracingUsage
        return
    }
    if ($argument -in @('start', 'stop', 'periodic')) {
        $command = $argument.ToLowerInvariant()
        continue
    }
    $name = $argument -replace '^[-/]', ''
    if ($name -eq $argument -or -not $options.ContainsKey($name)) {
        throw "Unknown parameter: '$argument'. Run ebpf_tracing.ps1 -help for usage."
    }
    if (++$index -ge $args.Count -or [string]::IsNullOrWhiteSpace([string]$args[$index])) {
        throw "Missing value for '$argument'."
    }
    $options[$name] = [string]$args[$index]
}

if (-not $command -or [string]::IsNullOrWhiteSpace($options.trace_path)) {
    throw "A command and trace_path are required. Run ebpf_tracing.ps1 -help for usage."
}
foreach ($name in @('max_file_size_mb', 'max_committed_folder_size_mb',
        'max_committed_etl_files', 'max_committed_rundown_state_files')) {
    $value = 0
    if (-not [int]::TryParse($options[$name], [ref]$value) -or $value -lt 1) {
        throw "$name must be a positive integer."
    }
    $options[$name] = $value
}
if ($options.compress_rundown_state_files -notin @('true', 'false')) {
    throw "compress_rundown_state_files must be true or false."
}
if ([string]::IsNullOrWhiteSpace($options.trace_name)) {
    throw "trace_name must not be empty."
}
if ($options.rundown_period -notmatch '^\d+:[0-5]\d:[0-5]\d$') {
    throw "rundown_period must be expressed as H:mm:ss."
}

$tracePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($options.trace_path)
if ($tracePath.TrimEnd('\') -eq [System.IO.Path]::GetPathRoot($tracePath).TrimEnd('\')) {
    throw "trace_path must not be a filesystem root."
}
$traceName = $options.trace_name
$maxFileSizeBytes = [long]$options.max_file_size_mb * 1MB
if (-not (Test-Path -LiteralPath $tracePath)) {
    New-Item -ItemType Directory -Path $tracePath | Out-Null
}

switch ($command) {
    'start' {
        Invoke-TracingTool logman.exe @('create', 'trace', $traceName, '-o', (Join-Path $tracePath 'ebpf_trace'),
            '-f', 'bincirc', '-max', $options.max_file_size_mb, '-cnf', $options.rundown_period, '-v', 'mmddhhmm') `
            -AllowFailure # A previous boot may have already created the collector.
        Invoke-TracingTool logman.exe @('update', 'trace', $traceName, '-p',
            '{00e7ee66-5b24-5c41-22cb-af98f63e2f90}', '0x7', '0x4')
        foreach ($provider in @('{394f321c-5cf4-404c-aa34-4df1428a7f9c}', '{f2f2ca01-ad02-4a07-9e90-95a2334f3692}')) {
            Invoke-TracingTool logman.exe @('update', 'trace', $traceName, '-p', $provider, '0xffffffffffffffff', '0x4')
        }
        Invoke-TracingTool logman.exe @('start', $traceName)
    }
    'stop' {
        # An inactive collector can still be deleted.
        Invoke-TracingTool logman.exe @('stop', $traceName) -AllowFailure
        Invoke-TracingTool logman.exe @('delete', $traceName)
        Remove-Item -LiteralPath $tracePath -Recurse -Force
    }
    'periodic' {
        $committedPath = Join-Path $tracePath 'committed'
        if (-not (Test-Path -LiteralPath $committedPath)) {
            New-Item -ItemType Directory -Path $committedPath | Out-Null
        }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $bpftool = Join-Path $PSScriptRoot 'bpftool.exe'
        if (-not (Test-Path -LiteralPath $bpftool)) {
            $bpftool = 'bpftool.exe'
        }

        Push-Location -LiteralPath $tracePath
        try {
            Invoke-TracingTool netsh.exe @('wfp', 'show', 'state')
            Save-RundownFile (Join-Path $tracePath 'wfpstate.xml') 'wfpstate'

            $bpfStatePath = Join-Path $tracePath 'bpf_state.txt'
            foreach ($kind in @('prog', 'link', 'map')) {
                Add-Content -LiteralPath $bpfStatePath -Value "bpftool.exe -p $kind" -Encoding UTF8
                Invoke-TracingTool $bpftool @('-p', $kind) |
                    Add-Content -LiteralPath $bpfStatePath -Encoding UTF8
            }
            $maps = (Invoke-TracingTool $bpftool @('-j', 'map') | Out-String) | ConvertFrom-Json
            foreach ($map in $maps) {
                Add-Content -LiteralPath $bpfStatePath -Value "bpftool.exe map dump id $($map.id)" -Encoding UTF8
                # Not all map types support dumping their contents.
                Invoke-TracingTool $bpftool @('map', 'dump', 'id', $map.id) -AllowFailure |
                    Add-Content -LiteralPath $bpfStatePath -Encoding UTF8
            }
            Save-RundownFile $bpfStatePath 'bpfstate'
        } finally {
            Pop-Location
        }

        Get-ChildItem -LiteralPath $tracePath -Filter '*.etl' -File |
            Sort-Object Name -Descending | Select-Object -Skip 1 |
            Move-Item -Destination $committedPath -Force

        foreach ($pattern in @('wfpstate_*.*', 'bpfstate_*.*')) {
            Get-ChildItem -LiteralPath $committedPath -Filter $pattern -File |
                Sort-Object LastWriteTime -Descending |
                Select-Object -Skip $options.max_committed_rundown_state_files | Remove-Item -Force
        }

        $etlFiles = @(Get-ChildItem -LiteralPath $committedPath -Filter '*.etl' -File |
            Sort-Object LastWriteTime -Descending)
        # Preserve the batch script's exemption of the newest committed ETL from the size budget.
        $sizeKB = 0L
        $maxSizeKB = [long]$options.max_committed_folder_size_mb * 1024
        foreach ($file in ($etlFiles | Select-Object -Skip 1)) {
            $sizeKB += [long][Math]::Floor($file.Length / 1KB)
            if ($sizeKB -gt $maxSizeKB) {
                Remove-Item -LiteralPath $file.FullName -Force
            }
        }
        Get-ChildItem -LiteralPath $committedPath -Filter '*.etl' -File |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip $options.max_committed_etl_files | Remove-Item -Force
    }
}
