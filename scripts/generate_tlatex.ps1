# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $false)]
    [string]$Tla2ToolsJar = "tla2tools.jar"
)

$ErrorActionPreference = 'Stop'

function Invoke-TlaTex {
    param(
        [Parameter(Mandatory = $true)][string]$JarPath,
        [Parameter(Mandatory = $true)][string]$SpecPath,
        [Parameter(Mandatory = $true)][string]$OutDir
    )

    $specRoot = [System.IO.Path]::GetFileNameWithoutExtension($SpecPath)
    $logPath = Join-Path $OutDir ($specRoot + '.tlatex.log')

    $javaArgs = @(
        '-cp', $JarPath,
        'tla2tex.TLA',
        '-metadir', $OutDir,
        $SpecPath
    )

    try {
        & java @javaArgs *> $logPath
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = 1
    }

    $texPath = Join-Path $OutDir ($specRoot + '.tex')
    if (-not (Test-Path $texPath)) {
        Write-Error "TLATeX did not produce $texPath"
    }

    # TLATeX may emit trailing whitespace which trips pre-commit hooks.
    # Strip it deterministically.
    $lines = [System.IO.File]::ReadAllLines($texPath)
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $lines[$i] = $lines[$i] -replace "[ \t]+$", ""
    }
    [System.IO.File]::WriteAllLines($texPath, $lines)

    if ($exitCode -ne 0) {
        $log = Get-Content -Raw -ErrorAction SilentlyContinue $logPath
        Write-Error "TLATeX failed for $SpecPath`n$log"
    }

    Remove-Item -Force (Join-Path $OutDir ($specRoot + '.aux')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $OutDir ($specRoot + '.log')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $OutDir ($specRoot + '.dvi')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $OutDir ($specRoot + '.ps')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $OutDir ($specRoot + '.pdf')) -ErrorAction SilentlyContinue
    Remove-Item -Force $logPath -ErrorAction SilentlyContinue

    # TLATeX may also copy LaTeX build artifacts next to the input module.
    $specDir = Split-Path -Parent $SpecPath
    Remove-Item -Force (Join-Path $specDir ($specRoot + '.aux')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $specDir ($specRoot + '.log')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $specDir ($specRoot + '.dvi')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $specDir ($specRoot + '.ps')) -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $specDir ($specRoot + '.pdf')) -ErrorAction SilentlyContinue
}

if (-not (Test-Path $Tla2ToolsJar)) {
    throw "tla2tools.jar not found at: $Tla2ToolsJar`nDownload it (CI does) or pass -Tla2ToolsJar <path>."
}

$tlaFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\models') -Filter *.tla -Recurse |
    Where-Object { $_.FullName -notmatch '\\tlatex\\' }

foreach ($tla in $tlaFiles) {
    $modelDir = Split-Path -Parent $tla.FullName
    $outDir = Join-Path $modelDir 'tlatex'
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    Write-Host "Generating TLATeX for $($tla.FullName) -> $outDir"
    Invoke-TlaTex -JarPath $Tla2ToolsJar -SpecPath $tla.FullName -OutDir $outDir
}
