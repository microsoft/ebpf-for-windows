# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$Reference
)

$ErrorActionPreference = 'Stop'

$Executable = (Resolve-Path -LiteralPath $Executable).Path
$Output = [System.IO.Path]::GetFullPath($Output)

$Cases = @(
    & $Executable --list
)

$ListExit = $LASTEXITCODE

if ($ListExit -ne 0) {
    throw "--list failed with exit code $ListExit"
}

if ($Cases.Count -eq 0) {
    throw 'No behavior test cases were discovered'
}

if (
    @(
        $Cases |
            Sort-Object -Unique
    ).Count -ne $Cases.Count
) {
    throw 'Behavior test names are not unique'
}

$Lines = New-Object 'System.Collections.Generic.List[string]'

foreach ($Case in $Cases) {
    $Stderr = Join-Path `
        $env:TEMP `
        "bpf-api-$($Case.Replace('.', '-')).stderr.log"

    Remove-Item `
        -LiteralPath $Stderr `
        -Force `
        -ErrorAction SilentlyContinue

    $CaseOutput = @(
        & $Executable $Case 2> $Stderr
    )

    $CaseExit = $LASTEXITCODE

    if ($CaseExit -ne 0) {
        $ErrorText = Get-Content `
            -LiteralPath $Stderr `
            -Raw `
            -ErrorAction SilentlyContinue

        throw "$Case failed with exit code ${CaseExit}: $ErrorText"
    }

    $ErrorText = Get-Content `
        -LiteralPath $Stderr `
        -Raw `
        -ErrorAction SilentlyContinue

    if ($null -ne $ErrorText -and $ErrorText.Length -gt 0) {
        throw "$Case wrote to stderr: $ErrorText"
    }

    if ($CaseOutput.Count -ne 1) {
        throw "$Case produced $($CaseOutput.Count) output lines"
    }

    $Line = [string]$CaseOutput[0]
    $Pattern = "^$([regex]::Escape($Case))`t-?\d+`t\d+$"

    if ($Line -notmatch $Pattern) {
        throw "Unexpected output for ${Case}: $Line"
    }

    $Lines.Add($Line)
}

$OutputDirectory = Split-Path -Parent $Output

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item `
        -ItemType Directory `
        -Path $OutputDirectory |
        Out-Null
}

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

[System.IO.File]::WriteAllText(
    $Output,
    ($Lines -join "`n") + "`n",
    $Utf8NoBom
)

Write-Host "Wrote $($Lines.Count) results to $Output"

if ($Reference) {
    $Reference = (Resolve-Path -LiteralPath $Reference).Path
    $ReferenceBytes = [System.IO.File]::ReadAllBytes($Reference)
    $OutputBytes = [System.IO.File]::ReadAllBytes($Output)

    if (
        $ReferenceBytes.Length -ne $OutputBytes.Length -or
        -not [System.Linq.Enumerable]::SequenceEqual(
            [byte[]]$ReferenceBytes,
            [byte[]]$OutputBytes
        )
    ) {
        Write-Host '=== DIFFERENCE ==='

        Compare-Object `
            (Get-Content -LiteralPath $Reference) `
            (Get-Content -LiteralPath $Output) |
            Out-Host

        throw 'Windows behavior differs from the Linux reference'
    }

    Write-Host 'Windows behavior matches the Linux reference'
}
