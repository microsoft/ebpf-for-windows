# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Verifies that every JIT/interpreter-only test case has a native program based equivalent.

.DESCRIPTION
    eBPF for Windows intends to withdraw support for JIT compiled programs. Before that can happen,
    every scenario that is currently validated only by a JIT (or interpreter) loaded program must
    also be validated by a native (bpf2c generated .sys/_um.dll) program.

    This script enumerates the Catch2 test cases exported by the test executables and reports any
    JIT/interpreter-only test case that has no native counterpart.

    Two detection strategies are used:

    1. Build differencing (preferred, requires -NativeOnlyBuildPath).
       Test cases that are present in a regular build but absent from a native-only build
       (NativeOnlyDebug/NativeOnlyRelease) are, by definition, compiled out by
       CONFIG_BPF_JIT_DISABLED / CONFIG_BPF_INTERPRETER_DISABLED, and therefore contribute no
       coverage once JIT is withdrawn. This catches JIT-only tests whose names give no hint that
       they are JIT-only (for example the netsh program management tests).

    2. Name matching (always applied).
       Test cases whose names carry a 'jit' or 'interpret' token, for example 'droppacket-jit' or
       'EBPF_EXECUTION_INTERPRET'.

    For each JIT-only test case the script derives the expected native counterpart name by
    substituting the execution mode token ('jit'/'interpret' -> 'native') and the program file
    extension ('.o' -> '.sys'), then checks whether that counterpart exists.

    Test cases that can never have a native equivalent (for example tests of the ELF verifier or of
    the raw byte code loading APIs, which have no bpf2c generated artifact by construction) must be
    listed in the allow list, each with a justification.

.PARAMETER JitBuildPath
    Path to the output directory of a regular build (JIT and interpreter enabled), for example
    'x64\Debug'.

.PARAMETER NativeOnlyBuildPath
    Path to the output directory of a native-only build, for example 'x64\NativeOnlyDebug'. When
    supplied, build differencing is used, which gives complete results. When omitted, only name
    matching is performed and the results are incomplete.

.PARAMETER AllowListPath
    Path to the allow list of test cases that cannot have a native equivalent.
    Defaults to 'jit_native_coverage_allowlist.json' next to this script.

.PARAMETER OutputPath
    Optional path to write a Markdown report to, for example the GitHub step summary.

.PARAMETER UpdateAllowList
    Rewrites the allow list so that it contains every currently uncovered test case. Newly added
    entries get a placeholder reason that must be replaced by a real justification, so the script
    still fails until a human documents each entry. Intended for maintainers only.

.EXAMPLE
    .\scripts\check_jit_native_test_coverage.ps1 -JitBuildPath x64\Debug -NativeOnlyBuildPath x64\NativeOnlyDebug

.EXAMPLE
    .\scripts\check_jit_native_test_coverage.ps1 -JitBuildPath x64\Debug -OutputPath $env:GITHUB_STEP_SUMMARY
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $JitBuildPath,
    [Parameter(Mandatory = $false)][string] $NativeOnlyBuildPath,
    [Parameter(Mandatory = $false)][string] $AllowListPath,
    [Parameter(Mandatory = $false)][string] $OutputPath,
    [Parameter(Mandatory = $false)][switch] $UpdateAllowList
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Catch2 based test executables that may contain JIT/native test variants. Executables that are not
# present in a given build (for example because that component was not built) are skipped.
$TestExecutables = @(
    'unit_tests.exe',
    'api_test.exe',
    'sample_ext_app.exe',
    'socket_tests.exe',
    'connect_redirect_tests.exe',
    'netebpfext_unit.exe',
    'bpf2c_tests.exe',
    'ebpf_stress_tests_um.exe',
    'ebpf_stress_tests_km.exe',
    'cilium_tests.exe',
    'bpftool_tests.exe'
)

# Matches a 'jit' or 'interpret' token delimited by start/end of string or by '-', '_' or ' '.
$ExecutionModeTokenRegex = '(?i)(?<=^|[-_ ])(jit|interpret)(?=$|[-_ ])'

# Matches a 'native' token delimited the same way. A test case that already declares itself native
# is never reported by name matching, which avoids false positives for test cases whose name merely
# happens to contain the word 'jit', such as the 'jit-bounce' conformance test.
$NativeTokenRegex = '(?i)(?<=^|[-_ ])native(?=$|[-_ ])'

$PlaceholderReason = 'TODO: document why a native equivalent is not possible.'
$TrackingIssue = 'https://github.com/microsoft/ebpf-for-windows/issues/5439'

if ([string]::IsNullOrWhiteSpace($AllowListPath)) {
    $AllowListPath = Join-Path -Path $PSScriptRoot -ChildPath 'jit_native_coverage_allowlist.json'
}

function Get-CatchTestCase {
    <#
    .SYNOPSIS
        Returns the Catch2 test cases exported by a test executable.
    #>
    param (
        [Parameter(Mandatory = $true)][string] $ExecutablePath
    )

    # The XML reporter is used rather than the default listing because Catch2 wraps long test names
    # across multiple lines in the plain text listing, which makes it impossible to parse reliably.
    $output = & $ExecutablePath --list-tests --reporter xml 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "'$ExecutablePath --list-tests' failed with exit code $LASTEXITCODE.`n$output"
    }

    # Some test executables emit a banner on standard output before Catch2 writes its report, so the
    # XML document has to be extracted rather than parsed from the start of the output.
    $start = $output.IndexOf('<?xml')
    if ($start -lt 0) {
        throw "'$ExecutablePath --list-tests' did not produce an XML report.`n$output"
    }

    $closingTag = '</MatchingTests>'
    $end = $output.LastIndexOf($closingTag)
    if ($end -ge 0) {
        $end += $closingTag.Length
    } else {
        # An executable with no matching test cases emits a self closing root element.
        $closingTag = '<MatchingTests/>'
        $end = $output.LastIndexOf($closingTag)
        if ($end -lt 0) {
            throw "'$ExecutablePath --list-tests' produced a malformed XML report.`n$output"
        }
        $end += $closingTag.Length
    }

    $document = [xml]$output.Substring($start, $end - $start)
    $testCases = @()
    foreach ($testCase in $document.MatchingTests.TestCase) {
        $file = ''
        $line = 0
        if ($testCase.SourceInfo) {
            $file = [string]$testCase.SourceInfo.File
            $line = [int]$testCase.SourceInfo.Line
        }
        $testCases += [PSCustomObject]@{
            Name = [string]$testCase.Name
            File = $file
            Line = $line
        }
    }

    return $testCases
}

function Get-NativeToken {
    <#
    .SYNOPSIS
        Returns the native execution mode token that replaces a 'jit'/'interpret' token, preserving
        the casing style of the token being replaced.
    #>
    param (
        [Parameter(Mandatory = $true)][string] $Token
    )

    if ($Token -ceq $Token.ToUpperInvariant()) {
        return 'NATIVE'
    }

    return 'native'
}

function Get-NativeCandidateName {
    <#
    .SYNOPSIS
        Returns the possible names of the native counterpart of a JIT/interpreter test case.
    .DESCRIPTION
        The execution mode token and the eBPF program file extension are substituted independently,
        because a native counterpart may differ from its JIT sibling in either or both.
    #>
    param (
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Name
    )

    $candidates = [System.Collections.Generic.HashSet[string]]::new()

    $modeVariants = @($Name)
    $matches = [regex]::Matches($Name, $ExecutionModeTokenRegex)
    if ($matches.Count -gt 0) {
        # Replace all execution mode tokens at once, and also each token individually. The latter
        # matters for names in which only some of the tokens denote the execution mode, for example
        # the conformance test 'jit-bounce_jit', whose native counterpart is 'jit-bounce_native'.
        $modeVariants += [regex]::Replace($Name, $ExecutionModeTokenRegex, { param($match) Get-NativeToken $match.Value })
        if ($matches.Count -gt 1) {
            foreach ($match in $matches) {
                $modeVariants += $Name.Remove($match.Index, $match.Length).Insert($match.Index, (Get-NativeToken $match.Value))
            }
        }
    }

    foreach ($modeVariant in $modeVariants) {
        [void]$candidates.Add($modeVariant)
        # ELF object files are only consumable by the JIT/interpreter; the native counterpart of a
        # test that loads '<name>.o' loads '<name>.sys' or '<name>_um.dll'.
        [void]$candidates.Add(($modeVariant -replace '\.o(?=$|["\s\-])', '.sys'))
        [void]$candidates.Add(($modeVariant -replace '\.o(?=$|["\s\-])', '_um.dll'))
    }

    # The original name is not a valid counterpart of itself.
    [void]$candidates.Remove($Name)

    return @($candidates)
}

function Read-AllowList {
    <#
    .SYNOPSIS
        Reads the allow list and returns its 'exclusions' and 'baseline' entries.
    #>
    param (
        [Parameter(Mandatory = $true)][string] $Path
    )

    $empty = [PSCustomObject]@{ Exclusions = @(); Baseline = @() }

    if (-not (Test-Path -Path $Path)) {
        Write-Warning "Allow list '$Path' does not exist; treating it as empty."
        return $empty
    }

    $content = Get-Content -Path $Path -Raw
    if ([string]::IsNullOrWhiteSpace($content)) {
        return $empty
    }

    $parsed = $content | ConvertFrom-Json
    $propertyNames = @($parsed.PSObject.Properties.Name)
    if ($propertyNames -notcontains 'exclusions' -or $propertyNames -notcontains 'baseline') {
        throw "Allow list '$Path' must contain both an 'exclusions' and a 'baseline' array."
    }

    return [PSCustomObject]@{
        Exclusions = @($parsed.exclusions)
        Baseline   = @($parsed.baseline)
    }
}

function Write-AllowList {
    param (
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $Exclusions,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $Baseline
    )

    $document = [ordered]@{
        '_comment'   = @(
            'Copyright (c) eBPF for Windows contributors',
            'SPDX-License-Identifier: MIT',
            '',
            'Tracks JIT/interpreter-only test cases that have no native (bpf2c generated) equivalent.',
            'Maintained by scripts/check_jit_native_test_coverage.ps1. See GitHub issue 5439.',
            '',
            'exclusions: test cases that can never have a native equivalent, for example tests of the',
            '  ELF verifier or of the raw byte code loading APIs, which have no native artifact by',
            '  construction. Every entry must carry a reason. These entries are permanent.',
            '',
            'baseline: test cases that should have a native equivalent but do not have one yet. These',
            '  entries are a backlog: each must be removed as its native equivalent is added, and no',
            '  new entry may be added. The check fails on any gap that is in neither array, which',
            '  prevents the JIT-only surface from growing.'
        )
        'exclusions' = @($Exclusions | Sort-Object -Property Executable, Test)
        'baseline'   = @($Baseline | Sort-Object -Property Executable, Test)
    }

    $json = $document | ConvertTo-Json -Depth 6
    Set-Content -Path $Path -Value $json -Encoding utf8NoBOM
}

function Resolve-TestExecutable {
    param (
        [Parameter(Mandatory = $true)][string] $BuildPath,
        [Parameter(Mandatory = $true)][string] $Executable
    )

    $path = Join-Path -Path $BuildPath -ChildPath $Executable
    if (Test-Path -Path $path -PathType Leaf) {
        return $path
    }

    return $null
}

# ------------------------------------------------------------------------------------------------
# Collect the test cases.
# ------------------------------------------------------------------------------------------------

if (-not (Test-Path -Path $JitBuildPath -PathType Container)) {
    throw "JitBuildPath '$JitBuildPath' does not exist."
}

$useBuildDifferencing = -not [string]::IsNullOrWhiteSpace($NativeOnlyBuildPath)
if ($useBuildDifferencing -and -not (Test-Path -Path $NativeOnlyBuildPath -PathType Container)) {
    throw "NativeOnlyBuildPath '$NativeOnlyBuildPath' does not exist."
}

if (-not $useBuildDifferencing) {
    Write-Warning (
        'NativeOnlyBuildPath was not supplied. Only name based detection will be performed, so ' +
        'JIT-only tests whose names do not contain a jit/interpret token will not be detected.')
}

Write-Host "JIT build path         : $JitBuildPath"
Write-Host "Native-only build path : $(if ($useBuildDifferencing) { $NativeOnlyBuildPath } else { '<not supplied>' })"
Write-Host "Allow list             : $AllowListPath"
Write-Host ''

$allowList = Read-AllowList -Path $AllowListPath
$analyzedExecutables = @()
$gaps = @()
$knownExclusions = @()
$knownBaseline = @()
$placeholderExclusions = @()
$coveredCount = 0

foreach ($executable in $TestExecutables) {
    $jitExecutablePath = Resolve-TestExecutable -BuildPath $JitBuildPath -Executable $executable
    if ($null -eq $jitExecutablePath) {
        Write-Host "Skipping $executable (not present in $JitBuildPath)."
        continue
    }

    $nativeOnlyExecutablePath = $null
    if ($useBuildDifferencing) {
        $nativeOnlyExecutablePath = Resolve-TestExecutable -BuildPath $NativeOnlyBuildPath -Executable $executable
        if ($null -eq $nativeOnlyExecutablePath) {
            Write-Warning "Skipping $executable (present in $JitBuildPath but not in $NativeOnlyBuildPath)."
            continue
        }
    }

    $jitTestCases = @(Get-CatchTestCase -ExecutablePath $jitExecutablePath)
    $jitTestNames = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($jitTestCases | ForEach-Object { $_.Name }), [System.StringComparer]::Ordinal)

    # The set of test names that survive once JIT and the interpreter are gone. This is the set that
    # a native counterpart must be found in.
    if ($useBuildDifferencing) {
        $nativeTestNames = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@((Get-CatchTestCase -ExecutablePath $nativeOnlyExecutablePath) | ForEach-Object { $_.Name }),
            [System.StringComparer]::Ordinal)
    } else {
        $nativeTestNames = $jitTestNames
    }

    # Identify the JIT/interpreter-only test cases.
    $jitOnlyTestCases = @($jitTestCases | Where-Object {
        ($useBuildDifferencing -and -not $nativeTestNames.Contains($_.Name)) -or
        (($_.Name -match $ExecutionModeTokenRegex) -and ($_.Name -notmatch $NativeTokenRegex))
    })

    $analyzedExecutables += [PSCustomObject]@{
        Executable = $executable
        Total      = $jitTestCases.Count
        JitOnly    = $jitOnlyTestCases.Count
    }

    Write-Host ("Analyzing {0,-28} {1,4} test cases, {2,4} JIT/interpreter-only." -f `
        $executable, $jitTestCases.Count, $jitOnlyTestCases.Count)

    foreach ($testCase in $jitOnlyTestCases) {
        $candidates = @(Get-NativeCandidateName -Name $testCase.Name)
        $matched = @($candidates | Where-Object { $nativeTestNames.Contains($_) })
        if ($matched.Count -gt 0) {
            $coveredCount++
            continue
        }

        $exclusion = $allowList.Exclusions | Where-Object { $_.Executable -eq $executable -and $_.Test -eq $testCase.Name } | Select-Object -First 1
        if ($null -ne $exclusion) {
            $knownExclusions += $exclusion
            if ([string]::IsNullOrWhiteSpace($exclusion.Reason) -or $exclusion.Reason -eq $PlaceholderReason) {
                $placeholderExclusions += $exclusion
            }
            continue
        }

        $baseline = $allowList.Baseline | Where-Object { $_.Executable -eq $executable -and $_.Test -eq $testCase.Name } | Select-Object -First 1
        if ($null -ne $baseline) {
            $knownBaseline += $baseline
            continue
        }

        $expected = @(Get-NativeCandidateName -Name $testCase.Name | Sort-Object)
        $gaps += [PSCustomObject]@{
            Executable = $executable
            Test       = $testCase.Name
            File       = $testCase.File
            Line       = $testCase.Line
            Expected   = if ($expected.Count -gt 0) { $expected -join ', ' } else { '(add a native variant of this test case)' }
        }
    }
}

if ($analyzedExecutables.Count -eq 0) {
    throw "No test executables were found in '$JitBuildPath'. Was the solution built?"
}

# Allow list entries that no longer correspond to an uncovered test case are stale and must be
# removed, otherwise the allow list silently grows and stops reflecting reality. In particular, a
# stale baseline entry means the native equivalent has been added and the backlog entry is now done.
$analyzedExecutableNames = @($analyzedExecutables | ForEach-Object { $_.Executable })

function Get-StaleEntry {
    param (
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $Declared,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $Observed
    )

    return @($Declared | Where-Object {
        $entry = $_
        $analyzedExecutableNames -contains $entry.Executable -and
        -not ($Observed | Where-Object { $_.Executable -eq $entry.Executable -and $_.Test -eq $entry.Test })
    })
}

$staleExclusions = @(Get-StaleEntry -Declared $allowList.Exclusions -Observed $knownExclusions)
$staleBaseline = @(Get-StaleEntry -Declared $allowList.Baseline -Observed $knownBaseline)

if ($UpdateAllowList) {
    $updatedBaseline = @($knownBaseline)
    foreach ($gap in $gaps) {
        $updatedBaseline += [PSCustomObject]@{
            Executable = $gap.Executable
            Test       = $gap.Test
            Issue      = $TrackingIssue
        }
    }
    Write-AllowList -Path $AllowListPath -Exclusions @($knownExclusions) -Baseline $updatedBaseline
    Write-Host ''
    Write-Host "Updated '$AllowListPath': added $($gaps.Count) entry/entries to the baseline, dropped $($staleExclusions.Count + $staleBaseline.Count) stale entry/entries."
    Write-Host 'Move any entry that can never have a native equivalent into "exclusions" and give it a reason.'
    exit 0
}

# ------------------------------------------------------------------------------------------------
# Report.
# ------------------------------------------------------------------------------------------------

$report = [System.Text.StringBuilder]::new()
[void]$report.AppendLine('# JIT vs native test coverage')
[void]$report.AppendLine()
if ($useBuildDifferencing) {
    [void]$report.AppendLine("Comparing ``$JitBuildPath`` against ``$NativeOnlyBuildPath``.")
} else {
    [void]$report.AppendLine("Name based detection only (no native-only build supplied); results are incomplete.")
}
[void]$report.AppendLine()
[void]$report.AppendLine('| Test executable | Test cases | JIT/interpreter-only |')
[void]$report.AppendLine('| --- | ---: | ---: |')
foreach ($entry in $analyzedExecutables) {
    [void]$report.AppendLine("| $($entry.Executable) | $($entry.Total) | $($entry.JitOnly) |")
}
[void]$report.AppendLine()
[void]$report.AppendLine("Covered by a native equivalent: **$coveredCount**")
[void]$report.AppendLine()
[void]$report.AppendLine("Permanently excluded (no native equivalent possible): **$($knownExclusions.Count)**")
[void]$report.AppendLine()
[void]$report.AppendLine("Remaining backlog tracked in the baseline: **$($knownBaseline.Count)**")
[void]$report.AppendLine()

if ($knownBaseline.Count -gt 0) {
    [void]$report.AppendLine("## Backlog: native equivalents still to be written ($($knownBaseline.Count))")
    [void]$report.AppendLine()
    foreach ($entry in ($knownBaseline | Sort-Object -Property Executable, Test)) {
        [void]$report.AppendLine("- ``$($entry.Executable)`` / ``$($entry.Test)``")
    }
    [void]$report.AppendLine()
}

if ($gaps.Count -gt 0) {
    [void]$report.AppendLine("## New missing native equivalents ($($gaps.Count))")
    [void]$report.AppendLine()
    [void]$report.AppendLine('| Test executable | Test case | Source | Expected native test case |')
    [void]$report.AppendLine('| --- | --- | --- | --- |')
    foreach ($gap in $gaps) {
        $source = if ([string]::IsNullOrWhiteSpace($gap.File)) { '' } else { "$(Split-Path -Leaf $gap.File):$($gap.Line)" }
        [void]$report.AppendLine("| $($gap.Executable) | ``$($gap.Test)`` | $source | ``$($gap.Expected)`` |")
    }
    [void]$report.AppendLine()
}

if ($staleExclusions.Count -gt 0 -or $staleBaseline.Count -gt 0) {
    $stale = @($staleExclusions) + @($staleBaseline)
    [void]$report.AppendLine("## Stale allow list entries ($($stale.Count))")
    [void]$report.AppendLine()
    foreach ($entry in $stale) {
        [void]$report.AppendLine("- ``$($entry.Executable)`` / ``$($entry.Test)``")
    }
    [void]$report.AppendLine()
}

$reportText = $report.ToString()
Write-Host ''
Write-Host $reportText

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Add-Content -Path $OutputPath -Value $reportText
}

# ------------------------------------------------------------------------------------------------
# Verdict.
# ------------------------------------------------------------------------------------------------

$failed = $false

if ($gaps.Count -gt 0) {
    Write-Host "FAILED: $($gaps.Count) JIT/interpreter-only test case(s) have no native equivalent." -ForegroundColor Red
    Write-Host 'Add a native variant of each test case listed above.' -ForegroundColor Red
    Write-Host 'If a native equivalent is impossible, add the test case to "exclusions" with a reason.' -ForegroundColor Red
    $failed = $true
}

if ($placeholderExclusions.Count -gt 0) {
    Write-Host "FAILED: $($placeholderExclusions.Count) exclusion(s) still have a placeholder reason." -ForegroundColor Red
    foreach ($placeholder in $placeholderExclusions) {
        Write-Host "  $($placeholder.Executable) / $($placeholder.Test)" -ForegroundColor Red
    }
    $failed = $true
}

$staleEntries = @($staleExclusions) + @($staleBaseline)
if ($staleEntries.Count -gt 0) {
    Write-Host "FAILED: $($staleEntries.Count) allow list entry/entries are stale and must be removed." -ForegroundColor Red
    Write-Host 'A stale baseline entry means the native equivalent now exists, so remove the entry.' -ForegroundColor Red
    foreach ($stale in $staleEntries) {
        Write-Host "  $($stale.Executable) / $($stale.Test)" -ForegroundColor Red
    }
    $failed = $true
}

if ($failed) {
    exit 1
}

Write-Host "PASSED: no new JIT-only test cases. Backlog remaining: $($knownBaseline.Count)." -ForegroundColor Green
exit 0
