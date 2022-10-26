# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ($TestProgram, $StackDepth)

# Gather list of all possible tests
$tests = & $TestProgram "--list-tests" "--verbosity=quiet"

$env:EBPF_LOW_MEMORY_SIMULATION = $StackDepth
$env:EBPF_ENABLE_WER_REPORT = "yes"

Set-Content -Path ($TestProgram +".passed.log") ""

# Rerun failing tests until they pass
while ($true) {
    $previous_passed_tests = $passed_tests
    $passed_tests = Get-Content -Path ($TestProgram +".passed.log")

    # Print list of tests that have passed in the previous iteration.
    $passed_tests | Where-Object { $_ -notin $previous_passed_tests } | ForEach-Object { Write-Host "Passed: $_" }

    # Compute list of tests that haven't passed yet
    $remaining_tests = $tests | Where-Object { $_ -notin $passed_tests }

    if ($remaining_tests.Count -eq 0) {
        break
    }
    Set-Content -Path "remaining_tests.txt" -Value $remaining_tests
    $log =(& $TestProgram "-d yes" "--verbosity=quiet" "-f remaining_tests.txt" 2>&1)
    if ($LASTEXITCODE -eq 0) {
        write-host "All tests passed"
        break
    }
}

Write-Host "All tests passed"
