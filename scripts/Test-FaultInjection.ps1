# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
# This script is used as part of the systematic testing of the
# failure handling.
# First it will create a list of all the tests in the test binary.
# Second it will execute each test in the test binary.
# Third it will check the output of each test to see if it passed or failed.
# Fourth re-run the failed tests.
# Fifth it will check if all tests passed and exit.
#

param ($OutputFolder, $Timeout, $TestProgram, $StackDepth)

# Gather list of all possible tests
$tests = & $TestProgram "--list-tests" "--verbosity=quiet"

$env:EBPF_FAULT_INJECTION_SIMULATION = $StackDepth
$env:EBPF_ENABLE_WER_REPORT = "yes"

Set-Content -Path ($TestProgram + ".passed.log") ""
Set-Content -Path ($TestProgram + ".fault.log") ""

$iteration = 0


# Rerun failing tests until they pass
while ($true) {
    $previous_passed_tests = $passed_tests
    $passed_tests = Get-Content -Path ($TestProgram + ".passed.log")

    # Get the list of tests that have passed in the previous iteration.
    $passed_tests | Where-Object { $_ -notin $previous_passed_tests } | ForEach-Object { Write-Host "Passed: $_" }

    # Compute list of tests that haven't passed yet
    $remaining_tests = $tests | Where-Object { $_ -notin $passed_tests }

    # If all the tests have passed, exit.
    if ($remaining_tests.Count -eq 0) {
        Write-Host "Zero remaining tests"
        break
    }

    # Write the list of tests that haven't passed yet to a file.
    Set-Content -Path "remaining_tests.txt" -Value $remaining_tests

    $iteration ++
    write-host "Running iteration #" $iteration
    $remaining_tests | ForEach-Object { write-host "Running: $_" }

    # Run the test binary with any remaining tests.
    $process = Start-Process -NoNewWindow -FilePath $TestProgram -ArgumentList "-d yes", "--verbosity=quiet", "-f remaining_tests.txt" -PassThru
    if (!$process.WaitForExit($Timeout * 1000)) {
        $dumpFileName = "$($process.ProcessName)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').dmp"
        $dumpFilePath = Join-Path $OutputFolder $dumpFileName
        Write-Output "Capturing dump of $($process.ProcessName) to $dumpFilePath"
        Start-Process -NoNewWindow -Wait -FilePath procdump -ArgumentList "-accepteula -ma $($process.Id) $dumpFilePath"
        if (!$process.HasExited) {
            Write-Output "Killing $($process.ProcessName)"
            $process.Kill()
        }
    }
}

Write-Host "All tests passed"
