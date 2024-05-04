# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# This script executes the provided test command, waits for <timeout in seconds>
# and then captures a dump of the test process if it is still running. The dump
# is captured using the procdump tool from Sysinternals. The dump is saved to
# the <output folder> with the name of the test executable and the current date
# and time.

# Modifying $args directly can cause issues, so copy it to a new variable.
$arguments = $args

# Check that the correct number of arguments have been provided.
if ($arguments.Count -eq 0) {
    Write-Output "Usage: Run-Test.ps1 <output folder> <timeout in seconds> <test command> <test arguments>"
    exit 1
}

# Extract the output folder and timeout from the arguments.
$OutputFolder = $arguments[0]
$arguments = $arguments[1..($arguments.Length - 1)]
$Timeout = [int]$arguments[0]
$arguments = $arguments[1..($arguments.Length - 1)]

# Start the test process using the provided command and arguments.
# This can't use Start-Process as that doesn't save exit code and always returns 0.
$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.UseShellExecute = $false
$processInfo.FileName = $arguments[0]
$processInfo.Arguments = $arguments[1..($arguments.Length - 1)] -join ' '

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processInfo
$process.Start() | Out-Null

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

Write-Output "Test $($process.ProcessName) exited with code $($process.ExitCode)"
exit $process.ExitCode
