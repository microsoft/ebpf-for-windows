# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# This script executes the provided test command, waits for <timeout in seconds>
# and then captures a dump of the test process if it is still running. The dump
# is captured using the procdump tool from Sysinternals. The dump is saved to
# the <output folder> with the name of the test executable and the current date
# and time.

if ($args.Count -eq 0) {
    Write-Output "Usage: Run-Test.ps1 <output folder> <timeout in seconds> <test command> <test arguments>"
    exit 1
}

$OutputFolder = $args[0]
$args = $args[1..($args.Length - 1)]
$Timeout = [int]$args[0]
$args = $args[1..($args.Length - 1)]

$process = Start-Process -PassThru -NoNewWindow -FilePath $args[0] -ArgumentList $args[1..($args.Length - 1)]

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

exit $process.ExitCode