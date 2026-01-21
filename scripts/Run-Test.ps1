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
if ($arguments.Count -lt 3) {
    Write-Output "Usage: Run-Test.ps1 <output folder> <timeout in seconds> <test command> [<test arguments>]"
    exit 1
}

# Extract the output folder and timeout from the arguments.
$OutputFolder = $arguments[0]
$arguments = $arguments[1..($arguments.Length - 1)]
$Timeout = [int]$arguments[0]
$arguments = $arguments[1..($arguments.Length - 1)]

# Start the test process using the provided command and arguments.
# This can't use Start-Process as that doesn't save exit code and always returns 0.
$null = New-Item -Path $OutputFolder -ItemType Directory -Force -ErrorAction SilentlyContinue

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.UseShellExecute = $false
$processInfo.FileName = $arguments[0]
$processInfo.Arguments = ""
if ($arguments.Length -gt 1) {
    $processInfo.Arguments = $arguments[1..($arguments.Length - 1)] -join ' '
}

$test_executable_name = [System.IO.Path]::GetFileNameWithoutExtension($processInfo.FileName)

Write-Output "Running test: $($processInfo.FileName) $($processInfo.Arguments)"
Write-Output "Dump output folder: $OutputFolder"

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processInfo
$process.Start() | Out-Null

# If ProcDump is available (installed by CI when dump collection is enabled), start it as a background
# monitor so crashes that don't produce WER dumps still generate a dump file.
$procdump_process = $null
$procdump_command = Get-Command procdump.exe -ErrorAction SilentlyContinue
if ($null -eq $procdump_command) {
    $procdump_command = Get-Command procdump -ErrorAction SilentlyContinue
}

$enable_procdump_monitor = ($null -ne $procdump_command) -and (($env:EBPF_TEST_USE_PROCDUMP -eq 'yes') -or ($env:CI -eq 'true'))
if ($enable_procdump_monitor) {
    $procdump_args = @('-accepteula', '-ma')
    if ($env:EBPF_TEST_PROCDUMP_FIRST_CHANCE -eq 'yes') {
        $procdump_args += @('-e', '1')
    } else {
        $procdump_args += @('-e')
    }
    $procdump_args += @('-x', $OutputFolder, $process.Id)
    Write-Output "Starting ProcDump monitor: $($procdump_command.Source) $($procdump_args -join ' ')"
    try {
        $procdump_process = Start-Process -NoNewWindow -PassThru -FilePath $procdump_command.Source -ArgumentList $procdump_args
    } catch {
        Write-Output "Failed to start ProcDump monitor: $($_.Exception.Message)"
    }
}

if (!$process.WaitForExit($Timeout * 1000)) {
    $dumpFileName = "$test_executable_name\_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').dmp"
    $dumpFilePath = Join-Path $OutputFolder $dumpFileName
    Write-Output "Capturing dump of $test_executable_name to $dumpFilePath"
    if ($null -ne $procdump_command) {
        Start-Process -NoNewWindow -Wait -FilePath $procdump_command.Source -ArgumentList @('-accepteula', '-ma', $process.Id, $dumpFilePath)
    } else {
        Start-Process -NoNewWindow -Wait -FilePath procdump -ArgumentList @('-accepteula', '-ma', $process.Id, $dumpFilePath)
    }
    if (!$process.HasExited) {
        Write-Output "Killing $test_executable_name"
        $process.Kill()
    }
}

if (!$process.HasExited) {
    $process.WaitForExit() | Out-Null
}

if ($null -ne $procdump_process) {
    try {
        if (!$procdump_process.HasExited) {
            # If the test exited due to a crash, ProcDump may still be writing the dump.
            # Give it a small grace period to finish before killing it.
            $grace_ms = 20000
            if ($process.ExitCode -ne 0) {
                $null = $procdump_process.WaitForExit($grace_ms)
            }
            if (!$procdump_process.HasExited) {
                $procdump_process.Kill()
            }
        }
    } catch {
        # Ignore failures (e.g. ProcDump already exited).
    }
}

Write-Output "Test $test_executable_name exited with code $($process.ExitCode)"

if ($process.ExitCode -ne 0) {
    $dump_files = Get-ChildItem -Path $OutputFolder -Filter "*.dmp" -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending
    if ($null -ne $dump_files -and $dump_files.Count -gt 0) {
        Write-Output "Found dump file(s):"
        foreach ($dump_file in ($dump_files | Select-Object -First 10)) {
            Write-Output "  $($dump_file.FullName)"
        }
    } else {
        Write-Output "No dump files found in $OutputFolder"
    }
}

exit $process.ExitCode
