# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$True)] [string] $LogFileName)

# Flag set when a VM crash (PSRemotingTransportException) is detected.
# Prevents cascading connection attempts to a dead VM.
$script:VMCrashed = $false

#
# Common helper functions.
#


function Write-Log
{
    [CmdletBinding()]
    param([parameter(Mandatory=$False, ValueFromPipeline=$true)]$TraceMessage=$null,
          [parameter(Mandatory=$False)]$ForegroundColor = [System.ConsoleColor]::White)

    process
    {
        if (![System.String]::IsNullOrEmpty($TraceMessage)) {
            $timestamp = (Get-Date).ToString('HH:mm:ss')
            Write-Host "[$timestamp] :: $TraceMessage"-ForegroundColor $ForegroundColor
            # Write to the log file using FileStream with FileShare.ReadWrite to
            # avoid locking conflicts when multiple callers write concurrently.
            try {
                $logPath = "$env:TEMP\$LogFileName"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes("[$timestamp] :: $TraceMessage`r`n")
                $fs = [System.IO.FileStream]::new(
                    $logPath,
                    [System.IO.FileMode]::Append,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
                $fs.Write($bytes, 0, $bytes.Length)
                $fs.Close()
            } catch {
                # Never let a log-write failure kill the process.
            }
        }
    }
}

function ThrowWithErrorMessage
{
    Param(
        [Parameter(Mandatory = $True)] [string] $ErrorMessage
    )

    Write-Log $ErrorMessage -ForegroundColor Red
    Start-Sleep -Milliseconds 100
    throw $ErrorMessage
}

function Start-ProcessWithTimeout
{
    param(
        [Parameter(Mandatory=$true)] [string] $FilePath,
        [Parameter(Mandatory=$false)] [string[]] $ArgumentList = @(),
        [Parameter(Mandatory=$false)] [int] $TimeoutSeconds = 60
    )

    # Create temp files for output redirection
    $tempOut = [System.IO.Path]::GetTempFileName()
    $tempErr = [System.IO.Path]::GetTempFileName()

    try {
        Write-Log "Starting process with timeout: $TimeoutSeconds seconds"
        Write-Log "Executing: $FilePath $($ArgumentList -join ' ')"

        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -PassThru -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
        $handle = $process.Handle # Important: this ensures we can access the process info later
        Write-Log "Process started with ID: $($process.Id)"

        if ($process.WaitForExit($TimeoutSeconds * 1000)) {
            $exitCode = $process.ExitCode
            Write-Log "Process completed with exit code: $exitCode"
            return $exitCode
        } else {
            Write-Log "Process timed out after $TimeoutSeconds seconds, terminating process"
            if (-not $process.HasExited) {
                $process.Kill()
                $process.WaitForExit(5000)
            }
            Write-Log "Process terminated due to timeout"
            return -1 # Indicate timeout
        }
    } catch {
        Write-Log "Exception running process: $_" -ForegroundColor Red
        return -2 # Indicate exception
    } finally {
        # Clean up temp files
        if (Test-Path $tempOut) { Remove-Item $tempOut -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempErr) { Remove-Item $tempErr -Force -ErrorAction SilentlyContinue }
    }
}


function Compress-File
{
    param ([Parameter(Mandatory = $True)] [string] $SourcePath,
           [Parameter(Mandatory = $True)] [string] $DestinationPath
    )

    Write-Log "Compressing $SourcePath -> $DestinationPath"

    # Use System.IO.Compression directly instead of Compress-Archive
    # to avoid the 2GB MemoryStream limitation in Compress-Archive (affects files > 2GB).
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    # Retry 5 times to ensure compression operation succeeds.
    # To mitigate error message: "The process cannot access the file <filename> because it is being used by another process."
    $retryCount = 1
    while ($retryCount -le 5) {
        try {
            $ErrorActionPreference = "Stop"

            # Remove existing destination if present.
            if (Test-Path $DestinationPath) {
                Remove-Item $DestinationPath -Force
            }

            $zipArchive = [System.IO.Compression.ZipFile]::Open(
                $DestinationPath,
                [System.IO.Compression.ZipArchiveMode]::Create)

            try {
                $sourceFiles = Get-ChildItem -Path $SourcePath -ErrorAction Stop
                foreach ($file in $sourceFiles) {
                    Write-Log "Adding $($file.Name) ($((($file.Length) / 1MB).ToString('F2')) MB) to archive..."
                    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                        $zipArchive,
                        $file.FullName,
                        $file.Name,
                        [System.IO.Compression.CompressionLevel]::Fastest) | Out-Null
                }
            } finally {
                $zipArchive.Dispose()
            }

            # Verify the compressed file was actually created.
            if (Test-Path $DestinationPath) {
                $compressedSize = (Get-Item $DestinationPath).Length
                Write-Log "Compression completed successfully. Compressed size: $(($compressedSize / 1MB).ToString('F2')) MB"
                return $true
            } else {
                throw "Compressed file was not created at $DestinationPath"
            }
        } catch {
            $ErrorMessage = "*** ERROR *** Failed to compress files (attempt $retryCount of 5): $($_.Exception.Message)"
            Write-Log $ErrorMessage
            # Clean up partial zip file on failure.
            if (Test-Path $DestinationPath) {
                Remove-Item $DestinationPath -Force -ErrorAction Ignore
            }
            if ($retryCount -lt 5) {
                Start-Sleep -seconds (5 * $retryCount)
            }
            $retryCount++
        }
    }

    # All retries failed.
    Write-Log "*** ERROR *** Failed to compress after 5 attempts. Compression failed."
    return $false
}

<#
.SYNOPSIS
    Attempts to compress files and copies them to a destination, with fallback to uncompressed files.

.DESCRIPTION
    This function standardizes the pattern of trying to compress files and copying the result,
    with automatic fallback to copying uncompressed files if compression fails.

.PARAMETER SourcePath
    The source files to compress (supports wildcards like *.dmp).

.PARAMETER DestinationDirectory
    The directory where the final files should be copied.

.PARAMETER CompressedFileName
    The name for the compressed file. If not provided, auto-generates based on source.

.OUTPUTS
    Returns a hashtable with the following properties:
    - Success: Boolean indicating if compression succeeded
    - CompressedPath: Path to compressed file (if compression succeeded)
    - UncompressedPath: Path to uncompressed file (if compression failed)
    - FinalPath: Path to the final file that was copied

.EXAMPLE
    $result = CompressOrCopy-File -SourcePath "C:\dumps\*.dmp" -DestinationDirectory "C:\output" -CompressedFileName "dumps.zip"
    if ($result.Success) {
        Write-Host "Compression succeeded: $($result.FinalPath)"
    } else {
        Write-Host "Compression failed, using uncompressed: $($result.FinalPath)"
    }
#>
function CompressOrCopy-File
{
    param(
        [Parameter(Mandatory=$True)][string] $SourcePath,
        [Parameter(Mandatory=$True)][string] $DestinationDirectory,
        [Parameter(Mandatory=$False)][string] $CompressedFileName
    )

    # Ensure destination directory exists.
    if (-not (Test-Path $DestinationDirectory -PathType Container)) {
        New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
    }

    # Auto-generate compressed filename if not provided.
    if (-not $CompressedFileName) {
        $sourceName = Split-Path $SourcePath -Leaf
        $CompressedFileName = "$sourceName.zip"
    }

    # Create temporary path for compression.
    $tempCompressedPath = Join-Path $env:TEMP $CompressedFileName
    $finalCompressedPath = Join-Path $DestinationDirectory $CompressedFileName

    # Attempt compression.
    $compressionSucceeded = Compress-File -SourcePath $SourcePath -DestinationPath $tempCompressedPath

    if ($compressionSucceeded -and (Test-Path $tempCompressedPath)) {
        # Compression succeeded - copy compressed file.
        Copy-Item -Path $tempCompressedPath -Destination $finalCompressedPath -Force
        Remove-Item -Path $tempCompressedPath -Force -ErrorAction Ignore

        $compressedFile = Get-ChildItem -Path $finalCompressedPath
        Write-Log "Copied compressed file: $($compressedFile.Name), Size: $((($compressedFile.Length) / 1MB).ToString("F2")) MB"

        return @{
            Success = $true
            CompressedPath = $finalCompressedPath
            UncompressedPath = ""
            FinalPath = $finalCompressedPath
        }
    } else {
        # Compression failed - copy uncompressed files as fallback.
        Write-Log "*** WARNING *** Compression failed. Copying uncompressed files instead."

        $sourceFiles = Get-ChildItem -Path $SourcePath -ErrorAction SilentlyContinue
        $copiedPaths = @()

        foreach ($file in $sourceFiles) {
            $destinationPath = Join-Path $DestinationDirectory $file.Name
            Copy-Item -Path $file.FullName -Destination $destinationPath -Force
            Write-Log "Copied uncompressed file: $($file.Name)"
            $copiedPaths += $destinationPath
        }

        # Clean up temporary compressed file if it exists.
        if (Test-Path $tempCompressedPath) {
            Remove-Item -Path $tempCompressedPath -Force -ErrorAction Ignore
        }

        return @{
            Success = $false
            CompressedPath = ""
            UncompressedPath = if ($copiedPaths.Count -gt 0) { $copiedPaths -join "; " } else { "" }
            FinalPath = if ($copiedPaths.Count -gt 0) { $copiedPaths -join "; " } else { "" }
        }
    }
}

<#
.SYNOPSIS
    Copies compressed files from a remote session, with fallback to uncompressed files.

.DESCRIPTION
    This function standardizes the pattern of trying to copy compressed files from a remote session
    and falling back to uncompressed files if the compressed copy fails.

.PARAMETER VMSession
    The remote PowerShell session to copy from.

.PARAMETER CompressedSourcePath
    The path to the compressed file on the remote session.

.PARAMETER UncompressedSourcePath
    The path to the uncompressed file on the remote session.

.PARAMETER DestinationDirectory
    The local directory where files should be copied.

.OUTPUTS
    Returns a hashtable with the following properties:
    - Success: Boolean indicating if compressed copy succeeded
    - CompressedPath: Path to compressed file (if compressed copy succeeded)
    - UncompressedPath: Path to uncompressed file (if compressed copy failed)
    - FinalPath: Path to the final file that was copied

.EXAMPLE
    $result = CopyCompressedOrUncompressed-FileFromSession -VMSession $session -CompressedSourcePath "C:\eBPF\trace.zip" -UncompressedSourcePath "C:\eBPF\trace.etl" -DestinationDirectory ".\Logs"
    if ($result.Success) {
        Write-Host "Compressed copy succeeded: $($result.FinalPath)"
    } else {
        Write-Host "Using uncompressed fallback: $($result.FinalPath)"
    }
#>
function CopyCompressedOrUncompressed-FileFromSession
{
    param(
        [Parameter(Mandatory=$True)] $VMSession,
        [Parameter(Mandatory=$True)][string] $CompressedSourcePath,
        [Parameter(Mandatory=$True)][string] $UncompressedSourcePath,
        [Parameter(Mandatory=$True)][string] $DestinationDirectory,
        [Parameter(Mandatory=$False)][int] $MaxRetries = 3
    )

    # Ensure destination directory exists.
    if (-not (Test-Path $DestinationDirectory -PathType Container)) {
        New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
    }

    $compressedFileName = Split-Path $CompressedSourcePath -Leaf
    $uncompressedFileName = Split-Path $UncompressedSourcePath -Leaf
    $compressedDestPath = Join-Path $DestinationDirectory $compressedFileName

    # Try to copy compressed file first with retry logic.
    Write-Log "Copy $CompressedSourcePath to $DestinationDirectory"
    $compressedCopySucceeded = $false

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-Log "Attempting compressed file copy (attempt $attempt of $MaxRetries)"
            Copy-Item `
                -FromSession $VMSession `
                -Path $CompressedSourcePath `
                -Destination $DestinationDirectory `
                -Recurse `
                -Force `
                -ErrorAction Stop

            # Check if compressed copy succeeded.
            if (Test-Path $compressedDestPath) {
                Write-Log "Successfully copied compressed file: $compressedFileName"
                $compressedCopySucceeded = $true
                break
            }
        } catch {
            Write-Log "Compressed file copy attempt $attempt failed: $($_.Exception.Message)"
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Seconds (2 * $attempt)  # Progressive delay
            }
        }
    }

    if ($compressedCopySucceeded) {
        return @{
            Success = $true
            CompressedPath = $compressedDestPath
            UncompressedPath = ""
            FinalPath = $compressedDestPath
        }
    } else {
        # Compressed copy failed, try uncompressed with retry logic.
        Write-Log "Compressed file not found or copy failed, trying uncompressed: Copy $UncompressedSourcePath to $DestinationDirectory"
        $uncompressedDestPath = Join-Path $DestinationDirectory $uncompressedFileName
        $uncompressedCopySucceeded = $false

        # Handle wildcard paths by expanding them on the remote session first.
        # Get file paths and sizes so we can skip files too large for Copy-Item -FromSession
        # (large files over Hyper-V PowerShell Direct can kill the socket/session).
        $MaxUncompressedCopySize = 2GB
        $sourceFiles = @()
        if ($UncompressedSourcePath -like "*\*.*") {
            try {
                $sourceFiles = Invoke-Command -Session $VMSession -ScriptBlock {
                    param($Path)
                    Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
                        [PSCustomObject]@{ FullName = $_.FullName; Length = $_.Length; Name = $_.Name }
                    }
                } -ArgumentList $UncompressedSourcePath -ErrorAction SilentlyContinue

                if ($sourceFiles.Count -eq 0) {
                    Write-Log "No files found matching pattern: $UncompressedSourcePath"
                }
            } catch {
                Write-Log "Failed to expand wildcard path $UncompressedSourcePath : $($_.Exception.Message)"
            }
        } else {
            # For non-wildcard paths, get size from remote session.
            try {
                $sourceFiles = Invoke-Command -Session $VMSession -ScriptBlock {
                    param($Path)
                    if (Test-Path $Path) {
                        $f = Get-Item $Path
                        [PSCustomObject]@{ FullName = $f.FullName; Length = $f.Length; Name = $f.Name }
                    }
                } -ArgumentList $UncompressedSourcePath -ErrorAction SilentlyContinue
                if ($sourceFiles) { $sourceFiles = @($sourceFiles) } else { $sourceFiles = @() }
            } catch {
                $sourceFiles = @()
            }
        }

        # Copy each file individually with retry logic
        $anyCopySucceeded = $false
        foreach ($fileInfo in $sourceFiles) {
            $sourceFile = $fileInfo.FullName
            $fileName = $fileInfo.Name
            $fileSize = $fileInfo.Length
            $destPath = Join-Path $DestinationDirectory $fileName

            # Skip files that are too large to copy over the session safely.
            if ($fileSize -gt $MaxUncompressedCopySize) {
                Write-Log ("*** WARNING *** Skipping $fileName ({0:F2} GB) - exceeds {1:F2} GB limit for uncompressed session copy. " +
                    "This file should have been compressed first.") -f ($fileSize / 1GB), ($MaxUncompressedCopySize / 1GB)
                continue
            }

            Write-Log ("Uncompressed file: $fileName, Size: {0:F2} MB" -f ($fileSize / 1MB))

            for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
                try {
                    Write-Log "Attempting to copy $sourceFile (attempt $attempt of $MaxRetries)"
                    Copy-Item `
                        -FromSession $VMSession `
                        -Path $sourceFile `
                        -Destination $DestinationDirectory `
                        -Force `
                        -ErrorAction Stop

                    # Check if copy succeeded.
                    if (Test-Path $destPath) {
                        Write-Log "Successfully copied uncompressed file: $fileName"
                        $anyCopySucceeded = $true
                        $uncompressedDestPath = $destPath  # Update to last successful file
                        break
                    }
                } catch {
                    Write-Log "Failed to copy $sourceFile (attempt $attempt): $($_.Exception.Message)"
                    if ($attempt -lt $MaxRetries) {
                        Start-Sleep -Seconds (2 * $attempt)  # Progressive delay
                    }
                }
            }
        }

        if (-not $anyCopySucceeded) {
            Write-Log "*** WARNING *** Failed to copy any files from $UncompressedSourcePath after $MaxRetries attempts each"
        }

        return @{
            Success = $false
            CompressedPath = ""
            UncompressedPath = $uncompressedDestPath
            FinalPath = $uncompressedDestPath
        }
    }
}

function Wait-TestJobToComplete
{
    param([Parameter(Mandatory = $true)] [System.Management.Automation.Job] $Job,
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [Parameter(Mandatory = $true)] [int] $TestJobTimeout,
           [Parameter(Mandatory = $true)] [string] $CheckpointPrefix,
           [Parameter(Mandatory = $false)] [bool] $ExecuteOnHost=$false,
           [Parameter(Mandatory = $false)] [bool] $ExecuteOnVM=$true,
           [Parameter(Mandatory = $false)] [bool] $VMIsRemote=$false,
           [Parameter(Mandatory = $false)] [string] $TestWorkingDirectory="C:\ebpf",
           [Parameter(Mandatory = $false)] [string] $LogFileName="timeout_kernel_dump.log",
           [Parameter(Mandatory = $false)] [string] $TestMode="CI/CD",
           [Parameter(Mandatory = $false)] [string[]] $Options=@("None"),
           [Parameter(Mandatory = $false)] [int] $TestHangTimeout=(10*60),
           [Parameter(Mandatory = $false)] [string] $UserModeDumpFolder="C:\Dumps",
           [Parameter(Mandatory = $false)] [bool] $SkipDumpOnTimeout=$false)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $HeartbeatInterval = 30  # Log a heartbeat every 30 seconds of silence.
    $TimeSinceLastOutput = 0

    # Stream job output to a file instead of directly to stdout.  This prevents
    # the polling loop from blocking when the runner agent / GitHub log ingestion
    # creates back-pressure on the stdout pipe (4 KB buffer on Windows).  If
    # Write-Host blocks, the entire loop freezes and no timeout can fire.
    $outputLogPath = Join-Path $env:TEMP "test_job_output_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Log "Job output streaming to: $outputLogPath"

    # Loop to fetch and print job output in near real-time.
    while ($Job.State -eq 'Running') {
        Start-Sleep -Seconds 2
        $TimeSinceLastOutput += 2

        try {
            $JobOutput = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if ($JobOutput) {
                # Write output to file (non-blocking, avoids stdout pipe pressure).
                $JobOutput | Out-File -FilePath $outputLogPath -Append -Encoding utf8
                # Also write to stdout, but limit to avoid pipe saturation.
                # Show the last few lines so the GitHub log has enough context.
                $lines = @($JobOutput)
                if ($lines.Count -le 5) {
                    $lines | ForEach-Object { Write-Host $_ }
                } else {
                    Write-Host "... ($($lines.Count) lines, see full output in TestLogs)"
                    $lines | Select-Object -Last 3 | ForEach-Object { Write-Host $_ }
                }
                $TimeSinceLastOutput = 0
            }
        } catch {
            Write-Log "Warning: Failed to receive job output (remote session may have ended): $($_.Exception.Message)"
        }

        # Emit periodic heartbeat so the GitHub log shows the runner is alive.
        if ($TimeSinceLastOutput -ge $HeartbeatInterval) {
            Write-Log "$CheckpointPrefix job still running ($([int]$sw.Elapsed.TotalSeconds)s elapsed, job state: $($Job.State))."
            $TimeSinceLastOutput = 0
        }

        if ($sw.Elapsed.TotalSeconds -gt $TestJobTimeout) {
            if ($Job.State -eq "Running") {
                if ($ExecuteOnVM -and -not $SkipDumpOnTimeout) {
                    $VMList = $Config.VMMap.$SelfHostedRunnerName
                    # Currently one VM runs per runner.
                    $TestVMName = $VMList[0].Name

                    try {
                        Write-Host "Running kernel test job on $TestVMName has timed out after $($TestJobTimeout / 60) minutes." -ForegroundColor Yellow
                        Write-Log "Generating kernel dump due to test timeout on $TestVMName"

                        Import-Module "$PSScriptRoot\vm_run_tests.psm1" -ArgumentList @(
                            $false,                                    # ExecuteOnHost
                            $true,                                     # ExecuteOnVM
                            $VMIsRemote,                               # VMIsRemote
                            $TestVMName,                               # VMName
                            $TestWorkingDirectory,                     # WorkingDirectory
                            $LogFileName,                              # LogFileName
                            $TestMode,                                 # TestMode
                            $Options,                                  # Options
                            $TestHangTimeout,                          # TestHangTimeout
                            $UserModeDumpFolder                        # UserModeDumpFolder
                        ) -Force -WarningAction SilentlyContinue

                        # Run Generate-KernelDumpOnVM in a sub-job with a timeout so it
                        # cannot block the timeout handler indefinitely (the VM may be
                        # unreachable, causing Invoke-Command to hang).
                        $DumpJobTimeout = 600  # seconds
                        Write-Log "Starting kernel dump generation (timeout: ${DumpJobTimeout}s)..."
                        $dumpJob = Start-Job -ScriptBlock {
                            param($ScriptRoot, $ExecuteOnHost, $ExecuteOnVM, $VMIsRemote,
                                  $TestVMName, $TestWorkingDirectory, $LogFileName,
                                  $TestMode, $Options, $TestHangTimeout, $UserModeDumpFolder)
                            Import-Module "$ScriptRoot\vm_run_tests.psm1" -ArgumentList @(
                                $ExecuteOnHost, $ExecuteOnVM, $VMIsRemote, $TestVMName,
                                $TestWorkingDirectory, $LogFileName, $TestMode, $Options,
                                $TestHangTimeout, $UserModeDumpFolder
                            ) -Force -WarningAction SilentlyContinue
                            Generate-KernelDumpOnVM
                        } -ArgumentList @(
                            $PSScriptRoot, $false, $true, $VMIsRemote,
                            $TestVMName, $TestWorkingDirectory, $LogFileName,
                            $TestMode, $Options, $TestHangTimeout, $UserModeDumpFolder
                        )
                        $dumpCompleted = $dumpJob | Wait-Job -Timeout $DumpJobTimeout
                        if (-not $dumpCompleted) {
                            Write-Log "Kernel dump generation timed out after ${DumpJobTimeout}s -- VM may be unreachable."
                            Stop-Job -Job $dumpJob -ErrorAction SilentlyContinue
                        } else {
                            Write-Log "Kernel dump generation completed."
                        }
                        # Bounded removal to avoid hanging on stuck PS Direct transports.
                        try {
                            $removeTask = [powershell]::Create().AddScript({ param($j) Remove-Job -Job $j -Force -ErrorAction SilentlyContinue }).AddArgument($dumpJob)
                            $asyncResult = $removeTask.BeginInvoke()
                            if (-not $asyncResult.AsyncWaitHandle.WaitOne(15000)) {
                                Write-Log "Warning: Remove-Job for dump job timed out."
                            }
                            $removeTask.Dispose()
                        } catch {}
                    } catch {
                        # Do nothing - this is expected as the VM will crash.
                    }
                }
                $JobTimedOut = $true
                break
            }
        }
    }

    # Print any remaining output after the job completes.
    try {
        $JobOutput = Receive-Job -Job $job -ErrorAction SilentlyContinue
        if ($JobOutput) {
            $JobOutput | Out-File -FilePath $outputLogPath -Append -Encoding utf8
            $lines = @($JobOutput)
            if ($lines.Count -le 20) {
                $lines | ForEach-Object { Write-Host $_ }
            } else {
                Write-Host "... ($($lines.Count) final lines written to log)"
                $lines | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
            }
        }
    } catch {
        Write-Log "Warning: Failed to receive final job output: $($_.Exception.Message)"
    }

    # Copy the job output log to TestLogs so it's uploaded as an artifact.
    try {
        if (Test-Path $outputLogPath) {
            $testLogsDir = ".\TestLogs"
            if (-not (Test-Path $testLogsDir)) { New-Item -ItemType Directory -Path $testLogsDir -Force | Out-Null }
            Copy-Item -Path $outputLogPath -Destination "$testLogsDir\job_output.log" -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    return $JobTimedOut
}

<#
.SYNOPSIS
    Helper function to create a directory if it does not already exist.

.DESCRIPTION
    This function checks if a directory exists at the specified path. If it does not exist, it creates the directory.

.PARAMETER Path
    The path of the directory to create.

.EXAMPLE
    Create-DirectoryIfNotExists -Path "C:\MyDirectory"
#>
function Create-DirectoryIfNotExists {
    param (
        [Parameter(Mandatory=$True)][string]$Path
    )

    # Create the directory if it does not already exist.
    if (-not (Test-Path -Path $Path -PathType Container)) {
        New-Item -Path $Path -ItemType Directory -Force
    }

    # Check if the directory was successfully created.
    if (-not (Test-Path -PathType Container $Path)) {
        throw "Failed to create directory: $Path"
    }
}

<#
.SYNOPSIS
    Helper function to replace placeholder strings in a file.

.DESCRIPTION
    This function replaces all occurrences of a specified search string with a replacement string in a file.

.PARAMETER FilePath
    The path to the file in which to replace the placeholder strings.

.PARAMETER SearchString
    The string to search for in the file.

.PARAMETER ReplaceString
    The string to replace the search string with.

.EXAMPLE
    Replace-PlaceholderStrings -FilePath "C:\MyFile.txt" -SearchString "PLACEHOLDER" -ReplaceString "ActualValue"
#>
function Replace-PlaceholderStrings {
    param (
        [Parameter(Mandatory=$True)][string]$FilePath,
        [Parameter(Mandatory=$True)][string]$SearchString,
        [Parameter(Mandatory=$True)][string]$ReplaceString
    )

    try {
        $content = Get-Content -Path $FilePath
        $content = $content -replace $SearchString, $ReplaceString
        Set-Content -Path $FilePath -Value $content
    } catch {
        throw "Failed to replace placeholder strings in file: $FilePath. Error: $_"
    }
}

<#
.SYNOPSIS
    Helper function to invoke a script using PsExec.

.DESCRIPTION
    This function uses PsExec to run a PowerShell script in the LocalSystem account context.

.PARAMETER Script
    The script to execute using PsExec.

.EXAMPLE
    Invoke-PsExecScript -Script "Get-Process"
#>
function Invoke-PsExecScript {
    param (
        [Parameter(Mandatory=$true)][string]$Script
    )
    $PSExecPath = Get-PSExec
    if (($null -eq $PSExecPath) -or (-not (Test-Path $PSExecPath))) {
        throw "Failed to retrieve PsExec path."
    }

    $outputFile = [System.IO.Path]::GetTempFileName()
    $errorFile = [System.IO.Path]::GetTempFileName()

    try {
        $process = Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula -nobanner -s powershell.exe -command `"$Script`"" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
        $output = Get-Content $outputFile
        $err = Get-Content $errorFile

        if ($process.ExitCode -ne 0) {
            throw "PsExec failed with exit code $($process.ExitCode). Output: $output Error: $err"
        }

        return $output
    } finally {
        Remove-Item $outputFile -Force -ErrorAction Ignore
        Remove-Item $errorFile -Force -ErrorAction Ignore
    }
}

<#
.SYNOPSIS
    Returns the well-known password used for inner test VM accounts.

.DESCRIPTION
    Single source of truth for the VM password used by both the Administrator and
    VMStandardUser accounts on the inner test VMs. All scripts that need the password
    should call this function rather than hardcoding the value.

    A simple well-known password is acceptable here because these are ephemeral nested
    test VMs that are not network-accessible outside the host. They are created, used
    for CI/CD test execution, and destroyed within a single pipeline run. The password
    only needs to meet Windows complexity requirements and remain consistent between
    the unattend.xml provisioning (via PLACEHOLDER_PASSWORD substitution in Create-VM)
    and the PowerShell Direct credentials used by the test scripts.

.OUTPUTS
    [String] The VM password.
#>
function Get-VMPassword {
    return 'eBPF4W!n'
}

<#
.SYNOPSIS
    Imports the CredentialManager, and installs it if necessary.

.DESCRIPTION
    This function imports the CredentialManager module and installs it if it is not already installed. It also ensures that any dependencies are installed.
#>
function Get-CredentialManager {
    # Import the CredentialManager module. Ensure any dependencies are installed.
    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop *> $null 2>&1
    Import-PackageProvider -Name NuGet -Force -ErrorAction Stop *> $null 2>&1
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        Install-Module -Name CredentialManager -Force -ErrorAction Stop *> $null 2>&1
    }
    Import-Module CredentialManager -ErrorAction Stop
}

<#
.SYNOPSIS
    Retrieves a credential from the Windows Credential Manager using PsExec.

.PARAMETER Target
    The name of the stored credential. Default is "MyStoredCredential".

.DESCRIPTION
    This function uses PsExec to run a PowerShell script in the LocalSystem account context to retrieve a credential from the Windows Credential Manager.

.EXAMPLE
    $credential = Retrieve-StoredCredential -Target "MyStoredCredential"
#>
function Retrieve-StoredCredential {
    param (
        [Parameter(Mandatory=$True)][string]$Target
    )
    Get-CredentialManager

    $Script = @"
        Import-Module CredentialManager -ErrorAction Stop;
        `$Credential = Get-StoredCredential -Target '$Target';
        `$UserName = `$Credential.UserName;
        `$Password = `$Credential.GetNetworkCredential().Password;
        \"`$UserName`n`$Password\"
"@

    # PSExec sometimes fails to fetch the output. Retry up to 3 times to improve reliability.
    $attempt = 0
    $maxRetries = 5
    while ($attempt -lt $maxRetries) {
        try {
            $output = Invoke-PsExecScript -Script $Script
            $lines = $output -split "`n"
            $Username = $lines[0].Trim()
            $plainPwd = $lines[1].Trim()
            $Password = [System.Security.SecureString]::new()
            foreach ($c in $plainPwd.ToCharArray()) { $Password.AppendChar($c) }
            if ($null -eq $Username -or $null -eq $Password) {
                throw "Failed to retrieve the stored credential."
            }
            return [System.Management.Automation.PSCredential]::new($Username, $Password)
        } catch {
            $attempt++
            if ($attempt -lt $maxRetries) {
                Start-Sleep -Seconds 5
            } else {
                throw "Failed to retrieve the stored credential after $maxRetries attempts."
            }
        }
    }
}

<#
.SYNOPSIS
    Creates a PSCredential for the specified VM user.

.DESCRIPTION
    For local VMs (PowerShell Direct), creates a PSCredential using the well-known
    password from Get-VMPassword.

    For remote VMs (WinRM), retrieves the credential from Windows Credential Manager
    using the specified target name. The credential must have been previously stored
    with New-StoredCredential using `-Persist LocalMachine`.

.PARAMETER Username
    The username for the credential.

.PARAMETER VMIsRemote
    When true, retrieves the credential from Credential Manager instead of using
    the hardcoded password. Defaults to false.

.EXAMPLE
    $credential = Get-VMCredential -Username 'Administrator'
    $credential = Get-VMCredential -Username 'Administrator' -VMIsRemote $true
#>
function Get-VMCredential {
    param (
        [Parameter(Mandatory=$True)][string]$Username,
        [Parameter(Mandatory=$false)][bool]$VMIsRemote = $false
    )
    if ($VMIsRemote) {
        # Determine the Credential Manager target based on username.
        if ($Username -eq 'Administrator') {
            $CredentialTarget = 'TEST_VM'
        } else {
            $CredentialTarget = 'TEST_VM_STANDARD'
        }
        return Retrieve-StoredCredential -Target $CredentialTarget
    } else {
        $plainPwd = Get-VMPassword
        $securePassword = [System.Security.SecureString]::new()
        foreach ($c in $plainPwd.ToCharArray()) { $securePassword.AppendChar($c) }
        return [System.Management.Automation.PSCredential]::new($Username, $securePassword)
    }
}


function Expand-ZipFile {
    param(
        [Parameter(Mandatory=$True)][string] $DownloadFilePath,
        [Parameter(Mandatory=$True)][string] $OutputDir,
        [Parameter(Mandatory=$True)][int] $maxRetries,
        [Parameter(Mandatory=$True)][int] $retryDelay,
        [Parameter(Mandatory=$True)][int] $timeout
    )

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $job = Start-Job -ScriptBlock {
                param ($DownloadFilePath, $OutputDir)
                Expand-Archive -Path $DownloadFilePath -DestinationPath $OutputDir -Force
            } -ArgumentList $DownloadFilePath, $OutputDir

            if (Wait-Job -Job $job -Timeout $timeout) {
                Write-Log "Extraction completed. $DownloadFilePath -> $OutputDir"
                Receive-Job -Job $job
                break
            } else {
                Stop-Job -Job $job
                try {
                    $removeTask = [powershell]::Create().AddScript({ param($j) Remove-Job -Job $j -Force -ErrorAction SilentlyContinue }).AddArgument($job)
                    $asyncResult = $removeTask.BeginInvoke()
                    if (-not $asyncResult.AsyncWaitHandle.WaitOne(15000)) {
                        Write-Log "Warning: Remove-Job timed out in Expand-ZipFile"
                    }
                    $removeTask.Dispose()
                } catch {}
                if ($i -eq ($maxRetries - 1)) {
                    throw "Failed to extract $DownloadFilePath after $maxRetries attempts."
                } else {
                    Start-Sleep -Seconds $retryDelay
                }
            }
        } catch {
            if ($i -eq ($maxRetries - 1)) {
                throw "Failed to extract $DownloadFilePath after $maxRetries attempts."
            } else {
                Start-Sleep -Seconds $retryDelay
            }
        }
    }
}

function Get-ZipFileFromUrl {
    param(
        [Parameter(Mandatory=$True)][string] $Url,
        [Parameter(Mandatory=$True)][string] $DownloadFilePath,
        [Parameter(Mandatory=$True)][string] $OutputDir
    )
    $maxRetries = 5
    $retryDelay = 5 # seconds
    $timeout = 300 # seconds

    Write-Log "Downloading $Url to $DownloadFilePath"

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Head -TimeoutSec $timeout
            if ($response.StatusCode -ne 200) {
                throw "Failed to reach $Url HTTP status code: $($response.StatusCode)"
            }

            $ProgressPreference = 'SilentlyContinue'

            $job = Start-Job -ScriptBlock {
                param ($Url, $DownloadFilePath, $timeout)
                Invoke-WebRequest -Uri $Url -OutFile $DownloadFilePath -TimeoutSec $timeout
            } -ArgumentList $Url, $DownloadFilePath, $timeout

            if (Wait-Job -Job $job -Timeout $timeout) {
                Receive-Job -Job $job

                Write-Log "Extracting $DownloadFilePath to $OutputDir"
                Expand-ZipFile -DownloadFilePath $DownloadFilePath -OutputDir $OutputDir -maxRetries $maxRetries -retryDelay $retryDelay -timeout $timeout
                break
            } else {
                Stop-Job -Job $job
                try {
                    $removeTask = [powershell]::Create().AddScript({ param($j) Remove-Job -Job $j -Force -ErrorAction SilentlyContinue }).AddArgument($job)
                    $asyncResult = $removeTask.BeginInvoke()
                    if (-not $asyncResult.AsyncWaitHandle.WaitOne(15000)) {
                        Write-Log "Warning: Remove-Job timed out in Get-ZipFileFromUrl"
                    }
                    $removeTask.Dispose()
                } catch {}
                if (Test-Path $DownloadFilePath) {
                    Remove-Item -Path $DownloadFilePath -Force -ErrorAction Ignore
                }
                if ($i -eq ($maxRetries - 1)) {
                    throw "Failed to download $Url after $maxRetries attempts."
                } else {
                    Start-Sleep -Seconds $retryDelay
                }
            }
        } catch {
            if (Test-Path $DownloadFilePath) {
                Remove-Item -Path $DownloadFilePath -Force -ErrorAction Ignore
            }
            if ($i -eq ($maxRetries - 1)) {
                throw "Failed to download $Url after $maxRetries attempts."
            } else {
                Start-Sleep -Seconds $retryDelay
            }
        }
    }
}

function Get-RegressionTestArtifacts
{
    param([Parameter(Mandatory=$True)][string] $Configuration,
          [Parameter(Mandatory=$True)][string] $ArtifactVersion)

    $RegressionTestArtifactsPath = "$pwd\regression"
    $OriginalPath = $pwd
    if (Test-Path -Path $RegressionTestArtifactsPath) {
        Remove-Item -Path $RegressionTestArtifactsPath -Recurse -Force
    }
    mkdir $RegressionTestArtifactsPath

    # Verify artifacts' folder presence
    if (-not (Test-Path -Path $RegressionTestArtifactsPath)) {
        $ErrorMessage = "*** ERROR *** Regression test artifacts folder not found: $RegressionTestArtifactsPath)"
        Write-Log $ErrorMessage
        throw $ErrorMessage
    }

    # Download regression test artifacts for each version.
    $DownloadPath = "$RegressionTestArtifactsPath"
    $ArtifactName = "Release-v$ArtifactVersion/Build.$Configuration.x64.zip"
    $ArtifactUrl = "https://github.com/microsoft/ebpf-for-windows/releases/download/" + $ArtifactName

    if (Test-Path -Path $DownloadPath\Build-x64.$Configuration) {
        Remove-Item -Path $DownloadPath\Build-x64.$Configuration -Recurse -Force
    }

    Get-ZipFileFromUrl -Url $ArtifactUrl -DownloadFilePath "$DownloadPath\Build-x64.$Configuration.zip" -OutputDir $DownloadPath
    $DownloadedArtifactPath = "$DownloadPath\Build $Configuration x64"
    if (!(Test-Path -Path $DownloadedArtifactPath)) {
        throw ("Path ""$DownloadedArtifactPath"" not found.")
    }

    # Copy all the drivers, DLLs, exe and .o files to pwd.
    Write-Log "Copy regression test artifacts to main folder" -ForegroundColor Green
    Push-Location $DownloadedArtifactPath
    Get-ChildItem -Path .\* -Include *.sys | Move-Item -Destination $OriginalPath -Force
    Get-ChildItem -Path .\* -Include *.dll | Move-Item -Destination $OriginalPath -Force
    Get-ChildItem -Path .\* -Include *.exe | Move-Item -Destination $OriginalPath -Force
    Get-ChildItem -Path .\* -Include *.o | Move-Item -Destination $OriginalPath -Force
    Pop-Location

    Remove-Item -Path $DownloadPath -Force -Recurse

    # Delete ebpfapi.dll from the artifacts. ebpfapi.dll from the MSI installation should be used instead.
    Remove-Item -Path ".\ebpfapi.dll" -Force
}

# Copied from https://github.com/microsoft/msquic/blob/main/scripts/prepare-machine.ps1
function Get-CoreNetTools {
    param(
        [string] $Architecture = "x64"
    )
    # Download and extract https://github.com/microsoft/corenet-ci.
    $DownloadPath = "$pwd\corenet-ci"
    mkdir $DownloadPath
    Write-Log "Downloading CoreNet-CI to $DownloadPath"
    Get-ZipFileFromUrl -Url "https://github.com/microsoft/corenet-ci/archive/refs/heads/main.zip" -DownloadFilePath "$DownloadPath\corenet-ci.zip" -OutputDir $DownloadPath
    # DuoNic.
    if ($Architecture -eq "arm64") {
        $duoNicPath = "$DownloadPath\corenet-ci-main\vm-setup\duonic\arm64\*"
    } else {
        $duoNicPath = "$DownloadPath\corenet-ci-main\vm-setup\duonic\*"
    }
    Move-Item -Path $duoNicPath -Destination $pwd -Force
    # Procdump.
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\procdump64.exe" -Destination $pwd -Force
    # NotMyFault.
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\notmyfault64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse
}

# Download and extract PSExec to run tests as SYSTEM.
function Get-PSExec {
    $psExecPath = "$pwd\PsExec64.exe"
    # Check to see if PSExec already exists
    if (Test-Path -Path $psExecPath) {
        return $psExecPath
    }
    $url = "https://download.sysinternals.com/files/PSTools.zip"
    $DownloadPath = "$pwd\psexec"

    Get-ZipFileFromUrl -Url $url -DownloadFilePath "$pwd\pstools.zip" -OutputDir "$DownloadPath"
    Move-Item -Path "$DownloadPath\PsExec64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse -ErrorAction Ignore
    return $psExecPath
}

<#
.SYNOPSIS
    Invokes a command on a remote or local VM.

.PARAMETER VMName
    The name of the VM.

.PARAMETER VMIsRemote
    Indicates if the VM is remote.

.PARAMETER Credential
    The credential to use for the VM.

.DESCRIPTION
    This function invokes a command on a remote or local VM using the specified credentials.

.PARAMETER ScriptBlock
    The script block to execute on the VM.

.PARAMETER ArgumentList
    The arguments to pass to the script block.

.EXAMPLE
    Invoke-CommandOnVM -VMName "MyVM" -VMIsRemote $true -Credential $credential -ScriptBlock { Get-Process }
#>
function Invoke-CommandOnVM {
    param(
        [Parameter(Mandatory = $true)][string] $VMName,
        [Parameter(Mandatory = $false)][bool] $VMIsRemote = $false,
        [Parameter(Mandatory = $true)][PSCredential] $Credential,
        [Parameter(Mandatory = $true)][ScriptBlock] $ScriptBlock,
        [Parameter(Mandatory = $false)][object[]] $ArgumentList = @(),
        [Parameter(Mandatory = $false)][int] $TimeoutSeconds = 300
    )

    # Fast-fail if the VM has already crashed in this process to avoid
    # cascading connection attempts that will hang on the dead transport.
    if ($script:VMCrashed) {
        throw "VM $VMName has already crashed -- refusing new connection to avoid cascading hangs."
    }

    # Bounded execution: use -AsJob so we can monitor progress and enforce a
    # timeout.  This prevents a dead PS Direct transport from blocking the
    # caller indefinitely.
    Write-Log "Invoking command on VM: $VMName (IsRemote: $VMIsRemote, Timeout: ${TimeoutSeconds}s)"
    if ($VMIsRemote) {
        $invokeJob = Invoke-Command -ComputerName $VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -AsJob -ErrorAction Stop
    } else {
        $invokeJob = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -AsJob -ErrorAction Stop
    }

    # Use a Stopwatch for wall-clock accuracy.  The old accumulator-based
    # counter ($elapsed += $pollInterval) becomes inaccurate if Receive-Job or
    # any other operation in the loop blocks for longer than $pollInterval,
    # which can happen when the PS Direct VMBus transport is stuck.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $pollInterval = 5
    $heartbeatInterval = 30
    $timeSinceOutput = 0

    try {
        while ($invokeJob.State -eq 'Running') {
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                Write-Log "*** ERROR *** Command on VM $VMName timed out after $([int]$sw.Elapsed.TotalSeconds)s (limit ${TimeoutSeconds}s)."
                # Drain any final output before killing the job.
                try {
                    $output = Receive-Job -Job $invokeJob -ErrorAction SilentlyContinue 2>&1
                    if ($output) {
                        $lines = @($output)
                        if ($lines.Count -le 10) {
                            $lines | ForEach-Object { Write-Host $_ }
                        } else {
                            Write-Host "... ($($lines.Count) lines from VM, showing last 5)"
                            $lines | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
                        }
                    }
                } catch {}
                # Stop-Job can hang if the PS Direct VMBus transport is stuck.
                # Run it on a background thread with a 30-second timeout.
                $stopTask = [powershell]::Create().AddScript({
                    param($j) Stop-Job -Job $j -ErrorAction SilentlyContinue
                }).AddArgument($invokeJob)
                $stopAsync = $stopTask.BeginInvoke()
                if (-not $stopAsync.AsyncWaitHandle.WaitOne(30000)) {
                    Write-Log "Warning: Stop-Job timed out on VM $VMName -- continuing."
                }
                try { $stopTask.EndInvoke($stopAsync) } catch {}
                $stopTask.Dispose()
                throw [System.TimeoutException]::new("Command on VM $VMName timed out after $([int]$sw.Elapsed.TotalSeconds)s")
            }

            Start-Sleep -Seconds $pollInterval
            $timeSinceOutput += $pollInterval

            # Stream any available output from the remote command.
            try {
                $output = Receive-Job -Job $invokeJob -ErrorAction SilentlyContinue 2>&1
                if ($output) {
                    # Limit output to avoid pipe saturation between nested jobs.
                    $lines = @($output)
                    if ($lines.Count -le 5) {
                        $lines | ForEach-Object { Write-Host $_ }
                    } else {
                        Write-Host "... ($($lines.Count) lines from VM)"
                        $lines | Select-Object -Last 3 | ForEach-Object { Write-Host $_ }
                    }
                    $timeSinceOutput = 0
                }
            } catch {
                Write-Log "Warning: Failed to receive job output: $($_.Exception.Message)"
            }

            if ($timeSinceOutput -ge $heartbeatInterval) {
                Write-Log "Invoke-CommandOnVM: waiting on $VMName ($([int]$sw.Elapsed.TotalSeconds)s / ${TimeoutSeconds}s, job state: $($invokeJob.State))..."
                $timeSinceOutput = 0
            }
        }

        # Job finished -- drain remaining output (job may have ended between polls).
        Write-Log "Invoke-CommandOnVM: job on $VMName finished after $([int]$sw.Elapsed.TotalSeconds)s (state: $($invokeJob.State))."
        try {
            $output = Receive-Job -Job $invokeJob -ErrorAction SilentlyContinue 2>&1
            if ($output) {
                $lines = @($output)
                if ($lines.Count -le 20) {
                    $lines | ForEach-Object { Write-Host $_ }
                } else {
                    Write-Host "... ($($lines.Count) final lines from VM, showing last 10)"
                    $lines | Select-Object -Last 10 | ForEach-Object { Write-Host $_ }
                }
            }
        } catch {}

        # Also check child jobs for any error output that wasn't surfaced.
        if ($invokeJob.ChildJobs.Count -gt 0) {
            foreach ($child in $invokeJob.ChildJobs) {
                try {
                    $childOutput = Receive-Job -Job $child -ErrorAction SilentlyContinue 2>&1
                    if ($childOutput) {
                        $clines = @($childOutput)
                        if ($clines.Count -le 20) {
                            $clines | ForEach-Object { Write-Host $_ }
                        } else {
                            Write-Host "... ($($clines.Count) child job lines, showing last 10)"
                            $clines | Select-Object -Last 10 | ForEach-Object { Write-Host $_ }
                        }
                    }
                } catch {}
            }
        }

        # If the remote command failed, re-throw so the caller sees the error.
        if ($invokeJob.State -eq 'Failed') {
            $reason = $invokeJob.ChildJobs[0].JobStateInfo.Reason
            if ($reason) {
                if ($reason -is [System.Management.Automation.Remoting.PSRemotingTransportException]) {
                    $script:VMCrashed = $true
                    Write-Log "*** VM CRASH DETECTED *** Marking VM as crashed to prevent cascading connection attempts."
                }
                Write-Log "*** REMOTE FAILURE *** $($reason.GetType().Name): $($reason.Message)"
                throw $reason
            }
            throw "Command on VM $VMName failed."
        }
    } finally {
        # Remove-Job -Force can hang if the PS Direct VMBus transport is stuck
        # in an unmanaged call that Stop-Job couldn't interrupt. Run it on a
        # background thread with a timeout so it cannot block the caller.
        $removeTask = [powershell]::Create().AddScript({ param($j) Remove-Job -Job $j -Force -ErrorAction SilentlyContinue }).AddArgument($invokeJob)
        $asyncResult = $removeTask.BeginInvoke()
        if (-not $asyncResult.AsyncWaitHandle.WaitOne(15000)) {
            Write-Log "Warning: Remove-Job timed out for VM job -- disposing forcefully."
        }
        $removeTask.Dispose()
    }
}

<#
.SYNOPSIS
    Creates a new PowerShell session on a remote or local VM.
.PARAMETER VMName
    The name of the VM.
.PARAMETER VMIsRemote
    Indicates if the VM is remote.
.PARAMETER Credential
    The credential to use for the VM.
.RETURNS
    A new PowerShell session object.
.DESCRIPTION
    This function creates a new PowerShell session on a remote or local VM using the specified credentials
.EXAMPLE
    $session = New-SessionOnVM -VMName "MyVM" -VMIsRemote $true -Credential $credential
#>
function New-SessionOnVM {
    param(
        [Parameter(Mandatory = $true)][string] $VMName,
        [Parameter(Mandatory = $false)][bool] $VMIsRemote = $false,
        [Parameter(Mandatory = $true)][PSCredential] $Credential,
        [Parameter(Mandatory = $false)][int] $TimeoutMs = 60000
    )
    $session = $null
    Write-Log "Creating new session on VM: $VMName (IsRemote: $VMIsRemote, Timeout: $($TimeoutMs/1000)s)"
    # Set operation and open timeouts on remote (WinRM) sessions to prevent
    # indefinite hangs when the VM is unreachable (e.g. after a crash).
    # Note: -SessionOption is not supported with -VMName (PowerShell Direct),
    # but PS Direct connections fail relatively quickly when the VM is down
    # because the Hyper-V socket transport detects the VM state.
    if ($VMIsRemote) {
        $sessionOption = New-PSSessionOption -OperationTimeout $TimeoutMs -OpenTimeout $TimeoutMs
        $session = New-PSSession -ComputerName $VMName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
    } else {
        $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
    }
    return $session
}
