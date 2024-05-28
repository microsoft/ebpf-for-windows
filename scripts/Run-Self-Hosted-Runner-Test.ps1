# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
#
# This script executes the provided test command, waits for <TestHangTimeout> (in seconds) and then triggers user and
# kernel dumps if the test process is still running (This is typically the case when the test process is hung for some
# reason).
#
# The user mode dump is created using 'procdump64.exe' and the kernel dump using 'notmyfault64.exe' utilities
# respectively, both from the SysInternals Suite.  The script assumes the presence of these utilities under the current
# working directory.
#
# (While 'procdump64.exe' also has the ability to generate a kernel dump, that dump is restricted to the kernel
# portions of the user mode app's threads _only_ and does not provide any visibility into other kernel threads.  This
# script therefore uses the 'notmyfault64.exe' tool to generate a 'true' kernel dump which captures the state of all
# kernel threads and related data structures)
#

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)] [string] $TestCommand,
    [Parameter(Mandatory = $false)] [string] $TestArguments = "",
    [Parameter(Mandatory = $false)] [int] $TestHangTimeout = 3600,
    [Parameter(Mandatory = $false)] [string] $UserModeDumpFolder = "C:\Dumps",
    [Parameter(Mandatory = $false)] [bool] $NeedKernelDump = $true
)

function ThrowWithErrorMessage
{
    Param(
        [Parameter(Mandatory = $True)] [string] $ErrorMessage
    )

    Write-Log $ErrorMessage
    # Wait a bit to let the above message to show up.
    Start-Sleep -seconds 5
    throw $ErrorMessage
}

# Finds and returns the specified tool's location under the current directory. If not found, throws an exception.
function GetToolLocationPath
{
    param(
        [Parameter(Mandatory = $True)] [string] $ToolName
    )

    $ToolLocationPath = Get-ChildItem -Path "$Pwd" `
        -Recurse -Filter "$ToolName" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ToolLocationPath -eq $null) {
        ThrowWithErrorMessage -ErrorMessage "*** ERROR *** $ToolName not found under $Pwd."
    }

    return $ToolLocationPath.FullName
}

function GetDriveFreeSpaceGB
{
    Param(
        # Drive Specification in the form of a single alphabet string. (eg. "C:")
        [Parameter(Mandatory = $True)] [string] $DriveSpecification
    )

    if (($DriveSpecification.Length -eq $Null) -or ($DriveSpecification.Length -ne 2)) {
        ThrowWithErrorMessage -ErrorMessage "*** ERROR *** No drive or Invalid drive specified."
    }

    # Convert drive to single letter (eg. "C:" to "C") for Get-Volume.
    $DriveSpecification = $DriveSpecification -replace ".$"
    $FreeSpaceGB = (((Get-Volume $DriveSpecification).SizeRemaining) / 1GB).ToString("F2")

    return $FreeSpaceGB
}

if ($VerbosePreference -eq 'Continue') {
    Write-Log "Command               : $TestCommand"
    Write-Log "Arguments             : $TestArguments"
    Write-Log "Test Hang Timeout     : $TestHangTimeout"
    Write-Log "User mode dump Folder : $UserModeDumpFolder"
    Write-Log "Kernel dump needed    : $NeedKernelDump"
}

# Verify timeout is non-zero.
if ($TestHangTimeout -le 0) {
    ThrowWithErrorMessage `
    -ErrorMessage "*** ERROR *** Invalid test hang timeout value: $TestHangTimeout"
}

# Verify user mode dump folder name is not null.
if ($UserModeDumpFolder -eq $Null) {
    ThrowWithErrorMessage `
    -ErrorMessage "*** ERROR *** User mode dump folder cannot be NULL"
}

# Create dump folder if not present.
if (-not (Test-Path -Path $UserModeDumpFolder)) {
    New-Item -Path $UserModeDumpFolder -ItemType Directory -Force | Out-Null

    # Verify dump folder creation.
    if (-not (Test-Path -Path $UserModeDumpFolder)) {
        ThrowWithErrorMessage `
        -ErrorMessage "*** ERROR *** User mode dump folder creation failed: $UserModeDumpFolder"
    }
}

# Check if procdump64.exe and notmyfault64.exe are present on the system.
$ProcDumpBinary = "ProcDump64.exe"
Write-Log "Verifying $ProcDumpBinary presence in $Pwd..."
$ProcDumpBinaryPath = GetToolLocationPath -ToolName $ProcDumpBinary
Write-Log "$ProcDumpBinary location: $ProcDumpBinaryPath"
Write-Log "`n"

$NotMyFaultBinary = "NotMyFault64.exe"
Write-Log "Verifying $NotMyFaultBinary presence in $Pwd..."
$NotMyFaultBinaryPath = GetToolLocationPath -ToolName $NotMyFaultBinary
Write-Log "$NotMyFaultBinary location: $NotMyFaultBinaryPath"
Write-Log "`n"

# While at it, enable EULA for all SysInternals tools.
REG ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f | Out-Null

# The following 'Set-ItemProperty' command enables a full memory dump.
# NOTE: This needs a VM with an explicitly created page file of *AT LEAST* (physical_memory + 1MB) in size.
# The default value of the 'CrashDumpEnabled' key is 7 ('automatic' sizing of dump file size (system determined)).
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value 1

if ($VerbosePreference -eq 'Continue') {
    # Dump current kernel mode dump settings.
    Write-Log "`n"
    Write-Log "Current kernel dump configuration:`n"
    $KernelDumpInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $Lines = $KernelDumpInfo -split '; '
    foreach($Line in $Lines) {
        Write-Log "`t$Line"
    }
    Write-Log "`n"
}

# Get the available free space before test start (useful in investigating dump file creation failures)
$BeforeTestFreeSpaceGB = GetDriveFreeSpaceGB -DriveSpecification $Env:SystemDrive
Write-Log "Available System disk space (Before test start): $BeforeTestFreeSpaceGB GB"

# Start the test process using the provided command and arguments.
$FullTestCommandSpec = Join-Path $Pwd $TestCommand
Write-Log "`n`n"
Write-Log "Staring Test command: $FullTestCommandSpec $TestArguments"
Write-Log "Test hang timeout: $TestHangTimeout (seconds)"
Write-Log "`n"

# Create a temporary file for standard output and error.
$TestTempOutFile = [System.IO.Path]::GetTempFileName()

# Form the complete command line with output redirection for cmd.exe.
$TestCommandLine = "$FullTestCommandSpec $($TestArguments) > $TestTempOutFile 2>&1"

# Start the test process and wait for it to exit or timeout.
$TestProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $TestCommandLine" -PassThru -NoNewWindow

# Cache the process handle. This has a side-effect that enables access to the process's exit code after termination.
# (https://stackoverflow.com/a/23797762)
$ProcessHandle = $TestProcess.Handle

$WaitResult = $TestProcess.WaitForExit($TestHangTimeout * 1000)
if (-not $WaitResult) {
    Write-Log "`n"
    Write-Log "*** ERROR *** Test execution hang timeout ($TestHangTimeout seconds) expired.`n"

    # First, generate a user mode dump.
    $UserModeDumpFileName = "$($TestCommand)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').dmp"
    $UserModeDumpFilePath = Join-Path $UserModeDumpFolder $UserModeDumpFileName

    if ($VerbosePreference -eq 'Continue') {
        Write-Log "User mode Dumpfile name: $UserModeDumpFileName"
        Write-Log "User mode Dumpfile Path: $UserModeDumpFilePath"
    }

    # Get the available free space at this point in case the test creates its own files.
    # (useful in investigating user and/or kernel dump file creation failures).
    $DriveFreeSpaceGB = GetDriveFreeSpaceGB -DriveSpecification $Env:SystemDrive
    Write-Log "Current available disk space: $DriveFreeSpaceGB GB`n"

    # $TestProcess refers to 'cmd.exe' which ends up running the real test application.
    # (This is done so that we can capture the stdout and stderr outputs from the test application
    # itself. I have not been able to get Powershell's 'built-in' redirection mechanisms for the
    # 'Process' object to play well in our scenario).
    # We therefore need pass the test application's id to procdump64.exe
    $TestCommandId = (Get-Process -Name $TestCommand).Id
    Write-Log "Test Command:$TestCommand, Id:$TestCommandId"

    Write-Log "Creating User mode dump @ $UserModeDumpFilePath"
    $ProcDumpArguments = "-r -ma $($TestCommandId) $UserModeDumpFilePath"
    Write-Log "Dump Command: $ProcDumpBinaryPath $ProcDumpArguments"
    $ProcDumpProcess = Start-Process -NoNewWindow `
        -FilePath $ProcDumpBinaryPath `
        -ArgumentList $ProcDumpArguments `
        -Wait -PassThru
    Write-Log "Waiting for user mode dump to complete..."
    $ProcDumpProcess.WaitForExit()

    # Get procdump64.exe's exit code.
    $ExitCode = $($ProcDumpProcess.ExitCode)
    Write-Log "$ProcDumpBinaryPath completed with exit code: $ExitCode`n"

    # Flush disk buffers to ensure user mode dump data is completely written to disk.
    Write-Log "User mode dump completed. Flushing disk buffers..."
    Write-VolumeCache -DriveLetter C

    # Wait for a bit for things to settle down to ensure the user mode dump is completely flushed.
    Start-Sleep -seconds 10

    # Paranoia check: Make sure a (seemingly) valid dump file _is_ created.
    $UserModeDumpSizeMB =
        (((Get-ItemProperty -Path $UserModeDumpFilePath).Length) /1MB).ToString("F2")
    if ($UserModeDumpSizeMB -eq 0) {
        Write-Log "* WARNING * User mode dump $UserModeDumpFilePath NOT CREATED"
    } else {
        Write-Log "`n`n"
        Write-Log "Created $UserModeDumpFilePath, size: $UserModeDumpSizeMB MB"
        Write-Log "`n`n"
    }

    if ($NeedKernelDump) {
        Write-Log "Creating kernel dump...`n"
        # Wait a bit for the above message to show up in the log.
        Start-Sleep -seconds 5

        # This will/should not return (test system will/should bluescreen and reboot).
        Start-Process -NoNewWindow -Wait -FilePath $NotMyFaultBinaryPath -ArgumentList "/crash"

        # If we get here, notmyfault64.exe failed for some reason. Kill the hung process, throw error.
        $TestProcess.Kill()
        ThrowWithErrorMessage `
            -ErrorMessage "*** ERROR *** $($PSCommandPath): kernel mode dump creation FAILED"
    } else {
        Write-Log "`n`n"
        Write-Log "Kernel dump not needed, killing test process $($TestProcess.ProcessName)..."
        $TestProcess.Kill()
        Write-Log "`n`n"

        $ErrorMessage = "*** ERROR *** $($PSCommandPath): $FullTestCommandSpec.exe exceeded test hang timout of " +
            "$TestHangTimeout seconds"
        ThrowWithErrorMessage -ErrorMessage $ErrorMessage
    }
} else {

    # Ensure the process has completely exited.
    $TestProcess.WaitForExit()

    # Read and display the output (if any) from the temporary output file.
    $TestStandardOutput = Get-Content -Path $TestTempOutFile
    if ($TestStandardOutput) {
        Write-Log "`n`n"
        Write-Log "Test Program output:`n"
        foreach($Line in $TestStandardOutput) {
            if ($Line -ne $Null) {
                Write-Log $Line
            }
        }
    }
    Write-Log "`n"

    if ($($TestProcess.ExitCode) -ne 0) {
        $ErrorMessage = "*** ERROR *** $($PSCommandPath): $FullTestCommandSpec failed."
        ThrowWithErrorMessage -ErrorMessage $ErrorMessage
    }
}
