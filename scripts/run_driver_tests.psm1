# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName,
       [parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
       [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
       [Parameter(Mandatory = $false)][bool] $GranularTracing = $false)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue
Import-Module .\tracing_utils.psm1 -Force -ArgumentList ($LogFileName, $WorkingDirectory) -WarningAction SilentlyContinue

#
# Utility functions.
#

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
    $Volume = Get-Volume $DriveSpecification
    if ($Volume -eq $Null) {
        ThrowWithErrorMessage -ErrorMessage "*** ERROR *** Drive $DriveSpecification not found."
    }
    $FreeSpaceGB = (($Volume.SizeRemaining) / 1GB).ToString("F2")

    return $FreeSpaceGB
}

function Generate-KernelDump
{
    Push-Location $WorkingDirectory
    $NotMyFaultBinary = "NotMyFault64.exe"
    Write-Log "Verifying $NotMyFaultBinary presence in $Pwd..."
    $NotMyFaultBinaryPath = GetToolLocationPath -ToolName $NotMyFaultBinary
    Write-Log "$NotMyFaultBinary location: $NotMyFaultBinaryPath"
    Write-Log "`n"

    Write-Log "Creating kernel dump...`n"
    # Wait a bit for the above message to show up in the log.
    Start-Sleep -seconds 5

    # This will/should not return (test system will/should bluescreen and reboot).
    $NotMyFaultProc = Start-Process -NoNewWindow -Passthru -FilePath $NotMyFaultBinaryPath -ArgumentList "/crash"
    # wait for 30 minutes to generate the kernel dump.
    $NotMyFaultProc.WaitForExit(30*60*1000)

    # If we get here, notmyfault64.exe failed for some reason. Kill the hung process, throw error.
    ThrowWithErrorMessage `
        -ErrorMessage "*** ERROR *** $($PSCommandPath): kernel mode dump creation FAILED"
}

function Generate-ProcessDump
{
    param([Parameter(Mandatory = $true)] [int] $TestProcessId,
          [Parameter(Mandatory = $true)] [string] $TestCommand,
          [Parameter(Mandatory = $false)] [string] $UserModeDumpFolder = "C:\Dumps")

    # Check if procdump64.exe and notmyfault64.exe are present on the system.
    $ProcDumpBinary = "ProcDump64.exe"
    Write-Log "Verifying $ProcDumpBinary presence in $Pwd..."
    $ProcDumpBinaryPath = GetToolLocationPath -ToolName $ProcDumpBinary
    Write-Log "$ProcDumpBinary location: $ProcDumpBinaryPath"
    Write-Log "`n"

    # Create dump folder if not present.
    if (-not (Test-Path -Path $UserModeDumpFolder)) {
        Write-Log "$UserModeDumpFolder created."
        New-Item -Path $UserModeDumpFolder -ItemType Directory -Force -ErrorAction Stop
    }
    $UserModeDumpFileName = "$($TestCommand)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').dmp"
    $UserModeDumpFilePath = Join-Path $UserModeDumpFolder $UserModeDumpFileName

    if ($VerbosePreference -eq 'Continue') {
        Write-Log "User mode Dumpfile name: $UserModeDumpFileName"
        Write-Log "User mode Dumpfile Path: $UserModeDumpFilePath"
    }

    # Get the available free space at this point in case the test creates its own files.
    # (useful in investigating user and/or kernel dump file creation failures).
    try {
        $DriveFreeSpaceGB = GetDriveFreeSpaceGB -DriveSpecification $Env:SystemDrive
    } catch {
        Write-Log "Error getting available disk space: $_" -ForegroundColor Red
        $DriveFreeSpaceGB = "Unknown"
        # Continue with the test.
    }
    Write-Log "Current available disk space: $DriveFreeSpaceGB GB`n"

    Write-Log "Creating User mode dump @ $UserModeDumpFilePath"
    $ProcDumpArguments = "-r -ma $($TestProcessId) $UserModeDumpFilePath"
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

    # Make sure a valid dump file is created.
    $UserModeDumpSizeMB =
        (((Get-ItemProperty -Path $UserModeDumpFilePath).Length) /1MB).ToString("F2")
    if ($UserModeDumpSizeMB -eq 0) {
        Write-Log "* WARNING * User mode dump $UserModeDumpFilePath NOT CREATED"
    } else {
        Write-Log "`n Created $UserModeDumpFilePath, size: $UserModeDumpSizeMB MB `n"
    }
}

#
# Test Completion processing
#

function Process-TestCompletion
{
    param([Parameter(Mandatory = $true)] [Object] $TestProcess,
          [Parameter(Mandatory = $true)] [string] $TestCommand,
          [Parameter(Mandatory = $false)] [bool] $NestedProcess,
          [Parameter(Mandatory = $false)] [int] $TestHangTimeout = (10*60), # 10 minutes default timeout.
          [Parameter(Mandatory = $false)] [bool] $NeedKernelDump = $true)

    if ($TestProcess -eq $null) {
        ThrowWithErrorMessage -ErrorMessage "*** ERROR *** Test $TestCommand failed to start."
    }

    # Use Wait-Process for the process to terminate or timeout.
    # See https://stackoverflow.com/a/23797762
    Wait-Process -InputObject $TestProcess -Timeout $TestHangTimeout -ErrorAction SilentlyContinue

    if (-not $TestProcess.HasExited) {
        Write-Log "`n*** ERROR *** Test $TestCommand execution hang timeout ($TestHangTimeout seconds) expired.`n"

        # Find the test process Id.
        if ($NestedProcess) {
            # The TestCommand is running nested inside another TestProcess.
            $TestNameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($TestCommand)
            $TestProcessId = (Get-Process -Name $TestNameNoExt).Id
        } else {
            $TestProcessId = $TestProcess.Id
        }
        Write-Log "Potentially hung process PID:$TestProcessId running $TestCommand"

        # Generate a user mode dump.
        Generate-ProcessDump -TestProcessId $TestProcessId -TestCommand $TestCommand

        # Next, kill the test process, if kernel dumps are not enabled.
        if (-not $NeedKernelDump) {
            Write-Log "Kernel dump not needed, killing process with PID:$TestProcessId..."
            Stop-Process -Id $TestProcessId
            ThrowWithErrorMessage -ErrorMessage "Test $TestCommand Hung!"
        }

        #finally, throw a new TestHung exception.
        Write-Log "Throwing TestHungException for $TestCommand" -ForegroundColor Red
        throw [System.TimeoutException]::new("Test $TestCommand execution hang timeout ($TestHangTimeout seconds) expired.")
    } else {
        # Read and display the output (if any) from the temporary output file.
        $TempOutputFile = "$env:TEMP\app_output.log"  # Log for standard output
        # Process the log file line-by-line
        if ((Test-Path $TempOutputFile) -and (Get-Item $TempOutputFile).Length -gt 0) {
            Write-Log "$TestCommand Output:`n" -ForegroundColor Green
            Get-Content -Path $TempOutputFile | ForEach-Object {
                Write-Log -TraceMessage $_
            }
            Remove-Item -Path $TempOutputFile -Force -ErrorAction Ignore
        }

        $TestExitCode = $TestProcess.ExitCode
        if ($TestExitCode -ne 0) {
            $TempErrorFile = "$env:TEMP\app_error.log"    # Log for standard error
            if ((Test-Path $TempErrorFile) -and (Get-Item $TempErrorFile).Length -gt 0) {
                Write-Log "$TestCommand Error Output:`n" -ForegroundColor Red
                Get-Content -Path $TempErrorFile | ForEach-Object {
                    Write-Log -TraceMessage $_ -ForegroundColor Red
                }
                Remove-Item -Path $TempErrorFile -Force -ErrorAction Ignore
            }

            $ErrorMessage = "*** ERROR *** $TestCommand failed with $TestExitCode."
            ThrowWithErrorMessage -ErrorMessage $ErrorMessage
        }
    }
}

#
# Execute tests.
#

function Invoke-NetshEbpfCommand
{
    param([Parameter(Mandatory=$True)][string] $Arguments)

    $ArgumentsList = @("ebpf") + $Arguments.Split(" ")

    $AddProgram = $false
    if ($ArgumentsList[1] -eq "add"){
        $AddProgram = $true
    }

    $LASTEXITCODE = 0
    $Output = &netsh.exe $ArgumentsList 2>&1

    # Check for errors.
    if ($LASTEXITCODE -ne 0) {
        throw ("netsh command returned error.")
    }

    Out-String -InputObject $Output | Write-Log -ForegroundColor Green

    # For add program command, the 4th element of the output string contains
    # the program Id.

    if ($AddProgram -eq $true) {
        $ProgId = ($Output.Split(" "))[3]
        return $ProgId
    }
}

function Invoke-Test
{
    param([Parameter(Mandatory = $True)][string] $TestName,
          [Parameter(Mandatory = $False)][string] $TestArgs = "",
          [Parameter(Mandatory = $False)][string] $InnerTestName = "",
          [Parameter(Mandatory = $False)][string] $TraceFileName = "",
          [Parameter(Mandatory = $True)][bool] $VerboseLogs,
          [Parameter(Mandatory = $True)][int] $TestHangTimeout,
          [Parameter(Mandatory = $False)][switch] $SkipTracing)

    try {
        # Initialize arguments.
        if ($TestArgs -ne "") {
            $ArgumentsList = @($TestArgs)
        }

        if ($VerboseLogs -eq $true) {
            $ArgumentsList += '-s'
        }

        # Execute Test.
        Write-Log "Executing $TestName $TestArgs"
        $TestFilePath = "$pwd\$TestName"
        $TempOutputFile = "$env:TEMP\app_output.log"  # Log for standard output
        $TempErrorFile = "$env:TEMP\app_error.log"    # Log for standard error
        if (-not $SkipTracing) {
            Start-WPRTrace
        }
        if ($ArgumentsList) {
            $TestProcess = Start-Process -FilePath $TestFilePath -ArgumentList $ArgumentsList -PassThru -NoNewWindow -RedirectStandardOutput $TempOutputFile -RedirectStandardError $TempErrorFile -ErrorAction Stop
        } else {
            $TestProcess = Start-Process -FilePath $TestFilePath -PassThru -NoNewWindow -RedirectStandardOutput $TempOutputFile -RedirectStandardError $TempErrorFile -ErrorAction Stop
        }
        # Cache the process handle to ensure subsequent access of the process is accurate.
        $handle = $TestProcess.Handle
        Write-Log "Started process pid: $($TestProcess.Id) name: $($TestProcess.ProcessName) and start: $($TestProcess.StartTime)"
        if ($InnerTestName -ne "") {
            Process-TestCompletion -TestProcess $TestProcess -TestCommand $InnerTestName -NestedProcess $True -TestHangTimeout $TestHangTimeout
        } else {
            Process-TestCompletion -TestProcess $TestProcess -TestCommand $TestName -TestHangTimeout $TestHangTimeout
        }

        Write-Log "Test `"$TestName $TestArgs`" Passed" -ForegroundColor Green
        Write-Log "`n==============================`n"
    }
    finally {
        if (-not $SkipTracing) {
            if ($TraceFileName -ne "") {
                $traceName = $TraceFileName
            } elseif ($InnerTestName -ne "") {
                $traceName = $InnerTestName
            } else {
                $traceName = $testName
            }
            Stop-WPRTrace -FileName $traceName
        }
    }
}

# Function to create a tuple with default values for Arguments and Timeout
function New-TestTuple {
    param (
        [string]$Test,
        [string]$Arguments = "",    # Default value: ""
        [int]$Timeout = 300         # Default value: 5 minutes
    )

    # Return a custom object (tuple)
    [pscustomobject]@{
        Test      = $Test
        Arguments = $Arguments
        Timeout   = $Timeout
    }
}

function Invoke-CICDTests
{
    param([parameter(Mandatory = $true)][bool] $VerboseLogs,
          [parameter(Mandatory = $true)][bool] $ExecuteSystemTests)


    Push-Location $WorkingDirectory
    $env:EBPF_ENABLE_WER_REPORT = "yes"

    # Now create an array of test tuples, overriding only the necessary values
    # load_native_program_invalid4 has been deleted from the test list, but 0.17 tests still have this test.
    # That causes the regression test to fail. So, we are skipping this test for now.

    $TestList = @(
        (New-TestTuple -Test "api_test.exe" -Arguments "~`"load_native_program_invalid4`" ~pinned_map_enum" -Timeout 600),
        (New-TestTuple -Test "bpftool_tests.exe" -Arguments "~`"prog load map_in_map`" ~`"prog prog run`""),
        (New-TestTuple -Test "sample_ext_app.exe"),
        (New-TestTuple -Test "socket_tests.exe" -Timeout 1800)
    )

    foreach ($Test in $TestList) {
        Invoke-Test -TestName $($Test.Test) -TestArgs $($Test.Arguments) -VerboseLogs $VerboseLogs -TestHangTimeout $($Test.Timeout) -TraceFileName $($Test.Test)
    }

    # Now run the system tests.

    $SystemTestList = @((New-TestTuple -Test "api_test.exe"))
    if ($ExecuteSystemTests) {
        foreach ($Test in $SystemTestList) {
            $TestCommand = "PsExec64.exe"
            $TestArguments = "-accepteula -nobanner -s -w `"$pwd`" `"$pwd\$($Test.Test) $($Test.Arguments)`" `"-d yes`""
            Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -InnerTestName $($Test.Test)  -VerboseLogs $VerboseLogs -TestHangTimeout $($Test.Timeout) -TraceFileName "$($Test.Test)_System"
        }
    }

    if ($Env:BUILD_CONFIGURATION -eq "Release") {
        Invoke-Test -TestName "ebpf_performance.exe" -VerboseLogs $VerboseLogs -SkipTracing
    }

    Pop-Location
}

function Invoke-XDPTest
{
    param([parameter(Mandatory = $true)][string] $RemoteIPV4Address,
          [parameter(Mandatory = $true)][string] $RemoteIPV6Address,
          [parameter(Mandatory = $true)][string] $XDPTestName,
          [parameter(Mandatory = $true)][string] $WorkingDirectory,
          [parameter(Mandatory = $true)][string] $TraceFileName)

    Push-Location $WorkingDirectory

    Write-Log "Executing $XDPTestName with remote address: $RemoteIPV4Address"
    $TestCommand = ".\xdp_tests.exe"
    $TestArguments = "$XDPTestName --remote-ip $RemoteIPV4Address"
    Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -VerboseLogs $false -TestHangTimeout $TestHangTimeout -TraceFileName "$($TraceFileName)_V4"

    Write-Log "Executing $XDPTestName with remote address: $RemoteIPV6Address"
    $TestCommand = ".\xdp_tests.exe"
    $TestArguments = "$XDPTestName --remote-ip $RemoteIPV6Address"
    Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -VerboseLogs $false -TestHangTimeout $TestHangTimeout -TraceFileName "$($TraceFileName)_V6"

    Write-Log "$XDPTestName Test Passed" -ForegroundColor Green
    Write-Log "`n`n"

    Pop-Location
}

function Invoke-ConnectRedirectTest
{
    param([parameter(Mandatory = $true)][string] $LocalIPv4Address,
          [parameter(Mandatory = $true)][string] $LocalIPv6Address,
          [parameter(Mandatory = $true)][string] $RemoteIPv4Address,
          [parameter(Mandatory = $true)][string] $RemoteIPv6Address,
          [parameter(Mandatory = $true)][string] $VirtualIPv4Address,
          [parameter(Mandatory = $true)][string] $VirtualIPv6Address,
          [parameter(Mandatory = $true)][int] $DestinationPort,
          [parameter(Mandatory = $true)][int] $ProxyPort,
          [parameter(Mandatory = $true)][string] $StandardUserName,
          [parameter(Mandatory = $true)][string] $StandardUserPassword,
          [parameter(Mandatory = $true)][string] $UserType,
          [parameter(Mandatory = $true)][string] $WorkingDirectory)

    Push-Location $WorkingDirectory

        $TestCommand = ".\connect_redirect_tests.exe"

        ## First run the test with both v4 and v6 programs attached.
        $TestArguments =
            " --virtual-ip-v4 $VirtualIPv4Address" +
            " --virtual-ip-v6 $VirtualIPv6Address" +
            " --local-ip-v4 $LocalIPv4Address" +
            " --local-ip-v6 $LocalIPv6Address" +
            " --remote-ip-v4 $RemoteIPv4Address" +
            " --remote-ip-v6 $RemoteIPv6Address" +
            " --destination-port $DestinationPort" +
            " --proxy-port $ProxyPort" +
            " --user-name $StandardUserName" +
            " --password $StandardUserPassword" +
            " --user-type $UserType"

        Write-Log "Executing connect redirect tests with v4 and v6 programs. Arguments: $TestArguments"
        Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -VerboseLogs $false -TestHangTimeout $TestHangTimeout -TraceFileName "connect_redirect_v4_v6_$($UserType)"

        ## Run test with only v4 program attached.
        $TestArguments =
            " --virtual-ip-v4 $VirtualIPv4Address" +
            " --local-ip-v4 $LocalIPv4Address" +
            " --remote-ip-v4 $RemoteIPv4Address" +
            " --destination-port $DestinationPort" +
            " --proxy-port $ProxyPort" +
            " --user-name $StandardUserName" +
            " --password $StandardUserPassword" +
            " --user-type $UserType" +
            " [connect_authorize_redirect_tests_v4]"

        Write-Log "Executing connect redirect tests with v4 programs. Arguments: $TestArguments"
        Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -VerboseLogs $false -TestHangTimeout $TestHangTimeout -TraceFileName "connect_redirect_v4_$($UserType)"

        ## Run tests with only v6 program attached.
        $TestArguments =
            " --virtual-ip-v6 $VirtualIPv6Address" +
            " --local-ip-v6 $LocalIPv6Address" +
            " --remote-ip-v6 $RemoteIPv6Address" +
            " --destination-port $DestinationPort" +
            " --proxy-port $ProxyPort" +
            " --user-name $StandardUserName" +
            " --password $StandardUserPassword" +
            " --user-type $UserType" +
            " [connect_authorize_redirect_tests_v6]"

        Write-Log "Executing connect redirect tests with v6 programs. Arguments: $TestArguments"
        Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -VerboseLogs $false -TestHangTimeout $TestHangTimeout -TraceFileName "connect_redirect_v6_$($UserType)"

        Write-Log "Connect-Redirect Test Passed" -ForegroundColor Green

    Pop-Location
}

function Invoke-CICDStressTests
{
    param([parameter(Mandatory = $true)][bool] $VerboseLogs,
          [parameter(Mandatory = $false)][int] $TestHangTimeout = (60*60),
          [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
          [parameter(Mandatory = $false)][bool] $NeedKernelDump = $true,
          [parameter(Mandatory = $false)][bool] $RestartExtension = $false)

    Push-Location $WorkingDirectory
    $env:EBPF_ENABLE_WER_REPORT = "yes"

    Write-Log "Executing eBPF kernel mode multi-threaded stress tests (restart extension:$RestartExtension)."

    $LASTEXITCODE = 0

    $TestCommand = ".\ebpf_stress_tests_km.exe"
    $TestArguments = " "
    if ($RestartExtension -eq $false) {
        $TestArguments = "-tt=8 -td=5"
    } else {
        $TestArguments = "-tt=8 -td=5 -erd=1000 -er=1"
    }

    Invoke-Test -TestName $TestCommand -TestArgs $TestArguments -VerboseLogs $VerboseLogs -TestHangTimeout $TestHangTimeout

    Pop-Location
}

function Invoke-CICDPerformanceTests
{
    param(
        [parameter(Mandatory = $true)][bool] $VerboseLogs,
        [parameter(Mandatory = $true)][bool] $CaptureProfile)
    Push-Location $WorkingDirectory

    Write-Log "Executing eBPF kernel mode performance tests."

    $LASTEXITCODE = 0

    # Stop the services, remove the driver from verifier, and restart the services.
    net.exe stop ebpfsvc
    net.exe stop ebpfcore
    # Remove the global verifier settings (this will remove the verifer interceptions that can degrade performance).
    verifier.exe /volatile 0
    # Remove the ebpfcore.sys driver from the verifier.
    verifier.exe /volatile /removedriver ebpfcore.sys
    net.exe start ebpfcore
    net.exe start ebpfsvc

    # Extract the performance test zip file.
    Expand-Archive -Path .\bpf_performance.zip -DestinationPath .\bpf_performance -Force
    Set-Location bpf_performance
    # Stop any existing tracing.
    wpr.exe -cancel

    if ($CaptureProfile) {
        $pre_command = 'wpr.exe -start CPU'
        $post_command = 'wpr.exe -stop ""' + $WorkingDirectory + '\bpf_performance_%NAME%.etl""'
        Release\bpf_performance_runner.exe -i tests.yml -e .sys -r --pre "$pre_command" --post "$post_command" | Tee-Object -FilePath $WorkingDirectory\bpf_performance_native.csv
    }
    else {
        Release\bpf_performance_runner.exe -i tests.yml -e .sys -r | Tee-Object -FilePath $WorkingDirectory\bpf_performance_native.csv
    }

    Pop-Location
}

Pop-Location
