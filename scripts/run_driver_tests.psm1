# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

$CodeCoverage = "$env:ProgramFiles\OpenCppCoverage\OpenCppCoverage.exe"

#
# Execute tests on VM.
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
          [Parameter(Mandatory = $True)][bool] $VerboseLogs,
          [Parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [Parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps",
          [Parameter(Mandatory = $False)][bool] $Coverage)

    Write-Log "Preparing to run $Testname"

    $LASTEXITCODE = 0

    $OriginalTestName = $TestName
    $ArgumentsList = @()

    if ($Coverage) {
        $ArgumentsList += @('-q', '--modules=C:\eBPF', '--export_type', ('binary:' + $TestName + '.cov'), '--', $TestName)
        $TestName = $CodeCoverage
    }
    # Execute Test.
    if ($VerboseLogs -eq $true) {
        $ArgumentsList += '-s'
    }

    $JoinedArgumentsList = $ArgumentsList -join " "
    $TestRunScript = ".\Run-Self-Hosted-Runner-Test.ps1"
    & $TestRunScript `
        -TestCommand $TestName `
        -TestArguments $JoinedArgumentsList `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -NeedKernelDump $True `
        -Verbose

    Write-Log "$TestName Passed" -ForegroundColor Green
    Write-Log "`n`n"
}

function Invoke-CICDTests
{
    param([parameter(Mandatory = $true)][bool] $VerboseLogs,
          [parameter(Mandatory = $false)][bool] $Coverage = $false,
          [parameter(Mandatory = $false)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps"
    )


    Push-Location $WorkingDirectory
    $env:EBPF_ENABLE_WER_REPORT = "yes"

    $TestList = @(
        "api_test.exe",
        "bpftool_tests.exe",
        "sample_ext_app.exe",
        "socket_tests.exe")

    foreach ($Test in $TestList) {
        Invoke-Test -TestName $Test -VerboseLogs $VerboseLogs -Coverage $Coverage
    }

    if ($Coverage) {
        # Combine code coverage reports
        $ArgumentsList += @()
        foreach ($Test in $TestList) {
            $ArgumentsList += @('--input_coverage', ($Test + '.cov'))
        }
        $ArgumentsList += @('--export_type', 'cobertura:c:\eBPF\ebpf_for_windows.xml', '--')

        $JoinedArgumentsList = $ArgumentsList -join " "
        $TestRunScript = ".\Run-Self-Hosted-Runner-Test.ps1"
        & $TestRunScript `
            -TestCommand $CodeCoverage `
            -TestArguments $JoinedArgumentsList `
            -TestHangTimeout = $TestHangTimeout `
            -UserModeDumpFolder $UserModeDumpFolder `
            -Verbose
    }

    if ($Env:BUILD_CONFIGURATION -eq "Release") {
        Invoke-Test -TestName "ebpf_performance.exe" -VerboseLogs $VerboseLogs
    }

    Pop-Location
}

function Invoke-XDPTest
{
    param([parameter(Mandatory = $true)][string] $RemoteIPV4Address,
          [parameter(Mandatory = $true)][string] $RemoteIPV6Address,
          [parameter(Mandatory = $true)][string] $XDPTestName,
          [parameter(Mandatory = $true)][string] $WorkingDirectory,
          [parameter(Mandatory = $false)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps"
    )

    Push-Location $WorkingDirectory

    Write-Log "Executing $XDPTestName with remote address: $RemoteIPV4Address"
    $TestRunScript = ".\Run-Self-Hosted-Runner-Test.ps1"
    $TestCommand = ".\xdp_tests.exe"
    $TestArguments = "$XDPTestName --remote-ip $RemoteIPV4Address"

    & $TestRunScript `
        -TestCommand $TestCommand `
        -TestArguments $TestArguments `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -Verbose

    Start-Sleep -seconds 5
    Write-Log "Executing $XDPTestName with remote address: $RemoteIPV6Address"
    $TestRunScript = ".\Run-Self-Hosted-Runner-Test.ps1"
    $TestCommand = ".\xdp_tests.exe"
    $TestArguments = "$XDPTestName --remote-ip $RemoteIPV6Address"

    & $TestRunScript `
        -TestCommand $TestCommand `
        -TestArguments $TestArguments `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -Verbose

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
          [parameter(Mandatory = $true)][string] $WorkingDirectory,
          [parameter(Mandatory = $false)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps")

    Push-Location $WorkingDirectory

    $TestRunScript = ".\Run-Self-Hosted-Runner-Test.ps1"
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

    & $TestRunScript `
        -TestCommand $TestCommand `
        -TestArguments $TestArguments `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -Verbose

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

    & $TestRunScript `
        -TestCommand $TestCommand `
        -TestArguments $TestArguments `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -Verbose

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

    & $TestRunScript `
        -TestCommand $TestCommand `
        -TestArguments $TestArguments `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -Verbose

    Write-Log "Connect-Redirect Test Passed" -ForegroundColor Green

    Pop-Location
}

function Invoke-CICDStressTests
{
    param([parameter(Mandatory = $true)][bool] $VerboseLogs,
          [parameter(Mandatory = $false)][bool] $Coverage = $false,
          [parameter(Mandatory = $false)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
          [parameter(Mandatory = $false)][bool] $NeedKernelDump = $true,
          [parameter(Mandatory = $false)][bool] $RestartExtension = $false)

    Push-Location $WorkingDirectory
    $env:EBPF_ENABLE_WER_REPORT = "yes"

    Write-Log "Executing eBPF kernel mode multi-threaded stress tests (restart extension:$RestartExtension)."

    $LASTEXITCODE = 0

    $TestCommand = "ebpf_stress_tests_km"
    $TestArguments = " "
    if ($RestartExtension -eq $false) {
        $TestArguments = "-tt=8 -td=5"
    } else {
        $TestArguments = "-tt=8 -td=5 -erd=1000 -er=1"
    }

    $TestRunScript = ".\Run-Self-Hosted-Runner-Test.ps1"
    & $TestRunScript `
        -TestCommand $TestCommand `
        -TestArguments $TestArguments `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder `
        -NeedKernelDump $True `
        -Verbose

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
