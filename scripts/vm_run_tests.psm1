# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory = $false)][bool] $ExecuteOnHost = $false,
    [Parameter(Mandatory = $false)][bool] $ExecuteOnVM = $false,
    # The following parameters are only used when ExecuteOnVM is true
    [Parameter(Mandatory = $false)][bool] $VMIsRemote = $false,
    [Parameter(Mandatory = $True)] [string] $VMName,
    # The following are shared parameters for both ExecuteOnHost and ExecuteOnVM
    [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
    [Parameter(Mandatory = $True)] [string] $LogFileName,
    [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
    [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
    [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
    [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
    # Granular tracing parameters (passed through to run_driver_tests.psm1)
    [Parameter(Mandatory = $false)][bool] $GranularTracing = $false,
    # Boolean parameter indicating if XDP tests should be run.
    [Parameter(Mandatory = $false)][bool] $RunXdpTests = $false,
    [Parameter(Mandatory = $false)][string] $TraceDir = "",
    [Parameter(Mandatory = $false)][string] $KmTraceType = "file"
)

if (-not (Test-Path .\common.psm1)) {
    throw "common.psm1 module not found in the current directory."
}
Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

function Invoke-OnHostOrVM {
    param(
        [Parameter(Mandatory = $true, Position = 0)][ScriptBlock] $ScriptBlock,
        [Parameter(Mandatory = $false)][object[]] $ArgumentList = @(),
        [Parameter(Mandatory = $false)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $false)][int] $TimeoutSeconds = 0
    )
    if ($script:ExecuteOnHost) {
        & $ScriptBlock @ArgumentList
    } elseif ($script:ExecuteOnVM) {
        $Credential = Get-VMCredential -Username 'Administrator' -VMIsRemote $script:VMIsRemote
        Invoke-CommandOnVM -VMName $script:VMName -VMIsRemote $script:VMIsRemote -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -TimeoutSeconds $TimeoutSeconds
    } else {
        throw "Either ExecuteOnHost or ExecuteOnVM must be true."
    }
}

function Invoke-TestOnVM {
    param(
        [Parameter(Mandatory = $true)] [string] $TestName,
        [Parameter(Mandatory = $false)] [string] $TestArgs = "",
        [Parameter(Mandatory = $false)] [string] $InnerTestName = "",
        [Parameter(Mandatory = $false)] [string] $TraceFileName = "",
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs = $false,
        [Parameter(Mandatory = $false)] [int] $TestTimeout = 300,
        [Parameter(Mandatory = $false)] [bool] $SkipTracing = $false,
        [Parameter(Mandatory = $false)] [string] $TracingProfileName = "EbpfForWindows-Networking"
    )
    Write-Log "=== Starting test: $TestName ==="

    $scriptBlock = {
        param($WorkingDirectory, $LogFileName, $TestTimeout, $UserModeDumpFolder, $GranularTracing,
              $TestName, $TestArgs, $InnerTestName, $TraceFileName, $VerboseLogs, $SkipTracing, $TracingProfileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestTimeout, $UserModeDumpFolder, $GranularTracing) -Force -WarningAction SilentlyContinue
        $env:EBPF_ENABLE_WER_REPORT = "yes"
        Push-Location $WorkingDirectory
        $invokeArgs = @{
            TestName        = $TestName
            VerboseLogs     = $VerboseLogs
            TestHangTimeout = $TestTimeout
        }
        if ($TestArgs -ne "")           { $invokeArgs['TestArgs'] = $TestArgs }
        if ($InnerTestName -ne "")      { $invokeArgs['InnerTestName'] = $InnerTestName }
        if ($TraceFileName -ne "")      { $invokeArgs['TraceFileName'] = $TraceFileName }
        if ($SkipTracing)               { $invokeArgs['SkipTracing'] = $true }
        if ($TracingProfileName -ne "") { $invokeArgs['TracingProfileName'] = $TracingProfileName }
        Invoke-Test @invokeArgs
        Pop-Location
    }

    $argList = @(
        $script:WorkingDirectory, $script:LogFileName, $TestTimeout, $script:UserModeDumpFolder, $GranularTracing,
        $TestName, $TestArgs, $InnerTestName, $TraceFileName, $VerboseLogs, $SkipTracing, $TracingProfileName
    )
    # Each test gets its own PS Direct session. The TimeoutSeconds is a safety
    # net beyond the per-test hang timeout (which handles dump generation and
    # WPR trace collection before throwing).
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds ($TestTimeout + 600)
    Write-Log "=== Completed test: $TestName ==="
}

function Generate-KernelDumpOnVM {
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName)
        Import-Module "$WorkingDirectory\common.psm1" -ArgumentList $LogFileName -Force -WarningAction SilentlyContinue -Scope Global
        Import-Module "$WorkingDirectory\run_driver_tests.psm1" -ArgumentList $WorkingDirectory, $LogFileName -Force -WarningAction SilentlyContinue -Scope Global
        Generate-KernelDump
    }
    $argList = @($script:WorkingDirectory, $script:LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Add-eBPFProgram {
    param (
        [Parameter(Mandatory = $true)] [string] $Program,
        [Parameter(Mandatory = $false)] [string] $Interface = "",
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    $scriptBlock = {
        param($Program, $Interface, $WorkingDirectory, $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        if ([System.String]::IsNullOrEmpty($Interface)){
            Write-Log "Loading $Program on $VM."
            $ProgId = Invoke-NetshEbpfCommand -Arguments "add program $WorkingDirectory\$Program"
        } else {
            Write-Log "Loading $Program on interface $Interface on $VM."
            $ProgId = Invoke-NetshEbpfCommand -Arguments "add program $WorkingDirectory\$Program interface=""$Interface"""
        }
        Write-Log "Loaded $Program with $ProgId" -ForegroundColor Green
        return $ProgId
    }
    $argList = @($Program, $Interface, $script:WorkingDirectory, $LogFileName)
    return (Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList)
}

function Set-eBPFProgram {
    param (
        [Parameter(Mandatory = $true)] $ProgId,
        [Parameter(Mandatory = $true)] [string] $Interface,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    $scriptBlock = {
        param($ProgId, $Interface, $WorkingDirectory, $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Write-Log "Setting program $ProgId at interface $Interface."
        Invoke-NetshEbpfCommand -Arguments "set program $ProgId xdp_test interface=""$Interface"""
    }
    $argList = @($ProgId, $Interface, $script:WorkingDirectory, $LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Remove-eBPFProgram {
    param (
        [Parameter(Mandatory = $true)] $ProgId,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    $scriptBlock = {
        param($ProgId, $WorkingDirectory, $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Write-Log "Unloading program $ProgId."
        Invoke-NetshEbpfCommand -Arguments "del program $ProgId"
        return $ProgId
    }
    $argList = @($ProgId, $script:WorkingDirectory, $LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Start-BackgroundProcess{
    param (
        [Parameter(Mandatory = $true)] [string] $ProgramName,
        [Parameter(Mandatory = $true)] [string] $Parameters
    )
    $session = $null
    if ($script:ExecuteOnVM){
        $VmCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $script:VMIsRemote
        $session = New-SessionOnVM -VMName $script:VMName -VMIsRemote $script:VMIsRemote -Credential $VmCredential
    } else {
        $session = New-PSSession -ErrorAction Stop
    }
    $scriptBlock = {
        param($ProgramName, $Parameters, $WorkingDirectory)
        $ProgramName = "$WorkingDirectory\$ProgramName"
        Start-Process -FilePath $ProgramName -ArgumentList $Parameters -PassThru -ErrorAction Stop | Out-Null
    }
    $argList = @($ProgramName, $Parameters, $script:WorkingDirectory)
    Write-Log "Starting $ProgramName with arguments $Parameters in a background session."
    Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $argList -ErrorAction Stop
}

function Stop-BackgroundProcess {
    param (
        [Parameter(Mandatory = $true)] [string] $ProgramName
    )
    $scriptBlock = {
        param($ProgramName)
        $ProgramName = [io.path]::GetFileNameWithoutExtension($ProgramName)
        Stop-Process -Name $ProgramName
    }
    $argList = @($ProgramName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Add-StandardUser {
    param (
        [Parameter(Mandatory = $true)] [string] $UserName,
        [Parameter(Mandatory = $true)] [SecureString] $Password
    )
    $scriptBlock = {
        param($UserName, $Password, $WorkingDirectory, $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Write-Log "Adding standard user $UserName and password $Password"
        # Check if the user already exists, suppressing all output.
        net user $UserName *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "User $UserName already exists. Skipping creation."
            return
        }
        net user $UserName $Password /add *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "User $UserName created successfully."
        } else {
            Write-Log "Failed to create user $UserName with error $LASTEXITCODE"
            throw "Failed to create user $UserName"
        }
    }

    # Convert SecureString to plain text before passing to script block.
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    # Invoke the script block.
    $argList = @($UserName, $PlainPassword, $script:WorkingDirectory, $script:LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Remove-StandardUser {
    param (
        [Parameter(Mandatory = $True)] [string] $UserName
    )
    $scriptBlock = {
        param($UserName)
        Remove-LocalUser -Name $UserName
    }
    $argList = @($UserName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Add-FirewallRule {
    param (
        [Parameter(Mandatory = $True)] [string] $ProgramName,
        [Parameter(Mandatory = $True)] [string] $RuleName,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    $scriptBlock = {
        param($ProgramName, $RuleName, $WorkingDirectory, $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Write-Log "Allowing $ProgramName test app through firewall."
        New-NetFirewallRule -DisplayName $RuleName -Program "$WorkingDirectory\$ProgramName" -Direction Inbound -Action Allow
    }
    $argList = @($ProgramName, $RuleName, $script:WorkingDirectory, $LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Invoke-ConnectRedirectTestHelper
{
    param(
        [Parameter(Mandatory = $true)] $Interfaces,
        [Parameter(Mandatory = $true)] $ConnectRedirectTestConfig,
        [Parameter(Mandatory = $true)][ValidateSet("Administrator", "StandardUser")] $UserType = "Administrator",
        [Parameter(Mandatory = $true)] [string] $LogFileName
    )
    $VM1Interface = $Interfaces[0]
    $VM1V4Address = $VM1Interface.V4Address
    $VM1V6Address = $VM1Interface.V6Address

    $VM2Interface = $Interfaces[1]
    $VM2V4Address = $VM2Interface.V4Address
    $VM2V6Address = $VM2Interface.V6Address

    $VipV4Address = $ConnectRedirectTestConfig.V4VipAddress
    $VipV6Address = $ConnectRedirectTestConfig.V6VipAddress
    $DestinationPort = $ConnectRedirectTestConfig.DestinationPort
    $ProxyPort = $ConnectRedirectTestConfig.ProxyPort

    $ProgramName = "tcp_udp_listener.exe"
    Add-FirewallRule -RuleName "Redirect_Test" -ProgramName $ProgramName -LogFileName $LogFileName

    if ($script:VMIsRemote) {
        $Credential = Get-VMCredential -Username 'Administrator' -VMIsRemote $true
        $Session = New-SessionOnVM -VMName $script:VMName -VMIsRemote $true -Credential $Credential
    }

    # Build array of all IP addresses from all interfaces
    $IPAddresses = @()
    foreach ($Interface in $Interfaces) {
        $IPAddresses += $Interface.V4Address
        $IPAddresses += $Interface.V6Address
    }

    # Start TCP and UDP listeners
    $Ports = @($DestinationPort, $ProxyPort)
    $Protocols = @("tcp", "udp")

    foreach ($IPAddress in $IPAddresses) {
        foreach ($Protocol in $Protocols) {
            foreach ($Port in $Ports) {
                Start-BackgroundProcess -ProgramName $ProgramName -Parameters "--protocol $Protocol --local-port $Port --local-address $IPAddress"
            }
        }
    }

    $InsecurePassword = Get-VMPassword

    $scriptBlock = {
        param($LocalIPv4Address, $LocalIPv6Address, $RemoteIPv4Address, $RemoteIPv6Address, $VirtualIPv4Address, $VirtualIPv6Address, $DestinationPort, $ProxyPort, $StandardUserName, $StandardUserPassword, $UserType, $WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder) -Force -WarningAction SilentlyContinue

        Write-Log "Invoking connect redirect tests [Mode=$UserType]"
        Invoke-ConnectRedirectTest `
            -LocalIPv4Address $LocalIPv4Address `
            -LocalIPv6Address $LocalIPv6Address `
            -RemoteIPv4Address $RemoteIPv4Address `
            -RemoteIPv6Address $RemoteIPv6Address `
            -VirtualIPv4Address $VirtualIPv4Address `
            -VirtualIPv6Address $VirtualIPv6Address `
            -DestinationPort $DestinationPort `
            -ProxyPort $ProxyPort `
            -StandardUserName $StandardUserName `
            -StandardUserPassword $StandardUserPassword `
            -UserType $UserType `
            -WorkingDirectory $WorkingDirectory
        Write-Log "Invoke-ConnectRedirectTest finished"
    }
    $argList = @($VM1V4Address, $VM1V6Address, $VM2V4Address, $VM2V6Address, $VipV4Address, $VipV6Address, $DestinationPort, $ProxyPort, 'VMStandardUser', $InsecurePassword, $UserType, $script:WorkingDirectory, $LogFileName, $script:TestHangTimeout, $script:UserModeDumpFolder)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds ($script:TestHangTimeout + 600)

    Stop-BackgroundProcess -ProgramName $ProgramName
}

function Stop-eBPFComponents {
    param(
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs = $false,
        [Parameter(Mandatory = $false)] [bool] $GranularTracing = $false
    )
    Write-Log "Stopping eBPF components"
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName, $GranularTracing)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Stop-eBPFServiceAndDrivers -GranularTracing $GranularTracing
    }
    $argList = @($script:WorkingDirectory, $script:LogFileName, $GranularTracing)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Run-KernelTests {
    param(
        [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs = $false
    )
    $TestMode = $script:TestMode.ToLower()
    Write-Log "Execute Run-KernelTests (TestMode=$TestMode)"

    switch ($TestMode) {
        { $_ -in "ci/cd", "regression" } {
            # Regular tests - each gets its own PS Direct session.
            Invoke-TestOnVM -TestName "api_test.exe" `
                -TestArgs "~`"load_native_program_invalid4`" ~pinned_map_enum" `
                -TestTimeout 600 -VerboseLogs $VerboseLogs -TraceFileName "api_test.exe"

            Invoke-TestOnVM -TestName "bpftool_tests.exe" `
                -TestArgs "~`"prog load map_in_map`" ~`"prog prog run`"" `
                -VerboseLogs $VerboseLogs -TraceFileName "bpftool_tests.exe"

            Invoke-TestOnVM -TestName "sample_ext_app.exe" `
                -VerboseLogs $VerboseLogs -TraceFileName "sample_ext_app.exe"

            Invoke-TestOnVM -TestName "socket_tests.exe" `
                -TestTimeout 1800 -VerboseLogs $VerboseLogs -TraceFileName "socket_tests.exe"

            # System tests (CI/CD only) - run as SYSTEM via PsExec64.
            if ($_ -eq "ci/cd") {
                $wd = $script:WorkingDirectory
                Invoke-TestOnVM -TestName "PsExec64.exe" `
                    -TestArgs "-accepteula -nobanner -s -w `"$wd`" `"$wd\api_test.exe`" `"-d yes`"" `
                    -InnerTestName "api_test.exe" `
                    -VerboseLogs $VerboseLogs -TraceFileName "api_test.exe_System"
            }

            # Performance smoke test (Release builds only).
            if ($Env:BUILD_CONFIGURATION -eq "Release") {
                Invoke-TestOnVM -TestName "ebpf_performance.exe" `
                    -TestTimeout 600 -VerboseLogs $VerboseLogs -SkipTracing $true
            }
        }

        "stress" {
            $MultiThread = $script:Options -contains "MultiThread"
            $RestartExtension = $script:Options -contains "RestartExtension"
            $RestartEbpfCore = $script:Options -contains "RestartEbpfCore"

            if (-not $MultiThread) {
                $StressDuration = 30 * 60
                Invoke-TestOnVM -TestName "api_test.exe" `
                    -TestArgs "--stress-test-duration $StressDuration ioctl_stress" `
                    -TestTimeout (60 * 60) -VerboseLogs $VerboseLogs `
                    -TracingProfileName "EbpfForWindowsProvider"
            } elseif ($RestartEbpfCore) {
                Invoke-TestOnVM -TestName "ebpf_restart_test_controller.exe" `
                    -TestTimeout (120 * 60) -VerboseLogs $VerboseLogs `
                    -TracingProfileName "EbpfForWindowsProvider"
            } else {
                $StressArgs = if ($RestartExtension) { "-tt=8 -td=5 -erd=1000 -er=1" } else { "-tt=8 -td=5" }
                Invoke-TestOnVM -TestName "ebpf_stress_tests_km.exe" `
                    -TestArgs $StressArgs `
                    -TestTimeout (120 * 60) -VerboseLogs $VerboseLogs `
                    -TracingProfileName "EbpfForWindowsProvider"
            }
        }

        "performance" {
            # Performance test has complex VM-side setup (stop/start services,
            # remove verifier, extract zip). Keep as a single session.
            $scriptBlock = {
                param($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder, $GranularTracing, $VerboseLogs, $CaptureProfile)
                Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
                Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder, $GranularTracing) -Force -WarningAction SilentlyContinue
                Invoke-CICDPerformanceTests -VerboseLogs $VerboseLogs -CaptureProfile $CaptureProfile
            }
            $CaptureProfile = $script:Options -contains "CaptureProfile"
            $argList = @($script:WorkingDirectory, $script:LogFileName, $script:TestHangTimeout, $script:UserModeDumpFolder, $GranularTracing, $VerboseLogs, $CaptureProfile)
            Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds ($script:TestHangTimeout + 600)
        }

        default {
            throw "Invalid test mode: $TestMode"
        }
    }

    Write-Log "Finished kernel tests for mode: $TestMode"

    # XDP and Connect Redirect tests (CI/CD and Regression only).
    if ($TestMode -in "ci/cd", "regression") {
        if ($script:RunXdpTests -eq $true) {
            Write-Log "Running XDP tests"
            Invoke-XDPTests -Interfaces $Config.Interfaces -LogFileName $script:LogFileName
            Write-Log "XDP tests completed"
        }
        Write-Log "Running Connect Redirect tests"
        Invoke-ConnectRedirectTestHelper -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "Administrator" -LogFileName $script:LogFileName
        Add-StandardUser -UserName 'VMStandardUser' -Password (ConvertTo-SecureString -String (Get-VMPassword) -AsPlainText -Force)
        Invoke-ConnectRedirectTestHelper -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "StandardUser" -LogFileName $script:LogFileName
        Write-Log "Connect Redirect tests completed"
    }
}
