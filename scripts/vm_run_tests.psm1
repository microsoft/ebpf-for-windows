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
    param(
        [Parameter(Mandatory = $false)][int] $TimeoutSeconds = 300
    )
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName)
        Import-Module "$WorkingDirectory\common.psm1" -ArgumentList $LogFileName -Force -WarningAction SilentlyContinue -Scope Global
        Import-Module "$WorkingDirectory\run_driver_tests.psm1" -ArgumentList $WorkingDirectory, $LogFileName -Force -WarningAction SilentlyContinue -Scope Global
        Generate-KernelDump
    }
    $argList = @($script:WorkingDirectory, $script:LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds $TimeoutSeconds
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
    return (Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 120)
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
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 120
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
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 120
}

function Start-BackgroundListeners {
    param (
        [Parameter(Mandatory = $true)] [string] $ProgramName,
        [Parameter(Mandatory = $true)] [string[]] $IPAddresses,
        [Parameter(Mandatory = $true)] [string[]] $Protocols,
        [Parameter(Mandatory = $true)] [int[]] $Ports
    )
    # Start all listeners in a single remote call instead of creating a
    # separate PS Direct session per listener.  The old approach leaked
    # wsmprovhost.exe host processes that kept the CI step alive forever.
    #
    # Serialize arrays as pipe-delimited strings to avoid PowerShell
    # array-flattening when passing through Invoke-Command -ArgumentList.
    $ipStr = $IPAddresses -join '|'
    $protoStr = $Protocols -join '|'
    $portStr = ($Ports | ForEach-Object { $_.ToString() }) -join '|'

    $scriptBlock = {
        param($ProgramName, $IpStr, $ProtoStr, $PortStr, $WorkingDirectory)
        $ProgramPath = "$WorkingDirectory\$ProgramName"
        foreach ($IP in ($IpStr -split '\|')) {
            foreach ($Proto in ($ProtoStr -split '\|')) {
                foreach ($Port in ($PortStr -split '\|')) {
                    Start-Process -FilePath $ProgramPath -ArgumentList "--protocol $Proto --local-port $Port --local-address $IP" -ErrorAction Stop | Out-Null
                }
            }
        }
    }
    $count = $IPAddresses.Count * $Protocols.Count * $Ports.Count
    Write-Log "Starting $count $ProgramName listeners ($($IPAddresses.Count) IPs x $($Protocols.Count) protocols x $($Ports.Count) ports)."
    $argList = @($ProgramName, $ipStr, $protoStr, $portStr, $script:WorkingDirectory)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 120
}

function Stop-BackgroundListeners {
    param (
        [Parameter(Mandatory = $true)] [string] $ProgramName
    )
    $scriptBlock = {
        param($ProgramName)
        $ProgramName = [io.path]::GetFileNameWithoutExtension($ProgramName)
        Stop-Process -Name $ProgramName -Force -ErrorAction SilentlyContinue
    }
    $argList = @($ProgramName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 60
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
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 120
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
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 60
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
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 120
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

    # Build array of all IP addresses from all interfaces.
    $IPAddresses = @()
    foreach ($Interface in $Interfaces) {
        $IPAddresses += $Interface.V4Address
        $IPAddresses += $Interface.V6Address
    }

    # Start all TCP and UDP listeners in a single remote call.
    $Ports = @($DestinationPort, $ProxyPort)
    $Protocols = @("tcp", "udp")
    Start-BackgroundListeners -ProgramName $ProgramName -IPAddresses $IPAddresses -Protocols $Protocols -Ports $Ports

    # Wrap the test in try/finally so listeners are always cleaned up,
    # even when the test throws.  Abandoned listeners were the root cause
    # of CI steps spinning forever (orphaned host-side session processes).
    try {
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
    } finally {
        try {
            Stop-BackgroundListeners -ProgramName $ProgramName
        } catch {
            Write-Log "Warning: Failed to stop background listeners: $($_.Exception.Message)"
        }
    }
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
    # Use a bounded timeout so a wedged VM doesn't block the caller indefinitely.
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds 300
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
            # All tests run in a SINGLE PS Direct session to avoid repeated
            # session open/close cycles.  The worker process architecture
            # (execute_test_worker.ps1) already handles timeout enforcement.
            $scriptBlock = {
                param($WorkingDirectory, $VerboseLogs, $TestMode, $TestHangTimeout, $UserModeDumpFolder, $Options, $LogFileName, $GranularTracing)
                Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
                Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder, $GranularTracing) -Force -WarningAction SilentlyContinue
                $ExecuteSystemTests = ($TestMode -eq "ci/cd")
                Invoke-CICDTests -VerboseLogs $VerboseLogs -ExecuteSystemTests $ExecuteSystemTests
            }
            $argList = @(
                $script:WorkingDirectory, $VerboseLogs, $TestMode,
                $script:TestHangTimeout, $script:UserModeDumpFolder,
                $script:Options, $script:LogFileName, $GranularTracing
            )
            # Timeout = 2x TestHangTimeout to allow normal multi-test execution
            # plus one test hitting the per-test timeout before the inner
            # exception propagates.
            Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds ($script:TestHangTimeout * 2)
        }

        "stress" {
            $MultiThread = $script:Options -contains "MultiThread"
            $RestartExtension = $script:Options -contains "RestartExtension"
            $RestartEbpfCore = $script:Options -contains "RestartEbpfCore"

            # Single PS Direct session for the entire stress test.
            $scriptBlock = {
                param($WorkingDirectory, $VerboseLogs, $TestHangTimeout, $UserModeDumpFolder, $LogFileName, $GranularTracing, $MultiThread, $RestartExtension, $RestartEbpfCore)
                Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
                Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder, $GranularTracing) -Force -WarningAction SilentlyContinue
                Invoke-CICDStressTests -VerboseLogs $VerboseLogs -MultiThread $MultiThread -RestartExtension $RestartExtension -RestartEbpfCore $RestartEbpfCore
            }
            $argList = @(
                $script:WorkingDirectory, $VerboseLogs,
                $script:TestHangTimeout, $script:UserModeDumpFolder,
                $script:LogFileName, $GranularTracing,
                $MultiThread, $RestartExtension, $RestartEbpfCore
            )
            # Stress tests set their own inner per-binary timeout (up to 120 min
            # for MT and restart variants).  The PS Direct session must stay alive
            # for longer than the max inner timeout.  Use the larger of 2x the
            # module-level TestHangTimeout and 150 minutes (inner max + buffer).
            $stressSessionTimeout = [Math]::Max($script:TestHangTimeout * 2, 150 * 60)
            Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -TimeoutSeconds $stressSessionTimeout
        }

        "performance" {
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
        # Build SecureString via .NET directly -- ConvertTo-SecureString requires
        # the Microsoft.PowerShell.Security module which fails to load on ARM64.
        $plainPwd = Get-VMPassword
        $securePwd = [System.Security.SecureString]::new()
        foreach ($c in $plainPwd.ToCharArray()) { $securePwd.AppendChar($c) }
        Add-StandardUser -UserName 'VMStandardUser' -Password $securePwd
        Invoke-ConnectRedirectTestHelper -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "StandardUser" -LogFileName $script:LogFileName
        Write-Log "Connect Redirect tests completed"
    }
}
