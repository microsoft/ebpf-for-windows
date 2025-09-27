# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory = $True)][bool] $ExecuteOnHost = $false,
    # The following parameters are only used when ExecuteOnVM is true
    [Parameter(Mandatory = $True)][bool] $ExecuteOnVM = $false,
    [Parameter(Mandatory = $false)][bool] $VMIsRemote = $false,
    [Parameter(Mandatory = $True)] [string] $VMName,
    [Parameter(Mandatory = $True)] [string] $Admin,
    [Parameter(Mandatory = $True)] [SecureString] $AdminPassword,
    [Parameter(Mandatory = $True)] [string] $StandardUser,
    [Parameter(Mandatory = $True)] [SecureString] $StandardUserPassword,
    # The following are shared parameters for both ExecuteOnHost and ExecuteOnVM
    [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
    [Parameter(Mandatory = $True)] [string] $LogFileName,
    [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
    [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
    [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30*60),
    [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
    # Granular tracing parameters (passed through to run_driver_tests.psm1)
    [Parameter(Mandatory = $false)][bool] $GranularTracing = $false,
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
        [Parameter(Mandatory = $false)][System.Management.Automation.Runspaces.PSSession] $Session
    )
    if ($script:ExecuteOnHost) {
        & $ScriptBlock @ArgumentList
    } elseif ($script:ExecuteOnVM) {
        $Credential = New-Credential -Username $script:Admin -AdminPassword $script:AdminPassword
        if ($script:VMIsRemote) {
            if ($null -ne $Session) {
                Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
            } else {
                Invoke-Command -ComputerName $script:VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
            }
        } else {
            Invoke-Command -VMName $script:VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
    } else {
        throw "Either ExecuteOnHost or ExecuteOnVM must be true."
    }
}

function Generate-KernelDumpOnVM {
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName)
        Import-Module "$WorkingDirectory\common.psm1" -ArgumentList $LogFileName -Force -WarningAction SilentlyContinue
        Import-Module "$WorkingDirectory\run_driver_tests.psm1" -ArgumentList $WorkingDirectory, $LogFileName -Force -WarningAction SilentlyContinue
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

function Start-ProcessHelper {
    param (
        [Parameter(Mandatory = $true)] [string] $ProgramName,
        [string] $Parameters,
        [Parameter(Mandatory = $false)][System.Management.Automation.Runspaces.PSSession] $Session
    )
    $scriptBlock = {
        param($ProgramName, $Parameters, $WorkingDirectory)
        $ProgramName = "$WorkingDirectory\$ProgramName"
        Start-Process -FilePath $ProgramName -ArgumentList $Parameters
    }
    $argList = @($ProgramName, $Parameters, $script:WorkingDirectory)
    Write-Log "Starting process $ProgramName with arguments $Parameters"
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList -Session $Session
}

function Stop-ProcessHelper {
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
        $Credential = New-Credential -Username $script:Admin -AdminPassword $script:AdminPassword
        $Session = New-PSSession -ComputerName $script:VMName -Credential $Credential
    }

    if ($script:TestMode -eq "Regression") {
        # Previous versions of tcp_udp_listener did not suport the local_address parameter, use old parameter sets.
        $TcpServerParameters = "--protocol tcp --local-port $DestinationPort"
        $TcpProxyParameters = "--protocol tcp --local-port $ProxyPort"
        $UdpServerParameters = "--protocol udp --local-port $DestinationPort"
        $UdpProxyParameters = "--protocol udp --local-port $ProxyPort"

        $ParameterArray = @($TcpServerParameters, $TcpProxyParameters, $UdpServerParameters, $UdpProxyParameters)
        foreach ($parameter in $ParameterArray)
        {
            Start-ProcessHelper -ProgramName $ProgramName -Parameters $parameter -Session $Session
        }
    } else {
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
                    Start-ProcessHelper -ProgramName $ProgramName -Parameters "--protocol $Protocol --local-port $Port --local-address $IPAddress" -Session $Session
                }
            }
        }
    }

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($($script:StandardUserPassword))
    $InsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

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
    $argList = @($VM1V4Address, $VM1V6Address, $VM2V4Address, $VM2V6Address, $VipV4Address, $VipV6Address, $DestinationPort, $ProxyPort, $script:StandardUser, $InsecurePassword, $UserType, $script:WorkingDirectory, $LogFileName, $script:TestHangTimeout, $script:UserModeDumpFolder)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList

    Stop-ProcessHelper -ProgramName $ProgramName

    if ($null -ne $Session)
    {
        Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    }
}

function Stop-eBPFComponents {
    param(
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs = $false,
        [Parameter(Mandatory = $true)] [string] $LogFileName,
        [Parameter(Mandatory = $false)] [bool] $GranularTracing = $false
    )
    Write-Log "Stopping eBPF components"
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName, $GranularTracing)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Stop-eBPFComponents -GranularTracing $GranularTracing
    }
    $argList = @($script:WorkingDirectory, $LogFileName, $GranularTracing)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Run-KernelTests {
    param(
        [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs = $false
    )
    Write-Log "Execute Run-KernelTests"
    $scriptBlock = {
        param($WorkingDirectory, $VerboseLogs, $TestMode, $TestHangTimeout, $UserModeDumpFolder, $Options, $LogFileName, $GranularTracing)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder, $GranularTracing) -Force -WarningAction SilentlyContinue
        $TestMode = $TestMode.ToLower()
        switch ($TestMode) {
            "ci/cd" {
                Invoke-CICDTests `
                    -VerboseLogs $VerboseLogs `
                    -ExecuteSystemTests $true `
                    2>&1 | Write-Log
            }
            "regression" {
                Invoke-CICDTests `
                    -VerboseLogs $VerboseLogs `
                    -ExecuteSystemTests $false `
                    2>&1 | Write-Log
            }
            "stress" {
                # Set RestartExtension to true if options contains that string.
                $RestartExtension = $Options -contains "RestartExtension"
                Invoke-CICDStressTests `
                    -VerboseLogs $VerboseLogs `
                    -RestartExtension $RestartExtension `
                    2>&1 | Write-Log
            }
            "performance" {
                # Set CaptureProfle to true if options contains that string.
                $CaptureProfile = $Options -contains "CaptureProfile"
                Invoke-CICDPerformanceTests -VerboseLogs $VerboseLogs -CaptureProfile $CaptureProfile 2>&1 | Write-Log
            }
            default {
                throw "Invalid test mode: $TestMode"
            }
        }
    }
    $argList = @($script:WorkingDirectory, $VerboseLogs, $script:TestMode, $script:TestHangTimeout, $script:UserModeDumpFolder, $script:Options, $script:LogFileName, $GranularTracing)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
    Write-Log "Finished Invoke-OnHostOrVM for Run-KernelTests"

    if (($script:TestMode -eq "CI/CD") -or ($script:TestMode -eq "Regression")) {
        Write-Log "Running Connect Redirect tests"
        Invoke-ConnectRedirectTestHelper -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "Administrator" -LogFileName $script:LogFileName
        Add-StandardUser -UserName $script:StandardUser -Password $script:StandardUserPassword
        Invoke-ConnectRedirectTestHelper -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "StandardUser" -LogFileName $script:LogFileName
        Write-Log "Connect Redirect tests completed"
    }
}
