# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [Parameter(ParameterSetName = 'VM', Mandatory = $True)] [string] $Admin,
    [Parameter(ParameterSetName = 'VM', Mandatory = $True)] [SecureString] $AdminPassword,
    [Parameter(ParameterSetName = 'VM', Mandatory = $True)] [string] $StandardUser,
    [Parameter(ParameterSetName = 'VM', Mandatory = $True)] [SecureString] $StandardUserPassword,
    [Parameter(ParameterSetName = 'VM', Mandatory = $True)] [string] $VMName,
    [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
    [Parameter(Mandatory = $True)] [string] $LogFileName,
    [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
    [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
    [Parameter(Mandatory = $false)][int] $TestHangTimeout = (10*60),
    [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
    [Parameter(ParameterSetName = 'Host', Mandatory = $true)][switch] $ExecuteOnHost,
    [Parameter(ParameterSetName = 'VM', Mandatory = $true)][switch] $ExecuteOnVM
)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
function Invoke-OnHostOrVM {
    param(
        [Parameter(Mandatory = $true, Position = 0)][ScriptBlock] $ScriptBlock,
        [Parameter(Mandatory = $false)][object[]] $ArgumentList = @()
    )
    if ($script:ExecuteOnHost) {
        & $ScriptBlock @ArgumentList
    } elseif ($script:ExecuteOnVM) {
        $Credential = New-Credential -Username $script:Admin -AdminPassword $script:AdminPassword
        Invoke-Command -VMName $script:VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
    }
}

function Generate-KernelDump {
    param(
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs
    )
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName, $VerboseLogs)
        Import-Module "$WorkingDirectory\common.psm1" -ArgumentList $LogFileName -Force -WarningAction SilentlyContinue
        Import-Module "$WorkingDirectory\run_driver_tests.psm1" -ArgumentList $WorkingDirectory, $LogFileName -Force -WarningAction SilentlyContinue
        Generate-KernelDump
    }
    $argList = @($script:WorkingDirectory, $script:LogFileName, $VerboseLogs)
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
            Write-Log "Loading $Program."
            $ProgId = Invoke-NetshEbpfCommand -Arguments "add program $WorkingDirectory\$Program"
        } else {
            Write-Log "Loading $Program on interface $Interface."
            $ProgId = Invoke-NetshEbpfCommand -Arguments "add program $WorkingDirectory\$Program interface=\"$Interface\""
        }
        Write-Log "Loaded $Program with $ProgId" -ForegroundColor Green
        return $ProgId
    }
    $argList = @($Program, $Interface, $script:WorkingDirectory, $LogFileName)
    return Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
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
        Invoke-NetshEbpfCommand -Arguments "set program $ProgId xdp_test interface=\"$Interface\""
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

function Start-Process {
    param (
        [Parameter(Mandatory = $true)] [string] $ProgramName,
        [string] $Parameters
    )
    $scriptBlock = {
        param($ProgramName, $Parameters, $WorkingDirectory)
        $ProgramName = "$WorkingDirectory\$ProgramName"
        Start-Process -FilePath $ProgramName -ArgumentList $Parameters
    }
    $argList = @($ProgramName, $Parameters, $script:WorkingDirectory)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Stop-Process {
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
        [Parameter(Mandatory = $true)] [string] $Password
    )
    $scriptBlock = {
        param($UserName, $Password)
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        New-LocalUser -Name $UserName -Password $SecurePassword
    }
    $argList = @($UserName, $Password)
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

function Invoke-XDPTest {
    param (
        [Parameter(Mandatory = $True)] [string] $XDPTestName,
        [Parameter(Mandatory = $True)] [string] $RemoteIPV4Address,
        [Parameter(Mandatory = $True)] [string] $RemoteIPV6Address,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    $scriptBlock = {
        param($XDPTestName, $RemoteIPV4Address, $RemoteIPV6Address, $TestHangTimeout, $UserModeDumpFolder, $WorkingDirectory, $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder) -Force -WarningAction SilentlyContinue
        Write-Log "Invoking $XDPTestName"
        Invoke-XDPTest `
            -RemoteIPV4Address $RemoteIPV4Address `
            -RemoteIPV6Address $RemoteIPV6Address `
            -XDPTestName $XDPTestName `
            -WorkingDirectory $WorkingDirectory
    }
    $argList = @($XDPTestName, $RemoteIPV4Address, $RemoteIPV6Address, $script:TestHangTimeout, $script:UserModeDumpFolder, $script:WorkingDirectory, $LogFileName)
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

function Invoke-XDPTest1 {
    param(
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2V6Address,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    Write-Log "Running XDP Test1 ..."
    $ProgId = Add-eBPFProgram -Program "reflect_packet.sys" -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_reflect_test" -RemoteIPV4Address $VM1Interface1V4Address -RemoteIPV6Address $VM1Interface1V6Address -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_reflect_test" -RemoteIPV4Address $VM1Interface2V4Address -RemoteIPV6Address $VM1Interface2V6Address -LogFileName $LogFileName
    Remove-eBPFProgram $ProgId $LogFileName
    Write-Log "XDP Test1 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest2 {
    param(
        [Parameter(Mandatory = $True)] [string] $VM1Interface1Alias,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2Alias,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2V6Address,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    Write-Log "Running XDP Test2 ..."
    $ProgId = Add-eBPFProgram -Program "reflect_packet.sys" -Interface $VM1Interface1Alias -LogFileName $LogFileName
    Set-eBPFProgram -ProgId $ProgId -Interface $VM1Interface2Alias -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_reflect_test" -RemoteIPV4Address $VM1Interface1V4Address -RemoteIPV6Address $VM1Interface1V6Address -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_reflect_test" -RemoteIPV4Address $VM1Interface2V4Address -RemoteIPV6Address $VM1Interface2V6Address -LogFileName $LogFileName
    Remove-eBPFProgram $ProgId $LogFileName
    Write-Log "XDP Test2 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest3 {
    param(
        [Parameter(Mandatory = $True)] [string] $VM1Interface1Alias,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2Alias,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface2V6Address,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    Write-Log "Running XDP Test3 ..."
    $ProgId1 = Add-eBPFProgram -Program "reflect_packet.sys" -Interface $VM1Interface1Alias -LogFileName $LogFileName
    $ProgId2 = Add-eBPFProgram -Program "encap_reflect_packet.sys" -Interface $VM1Interface2Alias -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_reflect_test" -RemoteIPV4Address $VM1Interface1V4Address -RemoteIPV6Address $VM1Interface1V6Address -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_encap_reflect_test" -RemoteIPV4Address $VM1Interface2V4Address -RemoteIPV6Address $VM1Interface2V6Address -LogFileName $LogFileName
    Remove-eBPFProgram $ProgId1 $LogFileName
    Remove-eBPFProgram $ProgId2 $LogFileName
    Write-Log "XDP Test3 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest4 {
    param(
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
        [Parameter(Mandatory = $True)] [string] $VM1Interface1Alias,
        [Parameter(Mandatory = $True)] [string] $VM2Interface1Alias,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    Write-Log "Running XDP Test4 ..."
    $ProgId1 = Add-eBPFProgram -Program "encap_reflect_packet.sys" -Interface $VM1Interface1Alias -LogFileName $LogFileName
    $ProgId2 = Add-eBPFProgram -Program "decap_permit_packet.sys" -Interface $VM2Interface1Alias -LogFileName $LogFileName
    Invoke-XDPTest -XDPTestName "xdp_reflect_test" -RemoteIPV4Address $VM1Interface1V4Address -RemoteIPV6Address $VM1Interface1V6Address -LogFileName $LogFileName
    Remove-eBPFProgram $ProgId1 $LogFileName
    Remove-eBPFProgram $ProgId2 $LogFileName
    Write-Log "XDP Test4 succeeded." -ForegroundColor Green
}

function Invoke-XDPTests {
    param(
        [Parameter(Mandatory = $True)] $Interfaces,
        [Parameter(Mandatory = $True)] [string] $LogFileName
    )
    Write-Log "Starting XDP tests"
    Write-Log "`n`n"
    $VM1Interface1 = $Interfaces[0]
    $VM1Interface1Alias = $VM1Interface1.Alias
    $VM1Interface1V4Address = $VM1Interface1.V4Address
    $VM1Interface1V6Address = $VM1Interface1.V6Address
    $VM2Interface1 = $Interfaces[1]
    $VM2Interface1Alias = $VM2Interface1.Alias
    $VM1Interface2 = $Interfaces[2]
    $VM1Interface2Alias = $VM1Interface2.Alias
    $VM1Interface2V4Address = $VM1Interface2.V4Address
    $VM1Interface2V6Address = $VM1Interface2.V6Address
    Add-FirewallRule -RuleName "XDP_Test" -ProgramName "xdp_tests.exe" -LogFileName $LogFileName
    Invoke-XDPTest1 -VM1Interface1V4Address $VM1Interface1V4Address -VM1Interface1V6Address $VM1Interface1V6Address -VM1Interface2V4Address $VM1Interface2V4Address -VM1Interface2V6Address $VM1Interface2V6Address -LogFileName $LogFileName
    Invoke-XDPTest2 -VM1Interface1Alias $VM1Interface1Alias -VM1Interface2Alias $VM1Interface2Alias -VM1Interface1V4Address $VM1Interface1V4Address -VM1Interface1V6Address $VM1Interface1V6Address -VM1Interface2V4Address $VM1Interface2V4Address -VM1Interface2V6Address $VM1Interface2V6Address -LogFileName $LogFileName
    Invoke-XDPTest3 -VM1Interface1Alias $VM1Interface1Alias -VM1Interface2Alias $VM1Interface2Alias -VM1Interface1V4Address $VM1Interface1V4Address -VM1Interface1V6Address $VM1Interface1V6Address -VM1Interface2V4Address $VM1Interface2V4Address -VM1Interface2V6Address $VM1Interface2V6Address -LogFileName $LogFileName
    Invoke-XDPTest4 -VM1Interface1V4Address $VM1Interface1V4Address -VM1Interface1V6Address $VM1Interface1V6Address -VM1Interface1Alias $VM1Interface1Alias -VM2Interface1Alias $VM2Interface1Alias -LogFileName $LogFileName
}

function Invoke-ConnectRedirectTests
{
    param(
        [Parameter(Mandatory = $true)] $Interfaces,
        [Parameter(Mandatory = $true] $ConnectRedirectTestConfig,
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
    $TcpServerParameters = "--protocol tcp --local-port $DestinationPort"
    $TcpProxyParameters = "--protocol tcp --local-port $ProxyPort"
    $UdpServerParameters = "--protocol udp --local-port $DestinationPort"
    $UdpProxyParameters = "--protocol udp --local-port $ProxyPort"

    $ParamaterArray = @($TcpServerParameters, $TcpProxyParameters, $UdpServerParameters, $UdpProxyParameters)
    Add-FirewallRule -RuleName "Redirect_Test" -ProgramName $ProgramName -LogFileName $LogFileName

    # Start TCP and UDP listeners on both the VMs.
    foreach ($param in $ParamaterArray)
    {
        Start-Process -ProgramName $ProgramName -Parameters $param
    }

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($($script:StandardUserPassword))
    $InsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    $scriptBlock = {
        param($LocalIPv4Address, $LocalIPv6Address, $RemoteIPv4Address, $RemoteIPv6Address, $VirtualIPv4Address, $VirtualIPv6Address, $DestinationPort, $ProxyPort, $StandardUserName, $StandardUserPassword, $UserType, $WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder)
        Import-Module $script:WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $script:WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($script:WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder) -Force -WarningAction SilentlyContinue

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

    Stop-Process -ProgramName $ProgramName

    # Remove standard user on VM1.
    Remove-StandardUser -UserName $script:StandardUser
}

function Stop-eBPFComponents {
    param(
        [Parameter(Mandatory = $false)] [bool] $VerboseLogs = $false,
        [Parameter(Mandatory = $true)] [string] $LogFileName
    )
    Write-Log "Stopping eBPF components"
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName)
        Import-Module $script:WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $script:WorkingDirectory\install_ebpf.psm1 -ArgumentList ($script:WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Stop-eBPFComponents
    }
    $argList = @($script:WorkingDirectory, $LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
}

function Run-KernelTests {
    param(
        [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
        [Parameter(Mandatory = $true)] [string] $LogFileName
    )
    $scriptBlock = {
        param($VerboseLogs, $TestMode, $TestHangTimeout, $UserModeDumpFolder, $Options, $LogFileName)
        Import-Module $script:WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $script:WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($script:WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder) -Force -WarningAction SilentlyContinue
        $TestMode = $TestMode.ToLower()
        switch ($TestMode) {
            "ci/cd" {
                Write-Log "Running CI/CD tests"
                Invoke-CICDTests -VerboseLogs $false -ExecuteSystemTests $true
            }
            "regression" {
                Write-Log "Running regression tests"
                Invoke-CICDTests -VerboseLogs $false -ExecuteSystemTests $false
            }
            "stress" {
                Write-Log "Running stress tests"
                $RestartExtension = $Options -contains "RestartExtension"
                Invoke-CICDStressTests -VerboseLogs $false -RestartExtension $RestartExtension
            }
            "performance" {
                Write-Log "Running performance tests"
                $CaptureProfile = $Options -contains "CaptureProfile"
                Invoke-CICDPerformanceTests -VerboseLogs $false -CaptureProfile $CaptureProfile
            }
            default {
                throw "Invalid test mode: $TestMode"
            }
        }
    }
    $argList = @($script:VerboseLogs, $script:TestMode, $script:TestHangTimeout, $script:UserModeDumpFolder, $script:Options, $LogFileName)
    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList $argList
    if (($script:TestMode -eq "CI/CD") -or ($script:TestMode -eq "Regression")) {
        Invoke-XDPTests -Interfaces $Config.Interfaces -LogFileName $LogFileName
        Invoke-ConnectRedirectTests -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "Administrator" -LogFileName $LogFileName
        Invoke-ConnectRedirectTests -Interfaces $Config.Interfaces -ConnectRedirectTestConfig $Config.ConnectRedirectTest -UserType "StandardUser" -LogFileName $LogFileName
    }
}
