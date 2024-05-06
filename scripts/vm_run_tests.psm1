# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory = $True)] [string] $Admin,
       [Parameter(Mandatory = $True)] [SecureString] $AdminPassword,
       [Parameter(Mandatory = $True)] [string] $StandardUser,
       [Parameter(Mandatory = $True)] [SecureString] $StandardUserPassword,
       [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
       [Parameter(Mandatory = $True)] [string] $LogFileName,
       [parameter(Mandatory = $false)][int] $TestHangTimeout = 3600,
       [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps")

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

#
# Execute tests on VM.
#
function Invoke-CICDTestsOnVM
{
    param([parameter(Mandatory = $True)] [string] $VMName,
          [parameter(Mandatory = $False)] [bool] $VerboseLogs = $false,
          [parameter(Mandatory = $False)] [bool] $Coverage = $false,
          [parameter(Mandatory = $False)][string] $TestMode = "CI/CD",
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps",
          [parameter(Mandatory = $False)][string[]] $Options = @())

    Write-Log "Running eBPF $TestMode tests on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName,
              [Parameter(Mandatory = $True)] [bool] $VerboseLogs,
              [Parameter(Mandatory = $True)] [bool] $Coverage,
              [parameter(Mandatory = $True)][string] $TestMode,
              [parameter(Mandatory = $true)][int] $TestHangTimeout,
              [parameter(Mandatory = $true)][string] $UserModeDumpFolder,
              [parameter(Mandatory = $True)][string[]] $Options)

        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        $TestMode = $TestMode.ToLower()
        switch ($TestMode)
        {
            "ci/cd" {
                Invoke-CICDTests `
                    -VerboseLogs $VerboseLogs `
                    -Coverage $Coverage `
                    -TestHangTimeout $TestHangTimeout `
                    -UserModeDumpFolder $UserModeDumpFolder `
                    2>&1 | Write-Log
            }
            "stress" {
                # Set RestartExtension to true if options contains that string
                $RestartExtension = $Options -contains "RestartExtension"
                Invoke-CICDStressTests `
                    -VerboseLogs $VerboseLogs `
                    -Coverage $Coverage `
                    -RestartExtension $RestartExtension `
                    -TestHangTimeout $TestHangTimeout `
                    -UserModeDumpFolder $UserModeDumpFolder `
                    2>&1 | Write-Log
            }
            "performance" {
                # Set CaptureProfle to true if options contains that string
                $CaptureProfile = $Options -contains "CaptureProfile"
                Invoke-CICDPerformanceTests -VerboseLogs $VerboseLogs -CaptureProfile $CaptureProfile 2>&1 | Write-Log
            }
            default {
                throw "Invalid test mode: $TestMode"
            }
        }

    } -ArgumentList(
            "eBPF",
            $LogFileName,
            $VerboseLogs,
            $Coverage,
            $TestMode,
            $TestHangTimeout,
            $UserModeDumpFolder,
            $Options) -ErrorAction Stop
}

function Add-eBPFProgramOnVM
{
    param ([parameter(Mandatory = $true)] [string] $VM,
           [parameter(Mandatory = $true)] [string] $Program,
           [string] $Interface,
           [Parameter(Mandatory = $True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Load program on VM.
    $ProgId = Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $VM,
              [parameter(Mandatory = $true)] [string] $Program,
              [string] $Interface,
              [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName)
        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
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
    } -ArgumentList ($VM, $Program, $Interface, "eBPF", $LogFileName) -ErrorAction Stop

    return $ProgId
}

function Set-eBPFProgramOnVM
{
    param ([parameter(Mandatory = $true)] [string] $VM,
           [parameter(Mandatory = $true)] $ProgId,
           [parameter(Mandatory = $true)] [string] $Interface,
           [Parameter(Mandatory = $True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Set program on VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $VM,
              [parameter(Mandatory = $true)] $ProgId,
              [parameter(Mandatory = $true)] [string] $Interface,
              [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName)
        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Write-Log "Setting program $ProgId at interface $Interface on $VM."
        Invoke-NetshEbpfCommand -Arguments "set program $ProgId xdp_test interface=""$Interface"""
    } -ArgumentList ($VM, $ProgId, $Interface, "eBPF", $LogFileName) -ErrorAction Stop
}
function Remove-eBPFProgramFromVM
{
    param ([parameter(Mandatory = $true)] [string] $VM,
           [parameter(Mandatory = $true)] $ProgId,
           [Parameter(Mandatory = $True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Unload program from VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $VM,
              [Parameter(Mandatory = $True)] $ProgId,
              [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName)
        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Write-Log "Unloading program $ProgId from $VM."
        Invoke-NetshEbpfCommand -Arguments "del program $ProgId"
        return $ProgId
    } -ArgumentList ($VM, $ProgId, "eBPF", $LogFileName) -ErrorAction Stop
}

function Start-ProcessOnVM
{
    param ([parameter(Mandatory = $true)] [string] $VM,
           [parameter(Mandatory = $true)] [string] $ProgramName,
           [string] $Parameters)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Start process on VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory= $True)] [string] $VM,
              [parameter(Mandatory= $true)] [string] $ProgramName,
              [string] $Parameters,
              [Parameter(Mandatory = $True)] [string] $WorkingDirectory)

        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        $ProgramName = "$WorkingDirectory\$ProgramName"

        Start-Process -FilePath $ProgramName -ArgumentList $Parameters
    } -ArgumentList ($VM, $ProgramName, $Parameters, "eBPF") -ErrorAction Stop
}

function Stop-ProcessOnVM
{
    param ([parameter(Mandatory = $true)] [string] $VM,
           [parameter(Mandatory = $true)] [string] $ProgramName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Stop process on VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $VM,
              [parameter(Mandatory = $true)] [string] $ProgramName)

        $ProgramName = [io.path]::GetFileNameWithoutExtension($ProgramName)
        Stop-Process -Name $ProgramName
    } -ArgumentList ($VM, $ProgramName) -ErrorAction Stop
}

function Add-StandardUserOnVM
{
    param ([parameter(Mandatory = $true)] [string] $VM,
           [parameter(Mandatory = $true)] [string] $UserName,
           [parameter(Mandatory = $true)] [string] $Password)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Create standard user.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([parameter(Mandatory = $true)] [string] $UserName,
              [parameter(Mandatory = $true)] [string] $Password)

        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        New-LocalUser -Name $UserName -Password $SecurePassword
    } -ArgumentList ($UserName, $Password) -ErrorAction Stop
}

function Remove-StandardUserOnVM
{
    param ([parameter(Mandatory = $True)] [string] $VM,
           [parameter(Mandatory = $True)] [string] $UserName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([parameter(Mandatory = $true)] [string] $UserName)

        Remove-LocalUser -Name $UserName
    } -ArgumentList ($UserName, $Password) -ErrorAction Stop
}

function Invoke-XDPTestOnVM
{
    param ([parameter(Mandatory = $True)] [string] $VM,
           [parameter(Mandatory = $True)] [string] $XDPTestName,
           [Parameter(Mandatory = $True)] [string] $RemoteIPV4Address,
           [Parameter(Mandatory = $True)] [string] $RemoteIPV6Address,
           [Parameter(Mandatory = $True)] [string] $LogFileName,
           [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
           [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $VM,
              [parameter(Mandatory = $true)] [string] $XDPTestName,
              [Parameter(Mandatory = $True)] [string] $RemoteIPV4Address,
              [Parameter(Mandatory = $True)] [string] $RemoteIPV6Address,
              [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName,
              [parameter(Mandatory = $True)][int] $TestHangTimeout,
              [parameter(Mandatory = $True)][string] $UserModeDumpFolder)


        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Write-Log "Invoking $XDPTestName on $VM"
        Invoke-XDPTest `
            -RemoteIPV4Address $RemoteIPV4Address `
            -RemoteIPV6Address $RemoteIPV6Address `
            -XDPTestName $XDPTestName `
            -WorkingDirectory $WorkingDirectory `
            -TestHangTimeout $TestHangTimeout `
            -UserModeDumpFolder $UserModeDumpFolder

    } -ArgumentList (
        $VM,
        $XDPTestName,
        $RemoteIPV4Address,
        $RemoteIPV6Address,
        "eBPF",
        $LogFileName,
        $TestHangTimeout,
        $UserModeDumpFolder) -ErrorAction Stop
}

function Add-FirewallRuleOnVM {
    param ([parameter(Mandatory = $True)] [string] $VM,
           [parameter(Mandatory = $True)] [string] $ProgramName,
           [parameter(Mandatory = $True)] [string] $RuleName,
           [Parameter(Mandatory = $True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Allow XDP Test in Firewwall on VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $VM,
              [Parameter(Mandatory = $True)] [string] $ProgramName,
              [Parameter(Mandatory = $True)] [string] $RuleName,
              [Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName)
        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

        Write-Log "Allowing $ProgramName test app through firewall on $VM."
        New-NetFirewallRule -DisplayName $RuleName -Program "$WorkingDirectory\$ProgramName" -Direction Inbound -Action Allow
    } -ArgumentList ($VM, $ProgramName, $RuleName, "eBPF", $LogFileName) -ErrorAction Stop
}

function Invoke-XDPTest1
{
    param([Parameter(Mandatory = $True)] [string] $VM,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2V6Address,
          [Parameter(Mandatory = $True)] [string] $LogFileName,
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")

    Write-Log "Running XDP Test1 on $VM ..."

    # Load reflect_packet without specifying interface on VM1.
    $ProgId = Add-eBPFProgramOnVM -VM $VM -Program "reflect_packet.sys" -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting both interfaces of VM1.
    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_reflect_test" `
        -RemoteIPV4Address $VM1Interface1V4Address `
        -RemoteIPV6Address $VM1Interface1V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_reflect_test" `
        -RemoteIPV4Address $VM1Interface2V4Address `
        -RemoteIPV6Address $VM1Interface2V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    # Unload program from VM.
    Remove-eBPFProgramFromVM $VM $ProgId $LogFileName

    Write-Log "XDP Test1 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest2
{
    param([Parameter(Mandatory = $True)] [string] $VM,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1Alias,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2Alias,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2V6Address,
          [Parameter(Mandatory = $True)] [string] $LogFileName,
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")

    Write-Log "Running XDP Test2 ..."

    # Load reflect_packet on interface1 on VM1.
    $ProgId = Add-eBPFProgramOnVM -VM $VM -Program "reflect_packet.sys" -Interface $VM1Interface1Alias -LogFileName $LogFileName

    # Attach the program on interface2 on VM1.
    Set-eBPFProgramOnVM -VM $VM -ProgId $ProgId -Interface $VM1Interface2Alias -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting both interfaces of VM1.
    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_reflect_test" `
        -RemoteIPV4Address $VM1Interface1V4Address `
        -RemoteIPV6Address $VM1Interface1V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_reflect_test" `
        -RemoteIPV4Address $VM1Interface2V4Address `
        -RemoteIPV6Address $VM1Interface2V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    # Unload program from VM1.
    Remove-eBPFProgramFromVM $VM $ProgId $LogFileName

    Write-Log "XDP Test2 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest3
{
    param([Parameter(Mandatory = $True)] [string] $VM,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1Alias,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2Alias,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface2V6Address,
          [Parameter(Mandatory = $True)] [string] $LogFileName,
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")


    Write-Log "Running XDP Test3 ..."

    # Load reflect_packet on interface1 of VM1.
    $ProgId1 = Add-eBPFProgramOnVM -VM $VM -Program "reflect_packet.sys" -Interface $VM1Interface1Alias -LogFileName $LogFileName

    # Load encap_reflact_packet on interface2 on VM1.
    $ProgId2 = Add-eBPFProgramOnVM -VM $VM -Program "encap_reflect_packet.sys" -Interface $VM1Interface2Alias -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting first interface of VM1.
    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_reflect_test" `
        -RemoteIPV4Address $VM1Interface1V4Address `
        -RemoteIPV6Address $VM1Interface1V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    # Run XDP encap reflect test from VM2 targeting second interface of VM1.
    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_encap_reflect_test" `
        -RemoteIPV4Address $VM1Interface2V4Address `
        -RemoteIPV6Address $VM1Interface2V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    # Unload programs from VM1.
    Remove-eBPFProgramFromVM $VM $ProgId1 $LogFileName
    Remove-eBPFProgramFromVM $VM $ProgId2 $LogFileName

    Write-Log "XDP Test3 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest4
{
    param([Parameter(Mandatory = $True)] [string] $VM,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory = $True)] [string] $VM1Interface1Alias,
          [Parameter(Mandatory = $True)] [string] $VM2Interface1Alias,
          [Parameter(Mandatory = $True)] [string] $LogFileName,
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")

    Write-Log "Running XDP Test4 ..."

    # Load encap_reflect_packet on VM1.
    $ProgId1 = Add-eBPFProgramOnVM -VM $VM -Program "encap_reflect_packet.sys" -Interface $VM1Interface1Alias -LogFileName $LogFileName

    # Load decap_permit_packet on VM2.
    $ProgId2 = Add-eBPFProgramOnVM -VM $VM -Program "decap_permit_packet.sys" -Interface $VM2Interface1Alias -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting first interface of VM1.
    Invoke-XDPTestOnVM `
        -VM $VM `
        -XDPTestName "xdp_reflect_test" `
        -RemoteIPV4Address $VM1Interface1V4Address `
        -RemoteIPV6Address $VM1Interface1V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    # Unload program from VM1.
    Remove-eBPFProgramFromVM $VM $ProgId1 $LogFileName
    # Unload program from VM1.
    Remove-eBPFProgramFromVM $VM $ProgId2 $LogFileName

    Write-Log "XDP Test4 succeeded." -ForegroundColor Green
}

function Invoke-XDPTestsOnVM
{
    param([parameter(Mandatory = $True)] $Interfaces,
          [parameter(Mandatory = $True)] [string] $VMName,
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")

    # NIC pairs are duo1-duo2 and duo3-duo4.
    # VM1 is interfaces duo1 and duo3.
    # VM2 is interfaces duo2 and duo4.

    Write-Log "Starting XDP tests on $VMName"
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
    $VM1Interface3V6Address = $VM1Interface2.V6Address

    Add-FirewallRuleOnVM -VM $VMName -RuleName "XDP_Test" -ProgramName "xdp_tests.exe" -LogFileName $LogFileName
    Invoke-XDPTest1 `
        -VM $VMName `
        -VM1Interface1V4Address $VM1Interface1V4Address `
        -VM1Interface1V6Address $VM1Interface1V6Address `
        -VM1Interface2V4Address $VM1Interface2V4Address `
        -VM1Interface2V6Address $VM1Interface3V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    Invoke-XDPTest2 `
        -VM $VMName `
        -VM1Interface1Alias $VM1Interface1Alias `
        -VM1Interface2Alias $VM1Interface2Alias `
        -VM1Interface1V4Address $VM1Interface1V4Address `
        -VM1Interface1V6Address $VM1Interface1V6Address `
        -VM1Interface2V4Address $VM1Interface2V4Address `
        -VM1Interface2V6Address $VM1Interface3V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    Invoke-XDPTest3 `
        -VM $VMName `
        -VM1Interface1Alias $VM1Interface1Alias `
        -VM1Interface2Alias $VM1Interface2Alias `
        -VM1Interface1V4Address $VM1Interface1V4Address `
        -VM1Interface1V6Address $VM1Interface1V6Address `
        -VM1Interface2V4Address $VM1Interface2V4Address `
        -VM1Interface2V6Address $VM1Interface3V6Address `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder

    Invoke-XDPTest4 `
        -VM $VMName `
        -VM1Interface1V4Address $VM1Interface1V4Address `
        -VM1Interface1V6Address $VM1Interface1V6Address `
        -VM1Interface1Alias $VM1Interface1Alias `
        -VM2Interface1Alias $VM2Interface1Alias `
        -LogFileName $LogFileName `
        -TestHangTimeout $TestHangTimeout `
        -UserModeDumpFolder $UserModeDumpFolder
}

function Invoke-ConnectRedirectTestsOnVM
{
    param([parameter(Mandatory = $true)] $Interfaces,
          [parameter(Mandatory = $true)] $ConnectRedirectTestConfig,
          [parameter(Mandatory = $true)][ValidateSet("Administrator", "StandardUser")] $UserType = "Administrator",
          [parameter(Mandatory = $true)] [string] $VMName,
          [parameter(Mandatory = $False)][int] $TestHangTimeout = 3600,
          [parameter(Mandatory = $False)][string] $UserModeDumpFolder = "C:\Dumps")

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
    $VMArray = @($VMName)

    Add-FirewallRuleOnVM -VM $VMName -RuleName "Redirect_Test" -ProgramName $ProgramName -LogFileName $LogFileName

    # Start TCP and UDP listeners on both the VMs.
    foreach ($vm in $VMArray)
    {
        foreach ($param in $ParamaterArray)
        {
            Start-ProcessOnVM -VM $vm -ProgramName $ProgramName -Parameters $param
        }
    }

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($($StandardUserPassword))
    $InsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # First remove the existing StandardUser account (if found). This can happen if the previous test run terminated
    # abnormally before performing the requisite post-test-run clean-up.
    $UserId = Invoke-Command -VMName $VMName -Credential $TestCredential `
           -ScriptBlock {param ($StandardUser) Get-LocalUser -Name "$StandardUser"} `
           -Argumentlist $StandardUser -ErrorAction SilentlyContinue
    if($UserId) {
        Write-Host "Deleting existing standard user:" $StandardUser "on" $VMName
        Remove-StandardUserOnVM -VM $VMName -UserName $StandardUser
    }

    # Add a standard user on VM1.
    Add-StandardUserOnVM -VM $VMName -UserName $StandardUser -Password $InsecurePassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)][string] $VM,
              [parameter(Mandatory = $true)][string] $LocalIPv4Address,
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
              [Parameter(Mandatory = $true)][string] $LogFileName,
              [parameter(Mandatory = $false)][int] $TestHangTimeout,
              [parameter(Mandatory = $false)][string] $UserModeDumpFolder)

        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_driver_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Write-Log "Invoking connect redirect tests [Mode=$UserType] on $VM"
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
            -WorkingDirectory $WorkingDirectory `
            -TestHangTimeout $TestHangTimeout `
            -UserModeDumpFolder $UserModeDumpFolder
        Write-Log "Invoke-ConnectRedirectTest finished on $VM"

    } -ArgumentList (
        $VMName,
        $VM1V4Address,
        $VM1V6Address,
        $VM2V4Address,
        $VM2V6Address,
        $VipV4Address,
        $VipV6Address,
        $DestinationPort,
        $ProxyPort,
        $StandardUser,
        $InsecurePassword,
        $UserType,
        "eBPF",
        $LogFileName,
        $TestHangTimeout,
        $UserModeDumpFolder) -ErrorAction Stop
    Stop-ProcessOnVM -VM $VMName -ProgramName $ProgramName

    # Remove standard user on VM1.
    Remove-StandardUserOnVM -VM $VMName -UserName $StandardUser
}

function Stop-eBPFComponentsOnVM
{
    param([parameter(Mandatory = $true)] [string] $VMName,
          [parameter(Mandatory = $false)] [bool] $VerboseLogs = $false)
    # Stop the components, so that Driver Verifier can catch memory leaks etc.
    Write-Log "Stopping eBPF components on $VMName"

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory = $True)] [string] $WorkingDirectory,
              [Parameter(Mandatory = $True)] [string] $LogFileName)
        $WorkingDirectory = "$Env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Stop-eBPFComponents
    } -ArgumentList ("eBPF", $LogFileName) -ErrorAction Stop
}

Pop-Location
