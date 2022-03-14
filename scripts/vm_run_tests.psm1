﻿# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $Admin,
       [Parameter(Mandatory=$True)] [SecureString] $AdminPassword,
       [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

#
# Execute tests on VM.
#

function Invoke-CICDTestsOnVM
{
    param([parameter(Mandatory=$true)] [string] $VMName,
          [parameter(Mandatory=$false)] [bool] $VerboseLogs = $false)
    Write-Log "Running eBPF CI/CD tests on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName,
              [Parameter(Mandatory=$True)] [bool] $VerboseLogs)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Invoke-CICDTests -VerboseLogs $VerboseLogs 2>&1 | Write-Log
    } -ArgumentList ("C:\eBPF", ("{0}_{1}" -f $VMName, $LogFileName), $VerboseLogs) -ErrorAction Stop
}

function Add-eBPFProgramOnVM
{
    param ([parameter(Mandatory=$true)] [string] $VM,
           [parameter(Mandatory=$true)] [string] $Program,
           [string] $Interface,
           [Parameter(Mandatory=$True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Load program on VM.
    $ProgId = Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $VM,
              [parameter(Mandatory=$true)] [string] $Program,
              [string] $Interface,
              [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            Import-Module $WorkingDirectory\run_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

            if ([System.String]::IsNullOrEmpty($Interface)){
                Write-Log "Loading $Program on $VM."
                $ProgId = Invoke-NetshEbpfCommand -Arguments "add program $WorkingDirectory\$Program"
            } else {
                Write-Log "Loading $Program on interface $Interface on $VM."
                $ProgId = Invoke-NetshEbpfCommand -Arguments "add program $WorkingDirectory\$Program interface=""$Interface"""
            }
            Write-Log "Loaded $Program with $ProgId" -ForegroundColor Green
            return $ProgId
    } -ArgumentList ($VM, $Program, $Interface, "C:\eBPF", ("{0}_{1}" -f $VM, $LogFileName)) -ErrorAction Stop

    return $ProgId
}

function Set-eBPFProgramOnVM
{
    param ([parameter(Mandatory=$true)] [string] $VM,
           [parameter(Mandatory=$true)] $ProgId,
           [parameter(Mandatory=$true)] [string] $Interface,
           [Parameter(Mandatory=$True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Set program on VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $VM,
              [parameter(Mandatory=$true)] $ProgId,
              [parameter(Mandatory=$true)] [string] $Interface,
              [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            Import-Module $WorkingDirectory\run_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
            Write-Log "Setting program $ProgId at interface $Interface on $VM."
            Invoke-NetshEbpfCommand -Arguments "set program $ProgId xdp interface=""$Interface"""
    } -ArgumentList ($VM, $ProgId, $Interface, "C:\eBPF", ("{0}_{1}" -f $VM, $LogFileName)) -ErrorAction Stop
}
function Remove-eBPFProgramFromVM
{
    param ([parameter(Mandatory=$true)] [string] $VM,
           [parameter(Mandatory=$true)] $ProgId,
           [Parameter(Mandatory=$True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Unload program from VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $VM,
              [Parameter(Mandatory=$True)] $ProgId,
              [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            Import-Module $WorkingDirectory\run_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
            Write-Log "Unloading program $ProgId from $VM."
            Invoke-NetshEbpfCommand -Arguments "del program $ProgId"
            return $ProgId
    } -ArgumentList ($VM, $ProgId, "C:\eBPF", ("{0}_{1}" -f $VM, $LogFileName)) -ErrorAction Stop
}

function Invoke-XDPTestOnVM
{
    param ([parameter(Mandatory=$true)] [string] $VM,
           [parameter(Mandatory=$true)] [string] $XDPTestName,
           [Parameter(Mandatory=$True)] [string] $RemoteIPV4Address,
           [Parameter(Mandatory=$True)] [string] $RemoteIPV6Address,
           [Parameter(Mandatory=$True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $VM,
              [parameter(Mandatory=$true)] [string] $XDPTestName,
              [Parameter(Mandatory=$True)] [string] $RemoteIPV4Address,
              [Parameter(Mandatory=$True)] [string] $RemoteIPV6Address,
              [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            Import-Module $WorkingDirectory\run_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
            Write-Log "Invoking $XDPTestName on $VM"
            Invoke-XDPTest $RemoteIPV4Address $RemoteIPV6Address $XDPTestName $WorkingDirectory
    } -ArgumentList ($VM, $XDPTestName, $RemoteIPV4Address, $RemoteIPV6Address, "C:\eBPF", ("{0}_{1}" -f $VM, $LogFileName)) -ErrorAction Stop
}

function Add-XDPTestFirewallRuleOnVM {
    param ([parameter(Mandatory=$true)] [string] $VM,
           [Parameter(Mandatory=$True)] [string] $LogFileName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    # Allow XDP Test in Firewwall on VM.
    Invoke-Command -VMName $VM -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $VM,
              [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            Write-Log "Allowing XDP test app through firewall on $VM."
            New-NetFirewallRule -DisplayName "XDP_Test" -Program "$WorkingDirectory\xdp_tests.exe" -Direction Inbound -Action Allow
    } -ArgumentList ($VM, "C:\eBPF", ("{0}_{1}" -f $VM, $LogFileName)) -ErrorAction Stop
}

function Invoke-XDPTest1
{
    param([Parameter(Mandatory=$True)] [string] $VM1,
          [Parameter(Mandatory=$True)] [string] $VM2,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2V6Address,
          [Parameter(Mandatory=$True)] [string] $LogFileName)

    Write-Log "Running XDP Test1 ..."

    # Load reflect_packet without specifying interface on VM1.
    $ProgId = Add-eBPFProgramOnVM -VM $VM1 -Program "reflect_packet.o" -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting both interfaces of VM1.
    Invoke-XDPTestOnVM $VM2 "xdp_reflect_test" $VM1Interface1V4Address $VM1Interface1V6Address $LogFileName
    Invoke-XDPTestOnVM $VM2 "xdp_reflect_test" $VM1Interface2V4Address $VM1Interface2V6Address $LogFileName

    # Unload program from VM1.
    Remove-eBPFProgramFromVM $VM1 $ProgId $LogFileName

    Write-Log "XDP Test1 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest2
{
    param([Parameter(Mandatory=$True)] [string] $VM1,
          [Parameter(Mandatory=$True)] [string] $VM2,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1Alias,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2Alias,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2V6Address,
          [Parameter(Mandatory=$True)] [string] $LogFileName)

    Write-Log "Running XDP Test2 ..."

    # Load reflect_packet on interface1 on VM1.
    $ProgId = Add-eBPFProgramOnVM -VM $VM1 -Program "reflect_packet.o" -Interface $VM1Interface1Alias -LogFileName $LogFileName

    # Attach the program on interface2 on VM1.
    Set-eBPFProgramOnVM -VM $VM1 -ProgId $ProgId -Interface $VM1Interface2Alias -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting both interfaces of VM1.
    Invoke-XDPTestOnVM $VM2 "xdp_reflect_test" $VM1Interface1V4Address $VM1Interface1V6Address $LogFileName
    Invoke-XDPTestOnVM $VM2 "xdp_reflect_test" $VM1Interface2V4Address $VM1Interface2V6Address $LogFileName

    # Unload program from VM1.
    Remove-eBPFProgramFromVM $VM1 $ProgId $LogFileName

    Write-Log "XDP Test2 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest3
{
    param([Parameter(Mandatory=$True)] [string] $VM1,
          [Parameter(Mandatory=$True)] [string] $VM2,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1Alias,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2Alias,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface2V6Address,
          [Parameter(Mandatory=$True)] [string] $LogFileName)

    Write-Log "Running XDP Test3 ..."

    # Load reflect_packet on interface1 of VM1.
    $ProgId1 = Add-eBPFProgramOnVM -VM $VM1 -Program "reflect_packet.o" -Interface $VM1Interface1Alias -LogFileName $LogFileName

    # Load encap_reflact_packet on interface2 on VM1.
    $ProgId2 = Add-eBPFProgramOnVM -VM $VM1 -Program "encap_reflect_packet.o" -Interface $VM1Interface2Alias -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting first interface of VM1.
    Invoke-XDPTestOnVM $VM2 "xdp_reflect_test" $VM1Interface1V4Address $VM1Interface1V6Address $LogFileName

    # Run XDP encap reflect test from VM2 targeting second interface of VM1.
    Invoke-XDPTestOnVM $VM2 "xdp_encap_reflect_test" $VM1Interface2V4Address $VM1Interface2V6Address $LogFileName

    # Unload programs from VM1.
    Remove-eBPFProgramFromVM $VM1 $ProgId1 $LogFileName
    Remove-eBPFProgramFromVM $VM1 $ProgId2 $LogFileName

    Write-Log "XDP Test3 succeeded." -ForegroundColor Green
}

function Invoke-XDPTest4
{
    param([Parameter(Mandatory=$True)] [string] $VM1,
          [Parameter(Mandatory=$True)] [string] $VM2,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V4Address,
          [Parameter(Mandatory=$True)] [string] $VM1Interface1V6Address,
          [Parameter(Mandatory=$True)] [string] $LogFileName)

    Write-Log "Running XDP Test4 ..."

    # Load encap_reflect_packet on VM1.
    $ProgId1 = Add-eBPFProgramOnVM -VM $VM1 -Program "encap_reflect_packet.o" -LogFileName $LogFileName

    # Load decap_permit_packet on VM2.
    $ProgId2 = Add-eBPFProgramOnVM -VM $VM2 -Program "decap_permit_packet.o" -LogFileName $LogFileName

    # Run XDP reflect test from VM2 targeting first interface of VM1.
    Invoke-XDPTestOnVM $VM2 "xdp_reflect_test" $VM1Interface1V4Address $VM1Interface1V6Address $LogFileName

    # Unload program from VM1.
    Remove-eBPFProgramFromVM $VM1 $ProgId1 $LogFileName
    # Unload program from VM2.
    Remove-eBPFProgramFromVM $VM2 $ProgId2 $LogFileName

    Write-Log "XDP Test4 succeeded." -ForegroundColor Green
}

function Invoke-XDPTestsOnVM
{
    param([parameter(Mandatory=$true)] $MultiVMTestConfig)

    $VM1 = $MultiVMTestConfig[0]
    $VM1Interface1 = $VM1.Interfaces[0]
    $VM1Interface1Alias = $VM1Interface1.Alias
    $VM1Interface1V4Address = $VM1Interface1.V4Address
    $VM1Interface1V6Address = $VM1Interface1.V6Address
    $VM1Interface2 = $VM1.Interfaces[1]
    $VM1Interface2Alias = $VM1Interface2.Alias
    $VM1Interface2V4Address = $VM1Interface2.V4Address
    $VM1Interface2V6Address = $VM1Interface2.V6Address

    $VM2 = $MultiVMTestConfig[1]

    Add-XDPTestFirewallRuleOnVM $VM2.Name $LogFileName
    Invoke-XDPTest1 $VM1.Name $VM2.Name $VM1Interface1V4Address $VM1Interface1V6Address $VM1Interface2V4Address $VM1Interface2V6Address $LogFileName
    Invoke-XDPTest2 $VM1.Name $VM2.Name $VM1Interface1Alias $VM1Interface2Alias $VM1Interface1V4Address $VM1Interface1V6Address $VM1Interface2V4Address $VM1Interface2V6Address $LogFileName
    Invoke-XDPTest3 $VM1.Name $VM2.Name $VM1Interface1Alias $VM1Interface2Alias $VM1Interface1V4Address $VM1Interface1V6Address $VM1Interface2V4Address $VM1Interface2V6Address $LogFileName
    Invoke-XDPTest4 $VM1.Name $VM2.Name $VM1Interface1V4Address $VM1Interface1V6Address $LogFileName
}

function Stop-eBPFComponentsOnVM
{
    param([parameter(Mandatory=$true)] [string] $VMName,
          [parameter(Mandatory=$false)] [bool] $VerboseLogs = $false)
    # Stop the components, so that Driver Verifier can catch memory leaks etc.
    Write-Log "Stopping eBPF components on $VMName"

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue
        Stop-eBPFComponents
    } -ArgumentList ("C:\eBPF", ("{0}_{1}" -f $VMName, $LogFileName)) -ErrorAction Stop
}

Pop-Location
