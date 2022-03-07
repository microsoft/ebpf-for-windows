# Copyright (c) Microsoft Corporation
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

function Invoke-XDPTests
{
    param([parameter(Mandatory=$true)] $MultiVMTestConfig)

    $VM1 = $MultiVMTestConfig[0].Name
    $VM1V4Address = $MultiVMTestConfig[0].V4Address
    $VM1V6Address = $MultiVMTestConfig[0].V6Address
    $VM2 = $MultiVMTestConfig[1].Name
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Write-Log "Loading encap_reflect_packet program on $VM1"

    Invoke-Command -VMName $VM1 -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            netsh ebpf add program $WorkingDirectory\encap_reflect_packet.o Pinpath=path1 2>&1 | Write-Log
    } -ArgumentList ("C:\eBPF", ("{0}_{1}" -f $VM1, $LogFileName)) -ErrorAction Stop

    # Run XDP Tests on VM2
    Invoke-Command -VMName $VM2 -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName,
              [Parameter(Mandatory=$True)] [string] $RemoteIPV4Address,
              [Parameter(Mandatory=$True)] [string] $RemoteIPV6Address)
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
            pushd $WorkingDirectory
            Write-Log "Loading decap proggram."
            netsh ebpf add program .\decap_permit_packet.o Pinpath=path1 2>&1 | Write-Log
            Write-Log "Allowing XDP test app through firewall."
            New-NetFirewallRule -DisplayName "XDP_Test" -Program "$WorkingDirectory\xdp_tests.exe" -Direction Inbound -Action Allow
            Write-Log "Invoking xdp reflect test (IPv4)."
            .\xdp_tests.exe xdp_reflect_test --remote-ip $RemoteIPV4Address | Write-Log
            Write-Log "Invoking xdp reflect test (IPv6)."
            .\xdp_tests.exe xdp_reflect_test --remote-ip $RemoteIPV6Address | Write-Log
            Write-Log "xdp reflect tests passed." -ForegroundColor Green
            popd
    } -ArgumentList ("C:\eBPF", ("{0}_{1}" -f $VM1, $LogFileName), $VM1V4Address, $VM1V6Address) -ErrorAction Stop
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