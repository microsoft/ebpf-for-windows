﻿# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\install_ebpf.psm1 -Force -ArgumentList ($WorkingDirectory, $LogFileName) -WarningAction SilentlyContinue

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
    param([Parameter(Mandatory=$True)][string] $TestName,
          [Parameter(Mandatory=$True)][bool] $VerboseLogs,
          [Parameter(Mandatory=$False)][bool] $Coverage)

    Write-Log "Executing $Testname"

    $LASTEXITCODE = 0

    $OriginalTestName = $TestName
    $ArgumentsList = @()

    if ($Coverage) {
        $ArgumentsList += @('--export_type', ('binary:' + $TestName + '.cov'), '--', $TestName)
        $TestName = 'OpenCppCoverage'
    }
    # Execute Test.
    if ($VerboseLogs -eq $true) {
        $ArgumentsList += '-s'
    }

    $Output = &$TestName $ArgumentsList
    $TestName = $OriginalTestName

    # Check for errors.
    Out-String -InputObject $Output | Write-Log
    $ParsedOutput = $Output.Split(" ")
    if (($LASTEXITCODE -ne 0) -or ($ParsedOutput[$ParsedOutput.Length -2] -eq "failed")) { throw ("$TestName Test Failed.") }

    Write-Log "$TestName Passed" -ForegroundColor Green
}

function Invoke-CICDTests
{
    param([parameter(Mandatory = $true)][bool] $VerboseLogs,
          [parameter(Mandatory = $false)][bool] $Coverage = $false)

    pushd $WorkingDirectory

    try {
        if ($Coverage) {
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            choco install -y --requirechecksum=true --checksum=2295A733DA39412C61E4F478677519DD0BB1893D88313CE56B468C9E50517888 --checksum-type=sha256 OpenCppCoverage
            if (!$env:PATH.Contains('C:\Program Files\OpenCppCoverage\')) {
                $env:PATH += 'C:\Program Files\OpenCppCoverage\;'
            }
        }
        $TestList = @(
            "ebpf_client.exe",
            "api_test.exe",
            "sample_ext_app.exe")

        foreach ($Test in $TestList) {
            Invoke-Test -TestName $Test -VerboseLogs $VerboseLogs -Coverage $Coverage
        }

        if ($Coverage) {
            # Combine code coverage reports
            $ArgumentsList += @()
            foreach ($Test in $TestList) {
                $ArgumentsList += @('--input_coverage', ($Test + '.cov'))
            }
            $ArgumentsList += @('--export_type', 'cobertura:ebpf_for_windows.xml', '--')
            $Output = &OpenCppCoverage $ArgumentsList
            Out-String -InputObject $Output | Write-Log
        }

        if ($Env:BUILD_CONFIGURATION -eq "Release") {
            Invoke-Test -TestName "ebpf_performance.exe" -VerboseLogs $VerboseLogs
        }
    }
    catch {
        Write-Log "One or more tests failed."
        throw
    }

    popd
}

function Invoke-XDPTest
{
    param([parameter(Mandatory=$true)][string] $RemoteIPV4Address,
          [parameter(Mandatory=$true)][string] $RemoteIPV6Address,
          [parameter(Mandatory=$true)][string] $XDPTestName,
          [parameter(Mandatory=$true)][string] $WorkingDirectory)

    pushd $WorkingDirectory

    Write-Log "Executing $XDPTestName with remote address: $RemoteIPV4Address."
    $LASTEXITCODE = 0
    $Output = .\xdp_tests.exe $XDPTestName --remote-ip $RemoteIPV4Address
    Out-String -InputObject $Output | Write-Log
    $ParsedOutput = $Output.Split(" ")
    if (($LASTEXITCODE -ne 0) -or ($ParsedOutput[$ParsedOutput.Length -2] -eq "failed")) { throw ("$XDPTestName Test Failed.") }

    Write-Log "Executing $XDPTestName with remote address: $RemoteIPV6Address."
    $LASTEXITCODE = 0
    $Output = .\xdp_tests.exe $XDPTestName --remote-ip $RemoteIPV6Address
    Out-String -InputObject $Output | Write-Log
    $ParsedOutput = $Output.Split(" ")
    if (($LASTEXITCODE -ne 0) -or ($ParsedOutput[$ParsedOutput.Length -2] -eq "failed")) { throw ("$XDPTestName Test Failed.") }

    Write-Log "$XDPTestName Test Passed" -ForegroundColor Green

    popd
}

Pop-Location