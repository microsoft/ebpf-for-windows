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
    $TestCred = New-Credentials -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCred -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName,
              [Parameter(Mandatory=$True)] [bool] $VerboseLogs)
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName)  -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\run_tests.psm1 -ArgumentList ($WorkingDirectory, $LogFileName)  -Force  -WarningAction SilentlyContinue
        Invoke-CICDTests -VerboseLogs $VerboseLogs 2>&1 | Write-Log
    } -ArgumentList ("C:\eBPF", ("{0}_{1}" -f $VMName, $LogFileName), $VerboseLogs) -ErrorAction Stop
}

Pop-Location