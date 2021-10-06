# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([parameter(Mandatory=$True)] [string] $LogFileName)


#
# Common helper functions.
#

function Write-Log
{
    [CmdletBinding()]
    param([parameter(Mandatory=$False, ValueFromPipeline=$true)]$TraceMessage=$null,
          [parameter(Mandatory=$False)]$ForegroundColor = [System.ConsoleColor]::White)

    process
    {
        if (($null -ne $TraceMessage) -and ![System.String]::IsNullOrEmpty($TraceMessage)) {
            $timestamp = (Get-Date).ToString('HH:mm:ss')
            Write-Host "[$timestamp] :: $TraceMessage"-ForegroundColor $ForegroundColor
            Write-Output "[$timestamp] :: $TraceMessage" | Out-File "$PSScriptRoot\$LogFileName" -Append
        }
    }
}

function New-Credential
{
    param([Parameter(Mandatory=$True)][string] $UserName,
          [Parameter(Mandatory=$True)][SecureString] $AdminPassword)

    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList  @($UserName, $AdminPassword)
    return $Credential
}
