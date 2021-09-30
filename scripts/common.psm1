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

function New-Credentials
{
    param([Parameter(Mandatory=$True)][string] $Username,
          [Parameter(Mandatory=$True)][SecureString] $AdminPassword)

    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList  @($Username, $AdminPassword)
    return $Credentials
}
