# Copyright (c) eBPF for Windows contributors
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
            Write-Output "[$timestamp] :: $TraceMessage" | Out-File "$env:TEMP\$LogFileName" -Append
        }
    }
}

function ThrowWithErrorMessage
{
    Param(
        [Parameter(Mandatory = $True)] [string] $ErrorMessage
    )

    Write-Log $ErrorMessage -ForegroundColor Red
    Start-Sleep -Milliseconds 100
    throw $ErrorMessage
}

function New-Credential
{
    param([Parameter(Mandatory=$True)][string] $UserName,
          [Parameter(Mandatory=$True)][SecureString] $AdminPassword)

    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList  @($UserName, $AdminPassword)
    return $Credential
}


function Compress-File
{
    param ([Parameter(Mandatory = $True)] [string] $SourcePath,
           [Parameter(Mandatory = $True)] [string] $DestinationPath
    )

    Write-Log "Compressing $SourcePath -> $DestinationPath"

    # Retry 3 times to ensure compression operation succeeds.
    # To mitigate error message: "The process cannot access the file <filename> because it is being used by another process."
    $retryCount = 1
    while ($retryCount -lt 4) {
        $error.clear()
        Compress-Archive `
            -Path $SourcePath `
            -DestinationPath $DestinationPath `
            -CompressionLevel Fastest `
            -Force
        if ($error[0] -ne $null) {
            $ErrorMessage = "*** ERROR *** Failed to compress kernel mode dump files: $error. Retrying $retryCount"
            Write-Output $ErrorMessage
            Start-Sleep -seconds (5 * $retryCount)
            $retryCount++
        } else {
            # Compression succeeded.
            break;
        }
    }
}