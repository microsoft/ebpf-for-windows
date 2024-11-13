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

function Wait-TestJobToComplete
{
    param([Parameter(Mandatory = $true)] [System.Management.Automation.Job] $Job,
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [Parameter(Mandatory = $true)] [int] $TestJobTimeout,
           [Parameter(Mandatory = $true)] [string] $CheckpointPrefix)
    $TimeElapsed = 0
    # Loop to fetch and print job output in near real-time
    while ($Job.State -eq 'Running') {
        $JobOutput = Receive-Job -Job $job
        $JobOutput | ForEach-Object { Write-Host $_ }

        Start-Sleep -Seconds 2
        $TimeElapsed += 2

        if ($TimeElapsed -gt $TestJobTimeout) {
            if ($Job.State -eq "Running") {
                $VMList = $Config.VMMap.$SelfHostedRunnerName
                # currently one VM runs per runner.
                $TestVMName = $VMList[0].Name
                Write-Host "Running kernel tests on $TestVMName has timed out after one hour" -ForegroundColor Yellow
                $Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
                $CheckpointName = "$CheckpointPrefix-$TestVMName-Checkpoint-$Timestamp"
                Write-Log "Taking snapshot $CheckpointName of $TestVMName"
                Checkpoint-VM -Name $TestVMName -SnapshotName $CheckpointName
                $JobTimedOut = $true
                break
            }
        }
    }

    # Print any remaining output after the job completes
    $JobOutput = Receive-Job -Job $job
    $JobOutput | ForEach-Object { Write-Host $_ }

    return $JobTimedOut
}

function Create-VMCredential {
    param (
        [Parameter(Mandatory=$True)][string]$VmUsername,
        [Parameter(Mandatory=$True)][string]$VmPassword
    )

    try {
        $secureVmPassword = ConvertTo-SecureString $VmPassword -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential($VmUsername, $secureVmPassword)
    } catch {
        throw "Failed to create VM credential: $_"
    }
}
