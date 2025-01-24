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

<#
.SYNOPSIS
    Helper function to create a directory if it does not already exist.

.DESCRIPTION
    This function checks if a directory exists at the specified path. If it does not exist, it creates the directory.

.PARAMETER Path
    The path of the directory to create.

.EXAMPLE
    Create-DirectoryIfNotExists -Path "C:\MyDirectory"
#>
function Create-DirectoryIfNotExists {
    param (
        [Parameter(Mandatory=$True)][string]$Path
    )

    try {
        if (-not (Test-Path -Path $Path -PathType Container)) {
            New-Item -Path $Path -ItemType Directory -Force # -ErrorAction Ignore | Out-Null
        }

        if (-not (Test-Path -PathType Container $Path)) {
            throw "Failed to create directory: $Path"
        }
    } catch {
        throw "Failed to create directory: $Path with error $_"
    }
}

<#
.SYNOPSIS
    Helper function to replace placeholder strings in a file.

.DESCRIPTION
    This function replaces all occurrences of a specified search string with a replacement string in a file.

.PARAMETER FilePath
    The path to the file in which to replace the placeholder strings.

.PARAMETER SearchString
    The string to search for in the file.

.PARAMETER ReplaceString
    The string to replace the search string with.

.EXAMPLE
    Replace-PlaceholderStrings -FilePath "C:\MyFile.txt" -SearchString "PLACEHOLDER" -ReplaceString "ActualValue"
#>
function Replace-PlaceholderStrings {
    param (
        [Parameter(Mandatory=$True)][string]$FilePath,
        [Parameter(Mandatory=$True)][string]$SearchString,
        [Parameter(Mandatory=$True)][string]$ReplaceString
    )

    try {
        $content = Get-Content -Path $FilePath
        $content = $content -replace $SearchString, $ReplaceString
        Set-Content -Path $FilePath -Value $content
    } catch {
        throw "Failed to replace placeholder strings in file: $FilePath. Error: $_"
    }
}

<#
.SYNOPSIS
    Imports the CredentialManager, and installs it if necessary.

.DESCRIPTION
    This function imports the CredentialManager module and installs it if it is not already installed. It also ensures that any dependencies are installed.
#>
function Get-CredentialManager {
    # Import the CredentialManager module. Ensure any dependencies are installed.
    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop *> $null 2>&1
    Import-PackageProvider -Name NuGet -Force -ErrorAction Stop *> $null 2>&1
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        Install-Module -Name CredentialManager -Force -ErrorAction Stop *> $null 2>&1
    }
    Import-Module CredentialManager -ErrorAction Stop
}

<#
.SYNOPSIS
    Generates a strong password using the credential manager.

.DESCRIPTION
    This function generates a strong password using the CredentialManager module.

.OUTPUTS
    [String]
    The generated strong password.
#>
function New-UniquePassword {
    Get-CredentialManager
    return Get-StrongPassword
}

<#
.SYNOPSIS
    Retrieves a credential from the Windows Credential Manager using PsExec.

.PARAMETER PsExecPath
    The path to the PsExec executable.

.PARAMETER Target
    The name of the stored credential. Default is "MyStoredCredential".

.DESCRIPTION
    This function uses PsExec to run a PowerShell script in the LocalSystem account context to retrieve a credential from the Windows Credential Manager.

.EXAMPLE
    $credential = Retrieve-StoredCredential -PsExecPath "C:\Path\To\PsExec.exe" -Target "MyStoredCredential"
#>
function Retrieve-StoredCredential {
    param (
        [Parameter(Mandatory=$True)][string]$PsExecPath,
        [Parameter(Mandatory=$True)][string]$Target
    )
    $Script = @"
        Import-Module CredentialManager -ErrorAction Stop;
        `$Credential = Get-StoredCredential -Target '$Target';
        `$UserName = `$Credential.UserName;
        `$Password = `$Credential.GetNetworkCredential().Password;
        \"`$UserName`n`$Password\"
"@

    $outputFile = [System.IO.Path]::GetTempFileName()
    $errorFile = [System.IO.Path]::GetTempFileName()

    try {
        $process = Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula -nobanner -s powershell.exe -command `"$Script`"" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
        $output = Get-Content $outputFile
        $error = Get-Content $errorFile

        if ($process.ExitCode -ne 0) {
            throw "PsExec failed with exit code $($process.ExitCode). Error: $error"
        }

        $lines = $output -split "`n"
        $Username = $lines[0].Trim()
        $Password = ConvertTo-SecureString -String $lines[1].Trim() -AsPlainText -Force
        return [System.Management.Automation.PSCredential]::new($Username, $Password)
    } catch {
        throw "An error occurred while retrieving the credential: $_"
    } finally {
        if (Test-Path $outputFile) { Remove-Item $outputFile }
        if (Test-Path $errorFile) { Remove-Item $errorFile }
    }
}

<#
.SYNOPSIS
    Stores a credential in the Windows Credential Manager using PsExec.

.PARAMETER PsExecPath
    The path to the PsExec executable.

.PARAMETER Username
    The username for the credential.

.PARAMETER Password
    The password for the credential as a secure string.

.PARAMETER Target
    The name of the stored credential. Default is "MyStoredCredential".

.DESCRIPTION
    This function uses PsExec to run a PowerShell script in the LocalSystem account context to store a credential in the Windows Credential Manager.

.EXAMPLE
    $securePassword = ConvertTo-SecureString "YourPassword" -AsPlainText -Force
    $credential = Generate-NewCredential -Username "YourUsername" -Password $securePassword -Target "MyStoredCredential" -PsExecPath "C:\Path\To\PsExec.exe"
#>
function Generate-NewCredential {
    param (
        [Parameter(Mandatory=$True)][string]$Username,
        [Parameter(Mandatory=$True)][string]$Password,
        [Parameter(Mandatory=$True)][string]$Target,
        [Parameter(Mandatory=$True)][string]$PsExecPath
    )
    Get-CredentialManager

    Write-Host "Password: $Password"
    $Script = @"
        Import-Module CredentialManager -ErrorAction Stop;
        New-StoredCredential -Target '$Target' -UserName '$Username' -Password '$Password';
"@

    $outputFile = [System.IO.Path]::GetTempFileName()
    $errorFile = [System.IO.Path]::GetTempFileName()

    try {
        $process = Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula -nobanner -s powershell.exe -command `"$Script`"" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
        $output = Get-Content $outputFile
        $error = Get-Content $errorFile

        if ($process.ExitCode -ne 0) {
            throw "PsExec failed with exit code $($process.ExitCode). Error: $error"
        }

        # Use the Retrieve-StoredCredential function to verify that the credential was stored correctly.
        return (Retrieve-StoredCredential -PsExecPath $PsExecPath -Target $Target)
    } catch {
        throw "An error occurred while storing the credential: $_"
    } finally {
        if (Test-Path $outputFile) { Remove-Item $outputFile }
        if (Test-Path $errorFile) { Remove-Item $errorFile }
    }
}
