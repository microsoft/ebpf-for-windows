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

#
# Retrieves the secret from Azure Key Vault.
# Returns a PSCredential object, where the username is the secret name and the password is the retrieved secret.
#
function Get-AzureKeyVaultCredential
{
    param([Parameter(Mandatory=$False)][string] $KeyVaultName='ebpf-cicd-key-vault',
          [Parameter(Mandatory=$True)][string] $SecretName)

    try {
        # # Check if the Az module is installed, if not, install it
        # if (-not (Get-Module -ListAvailable -Name Az)) {
        #     Install-Module -Name Az -AllowClobber -Force
        # }

        # Authenticate using the managed identity
        Connect-AzAccount -Identity

        # Retrieve the secret from Key Vault
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName

        # The SecretName is the username and the secret value is the password
        # Write-Host "Successfully retrieved secret from Azure Key Vault. KeyVaultName: $KeyVaultName SecretName: $SecretName"
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList  @($SecretName, $secret.SecretValue)
        return $credential
    } catch {
        throw "Failed to get Azure Key Vault Credential using KeyVaultName: $KeyVaultName SecretName: $SecretName Error: $_"
    }
}

#
# Retrieves the secret from Azure Key Vault.
# Returns a PSCredential object, where the username is the secret name and the password is the retrieved secret.
#
function Get-AzureKeyVaultCredential2
{
    param([Parameter(Mandatory=$False)][string] $KeyVaultName='ebpf-cicd-key-vault',
          [Parameter(Mandatory=$True)][string] $SecretName)

    try {
        # # Check if the Az module is installed, if not, install it
        # if (-not (Get-Module -ListAvailable -Name Az)) {
        #     Install-Module -Name Az -AllowClobber -Force
        # }

        # # Authenticate using the managed identity
        # Connect-AzAccount -Identity

        # Set-AzContext -SubscriptionId "your-subscription-id"

        # Get the managed identity token
        $keyVaultUri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://' + $KeyVaultName + '.vault.azure.net'
        Write-Host "Getting token from $keyVaultUri"
        $token = (Invoke-RestMethod -Uri $keyVaultUri -Method GET -Headers @{Metadata="true"}).access_token

        # Set the token in the header
        $headers = @{
            'Authorization' = "Bearer $token"
        }

        # Get the secret from the Key Vault
        $keyVaultSecretUri = 'https://' + $KeyVaultName + '.vault.azure.net/secrets/' + $SecretName + '?api-version=7.0'
        Write-Host "Getting secret from $keyVaultSecretUri"
        $secret = Invoke-RestMethod -Uri keyVaultSecretUri -Method GET -Headers $headers
        $password = ConvertTo-SecureString $secret.value -AsPlainText -Force

        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList  @($SecretName, $password)
    } catch {
        throw "Failed to get Azure Key Vault Credential using KeyVaultName: $KeyVaultName SecretName: $SecretName Error: $_"
    }
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
