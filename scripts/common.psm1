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

    # Retry 5 times to ensure compression operation succeeds.
    # To mitigate error message: "The process cannot access the file <filename> because it is being used by another process."
    $retryCount = 1
    while ($retryCount -le 5) {
        try {
            $ErrorActionPreference = "Stop"
            Compress-Archive `
                -Path $SourcePath `
                -DestinationPath $DestinationPath `
                -CompressionLevel Fastest `
                -Force

            # Verify the compressed file was actually created.
            if (Test-Path $DestinationPath) {
                Write-Log "Compression completed successfully."
                return $true
            } else {
                throw "Compressed file was not created at $DestinationPath"
            }
        } catch {
            $ErrorMessage = "*** ERROR *** Failed to compress files (attempt $retryCount of 5): $($_.Exception.Message)"
            Write-Log $ErrorMessage
            if ($retryCount -lt 5) {
                Start-Sleep -seconds (5 * $retryCount)
            }
            $retryCount++
        }
    }

    # All retries failed.
    Write-Log "*** ERROR *** Failed to compress after 5 attempts. Compression failed."
    return $false
}

<#
.SYNOPSIS
    Attempts to compress files and copies them to a destination, with fallback to uncompressed files.

.DESCRIPTION
    This function standardizes the pattern of trying to compress files and copying the result,
    with automatic fallback to copying uncompressed files if compression fails.

.PARAMETER SourcePath
    The source files to compress (supports wildcards like *.dmp).

.PARAMETER DestinationDirectory
    The directory where the final files should be copied.

.PARAMETER CompressedFileName
    The name for the compressed file. If not provided, auto-generates based on source.

.OUTPUTS
    Returns a hashtable with the following properties:
    - Success: Boolean indicating if compression succeeded
    - CompressedPath: Path to compressed file (if compression succeeded)
    - UncompressedPath: Path to uncompressed file (if compression failed)
    - FinalPath: Path to the final file that was copied

.EXAMPLE
    $result = CompressOrCopy-File -SourcePath "C:\dumps\*.dmp" -DestinationDirectory "C:\output" -CompressedFileName "dumps.zip"
    if ($result.Success) {
        Write-Host "Compression succeeded: $($result.FinalPath)"
    } else {
        Write-Host "Compression failed, using uncompressed: $($result.FinalPath)"
    }
#>
function CompressOrCopy-File
{
    param(
        [Parameter(Mandatory=$True)][string] $SourcePath,
        [Parameter(Mandatory=$True)][string] $DestinationDirectory,
        [Parameter(Mandatory=$False)][string] $CompressedFileName
    )

    # Ensure destination directory exists.
    if (-not (Test-Path $DestinationDirectory -PathType Container)) {
        New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
    }

    # Auto-generate compressed filename if not provided.
    if (-not $CompressedFileName) {
        $sourceName = Split-Path $SourcePath -Leaf
        $CompressedFileName = "$sourceName.zip"
    }

    # Create temporary path for compression.
    $tempCompressedPath = Join-Path $env:TEMP $CompressedFileName
    $finalCompressedPath = Join-Path $DestinationDirectory $CompressedFileName

    # Attempt compression.
    $compressionSucceeded = Compress-File -SourcePath $SourcePath -DestinationPath $tempCompressedPath

    if ($compressionSucceeded -and (Test-Path $tempCompressedPath)) {
        # Compression succeeded - copy compressed file.
        Copy-Item -Path $tempCompressedPath -Destination $finalCompressedPath -Force
        Remove-Item -Path $tempCompressedPath -Force -ErrorAction Ignore

        $compressedFile = Get-ChildItem -Path $finalCompressedPath
        Write-Log "Copied compressed file: $($compressedFile.Name), Size: $((($compressedFile.Length) / 1MB).ToString("F2")) MB"

        return @{
            Success = $true
            CompressedPath = $finalCompressedPath
            UncompressedPath = ""
            FinalPath = $finalCompressedPath
        }
    } else {
        # Compression failed - copy uncompressed files as fallback.
        Write-Log "*** WARNING *** Compression failed. Copying uncompressed files instead."

        $sourceFiles = Get-ChildItem -Path $SourcePath -ErrorAction SilentlyContinue
        $copiedPaths = @()

        foreach ($file in $sourceFiles) {
            $destinationPath = Join-Path $DestinationDirectory $file.Name
            Copy-Item -Path $file.FullName -Destination $destinationPath -Force
            Write-Log "Copied uncompressed file: $($file.Name)"
            $copiedPaths += $destinationPath
        }

        # Clean up temporary compressed file if it exists.
        if (Test-Path $tempCompressedPath) {
            Remove-Item -Path $tempCompressedPath -Force -ErrorAction Ignore
        }

        return @{
            Success = $false
            CompressedPath = ""
            UncompressedPath = if ($copiedPaths.Count -gt 0) { $copiedPaths -join "; " } else { "" }
            FinalPath = if ($copiedPaths.Count -gt 0) { $copiedPaths -join "; " } else { "" }
        }
    }
}

<#
.SYNOPSIS
    Copies compressed files from a remote session, with fallback to uncompressed files.

.DESCRIPTION
    This function standardizes the pattern of trying to copy compressed files from a remote session
    and falling back to uncompressed files if the compressed copy fails.

.PARAMETER VMSession
    The remote PowerShell session to copy from.

.PARAMETER CompressedSourcePath
    The path to the compressed file on the remote session.

.PARAMETER UncompressedSourcePath
    The path to the uncompressed file on the remote session.

.PARAMETER DestinationDirectory
    The local directory where files should be copied.

.OUTPUTS
    Returns a hashtable with the following properties:
    - Success: Boolean indicating if compressed copy succeeded
    - CompressedPath: Path to compressed file (if compressed copy succeeded)
    - UncompressedPath: Path to uncompressed file (if compressed copy failed)
    - FinalPath: Path to the final file that was copied

.EXAMPLE
    $result = CopyCompressedOrUncompressed-FileFromSession -VMSession $session -CompressedSourcePath "C:\eBPF\trace.zip" -UncompressedSourcePath "C:\eBPF\trace.etl" -DestinationDirectory ".\Logs"
    if ($result.Success) {
        Write-Host "Compressed copy succeeded: $($result.FinalPath)"
    } else {
        Write-Host "Using uncompressed fallback: $($result.FinalPath)"
    }
#>
function CopyCompressedOrUncompressed-FileFromSession
{
    param(
        [Parameter(Mandatory=$True)] $VMSession,
        [Parameter(Mandatory=$True)][string] $CompressedSourcePath,
        [Parameter(Mandatory=$True)][string] $UncompressedSourcePath,
        [Parameter(Mandatory=$True)][string] $DestinationDirectory
    )

    # Ensure destination directory exists.
    if (-not (Test-Path $DestinationDirectory -PathType Container)) {
        New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
    }

    $compressedFileName = Split-Path $CompressedSourcePath -Leaf
    $uncompressedFileName = Split-Path $UncompressedSourcePath -Leaf
    $compressedDestPath = Join-Path $DestinationDirectory $compressedFileName

    # Try to copy compressed file first.
    Write-Log "Copy $CompressedSourcePath to $DestinationDirectory"
    Copy-Item `
        -FromSession $VMSession `
        -Path $CompressedSourcePath `
        -Destination $DestinationDirectory `
        -Recurse `
        -Force `
        -ErrorAction Ignore 2>&1 | Write-Log

    # Check if compressed copy succeeded.
    if (Test-Path $compressedDestPath) {
        Write-Log "Successfully copied compressed file: $compressedFileName"
        return @{
            Success = $true
            CompressedPath = $compressedDestPath
            UncompressedPath = ""
            FinalPath = $compressedDestPath
        }
    } else {
        # Compressed copy failed, try uncompressed.
        Write-Log "Compressed file not found, trying uncompressed: Copy $UncompressedSourcePath to $DestinationDirectory"
        Copy-Item `
            -FromSession $VMSession `
            -Path $UncompressedSourcePath `
            -Destination $DestinationDirectory `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log

        $uncompressedDestPath = Join-Path $DestinationDirectory $uncompressedFileName
        if (Test-Path $uncompressedDestPath) {
            Write-Log "Successfully copied uncompressed file: $uncompressedFileName"
        } else {
            Write-Log "*** WARNING *** Failed to copy both compressed and uncompressed files"
        }

        return @{
            Success = $false
            CompressedPath = ""
            UncompressedPath = $uncompressedDestPath
            FinalPath = $uncompressedDestPath
        }
    }
}

function Wait-TestJobToComplete
{
    param([Parameter(Mandatory = $true)] [System.Management.Automation.Job] $Job,
           [Parameter(Mandatory = $true)] [PSCustomObject] $Config,
           [Parameter(Mandatory = $true)] [string] $SelfHostedRunnerName,
           [Parameter(Mandatory = $true)] [int] $TestJobTimeout,
           [Parameter(Mandatory = $true)] [string] $CheckpointPrefix,
           [Parameter(Mandatory = $false)] [bool] $ExecuteOnVM=$true)
    $TimeElapsed = 0
    # Loop to fetch and print job output in near real-time.
    while ($Job.State -eq 'Running') {
        $JobOutput = Receive-Job -Job $job
        $JobOutput | ForEach-Object { Write-Host $_ }

        Start-Sleep -Seconds 2
        $TimeElapsed += 2

        if ($TimeElapsed -gt $TestJobTimeout) {
            if ($Job.State -eq "Running") {
                if ($ExecuteOnVM) {
                    $VMList = $Config.VMMap.$SelfHostedRunnerName
                    # Currently one VM runs per runner.
                    $TestVMName = $VMList[0].Name
                    Write-Host "Running kernel tests on $TestVMName has timed out after one hour" -ForegroundColor Yellow
                    $Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
                    $CheckpointName = "$CheckpointPrefix-$TestVMName-Checkpoint-$Timestamp"
                    Write-Log "Taking snapshot $CheckpointName of $TestVMName"
                    Checkpoint-VM -Name $TestVMName -SnapshotName $CheckpointName
                }
                $JobTimedOut = $true
                break
            }
        }
    }

    # Print any remaining output after the job completes.
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

    # Create the directory if it does not already exist.
    if (-not (Test-Path -Path $Path -PathType Container)) {
        New-Item -Path $Path -ItemType Directory -Force
    }

    # Check if the directory was successfully created.
    if (-not (Test-Path -PathType Container $Path)) {
        throw "Failed to create directory: $Path"
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
    Helper function to invoke a script using PsExec.

.DESCRIPTION
    This function uses PsExec to run a PowerShell script in the LocalSystem account context.

.PARAMETER Script
    The script to execute using PsExec.

.EXAMPLE
    Invoke-PsExecScript -Script "Get-Process"
#>
function Invoke-PsExecScript {
    param (
        [Parameter(Mandatory=$true)][string]$Script
    )
    $PSExecPath = Get-PSExec
    if (($null -eq $PSExecPath) -or (-not (Test-Path $PSExecPath))) {
        throw "Failed to retrieve PsExec path."
    }

    $outputFile = [System.IO.Path]::GetTempFileName()
    $errorFile = [System.IO.Path]::GetTempFileName()

    try {
        $process = Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula -nobanner -s powershell.exe -command `"$Script`"" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
        $output = Get-Content $outputFile
        $err = Get-Content $errorFile

        if ($process.ExitCode -ne 0) {
            throw "PsExec failed with exit code $($process.ExitCode). Output: $output Error: $err"
        }

        return $output
    } finally {
        Remove-Item $outputFile -Force -ErrorAction Ignore
        Remove-Item $errorFile -Force -ErrorAction Ignore
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

.PARAMETER Target
    The name of the stored credential. Default is "MyStoredCredential".

.DESCRIPTION
    This function uses PsExec to run a PowerShell script in the LocalSystem account context to retrieve a credential from the Windows Credential Manager.

.EXAMPLE
    $credential = Retrieve-StoredCredential -Target "MyStoredCredential"
#>
function Retrieve-StoredCredential {
    param (
        [Parameter(Mandatory=$True)][string]$Target
    )
    Get-CredentialManager

    $Script = @"
        Import-Module CredentialManager -ErrorAction Stop;
        `$Credential = Get-StoredCredential -Target '$Target';
        `$UserName = `$Credential.UserName;
        `$Password = `$Credential.GetNetworkCredential().Password;
        \"`$UserName`n`$Password\"
"@

    # PSExec sometimes fails to fetch the output. Retry up to 3 times to improve reliability.
    $attempt = 0
    $maxRetries = 5
    while ($attempt -lt $maxRetries) {
        try {
            $output = Invoke-PsExecScript -Script $Script
            $lines = $output -split "`n"
            $Username = $lines[0].Trim()
            $Password = ConvertTo-SecureString -String $lines[1].Trim() -AsPlainText -Force
            if ($null -eq $Username -or $null -eq $Password) {
                throw "Failed to retrieve the stored credential."
            }
            return [System.Management.Automation.PSCredential]::new($Username, $Password)
        } catch {
            $attempt++
            if ($attempt -lt $maxRetries) {
                Start-Sleep -Seconds 5
            } else {
                throw "Failed to retrieve the stored credential after $maxRetries attempts."
            }
        }
    }
}

<#
.SYNOPSIS
    Stores a credential in the Windows Credential Manager using PsExec.

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
    $credential = Generate-NewCredential -Username "YourUsername" -Password $securePassword -Target "MyStoredCredential"
#>
function Generate-NewCredential {
    param (
        [Parameter(Mandatory=$True)][string]$Username,
        [Parameter(Mandatory=$True)][string]$Password,
        [Parameter(Mandatory=$True)][string]$Target
    )
    Get-CredentialManager
    $Script = @"
        Import-Module CredentialManager -ErrorAction Stop;
        New-StoredCredential -Target '$Target' -UserName '$Username' -Password '$Password' -Persist LocalMachine;
"@

    $output = Invoke-PsExecScript -Script $Script
    return (Retrieve-StoredCredential -Target $Target)
}


function Expand-ZipFile {
    param(
        [Parameter(Mandatory=$True)][string] $DownloadFilePath,
        [Parameter(Mandatory=$True)][string] $OutputDir,
        [Parameter(Mandatory=$True)][int] $maxRetries,
        [Parameter(Mandatory=$True)][int] $retryDelay,
        [Parameter(Mandatory=$True)][int] $timeout
    )

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $job = Start-Job -ScriptBlock {
                param ($DownloadFilePath, $OutputDir)
                Expand-Archive -Path $DownloadFilePath -DestinationPath $OutputDir -Force
            } -ArgumentList $DownloadFilePath, $OutputDir

            if (Wait-Job -Job $job -Timeout $timeout) {
                Write-Log "Extraction completed. $DownloadFilePath -> $OutputDir"
                Receive-Job -Job $job
                break
            } else {
                Stop-Job -Job $job
                Remove-Job -Job $job
                if ($i -eq ($maxRetries - 1)) {
                    throw "Failed to extract $DownloadFilePath after $maxRetries attempts."
                } else {
                    Start-Sleep -Seconds $retryDelay
                }
            }
        } catch {
            if ($i -eq ($maxRetries - 1)) {
                throw "Failed to extract $DownloadFilePath after $maxRetries attempts."
            } else {
                Start-Sleep -Seconds $retryDelay
            }
        }
    }
}

function Get-ZipFileFromUrl {
    param(
        [Parameter(Mandatory=$True)][string] $Url,
        [Parameter(Mandatory=$True)][string] $DownloadFilePath,
        [Parameter(Mandatory=$True)][string] $OutputDir
    )
    $maxRetries = 5
    $retryDelay = 5 # seconds
    $timeout = 300 # seconds

    Write-Log "Downloading $Url to $DownloadFilePath"

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Head -TimeoutSec $timeout
            if ($response.StatusCode -ne 200) {
                throw "Failed to reach $Url HTTP status code: $($response.StatusCode)"
            }

            $ProgressPreference = 'SilentlyContinue'

            $job = Start-Job -ScriptBlock {
                param ($Url, $DownloadFilePath, $timeout)
                Invoke-WebRequest -Uri $Url -OutFile $DownloadFilePath -TimeoutSec $timeout
            } -ArgumentList $Url, $DownloadFilePath, $timeout

            if (Wait-Job -Job $job -Timeout $timeout) {
                Receive-Job -Job $job

                Write-Log "Extracting $DownloadFilePath to $OutputDir"
                Expand-ZipFile -DownloadFilePath $DownloadFilePath -OutputDir $OutputDir -maxRetries $maxRetries -retryDelay $retryDelay -timeout $timeout
                break
            } else {
                Stop-Job -Job $job
                Remove-Job -Job $job
                if (Test-Path $DownloadFilePath) {
                    Remove-Item -Path $DownloadFilePath -Force -ErrorAction Ignore
                }
                if ($i -eq ($maxRetries - 1)) {
                    throw "Failed to download $Url after $maxRetries attempts."
                } else {
                    Start-Sleep -Seconds $retryDelay
                }
            }
        } catch {
            if (Test-Path $DownloadFilePath) {
                Remove-Item -Path $DownloadFilePath -Force -ErrorAction Ignore
            }
            if ($i -eq ($maxRetries - 1)) {
                throw "Failed to download $Url after $maxRetries attempts."
            } else {
                Start-Sleep -Seconds $retryDelay
            }
        }
    }
}

function Get-LegacyRegressionTestArtifacts
{
    $ArifactVersionList = @("0.11.0")
    $RegressionTestArtifactsPath = "$pwd\regression"
    if (Test-Path -Path $RegressionTestArtifactsPath) {
        Remove-Item -Path $RegressionTestArtifactsPath -Recurse -Force
    }
    mkdir $RegressionTestArtifactsPath

    # verify Artifacts' folder presense
    if (-not (Test-Path -Path $RegressionTestArtifactsPath)) {
        $ErrorMessage = "*** ERROR *** Regression test artifacts folder not found: $RegressionTestArtifactsPath)"
        Write-Log $ErrorMessage
        throw $ErrorMessage
    }

    # Download regression test artifacts for each version.
    foreach ($ArtifactVersion in $ArifactVersionList)
    {
        Write-Log "Downloading legacy regression test artifacts for version $ArtifactVersion"
        $DownloadPath = "$RegressionTestArtifactsPath\$ArtifactVersion"
        mkdir $DownloadPath
        $ArtifactName = "v$ArtifactVersion/Build-x64-native-only-Release.$ArtifactVersion.zip"
        $ArtifactUrl = "https://github.com/microsoft/ebpf-for-windows/releases/download/" + $ArtifactName

        for ($i = 0; $i -lt 5; $i++) {
            try {
                # Download and extract the artifact.
                Get-ZipFileFromUrl -Url $ArtifactUrl -DownloadFilePath "$DownloadPath\artifact.zip" -OutputDir $DownloadPath

                # Extract the inner zip file.
                Expand-Archive -Path "$DownloadPath\build-NativeOnlyRelease.zip" -DestinationPath $DownloadPath -Force
                break
            } catch {
                Write-Log -TraceMessage "Iteration $i failed to download $ArtifactUrl. Removing $DownloadPath" -ForegroundColor Red
                Remove-Item -Path $DownloadPath -Force -ErrorAction Ignore
                Start-Sleep -Seconds 5
            }
        }

        Move-Item -Path "$DownloadPath\NativeOnlyRelease\cgroup_sock_addr2.sys" -Destination "$RegressionTestArtifactsPath\cgroup_sock_addr2_$ArtifactVersion.sys" -Force
        Remove-Item -Path $DownloadPath -Force -Recurse
    }
}

function Get-RegressionTestArtifacts
{
    param([Parameter(Mandatory=$True)][string] $Configuration,
          [Parameter(Mandatory=$True)][string] $ArtifactVersion)

    $RegressionTestArtifactsPath = "$pwd\regression"
    $OriginalPath = $pwd
    if (Test-Path -Path $RegressionTestArtifactsPath) {
        Remove-Item -Path $RegressionTestArtifactsPath -Recurse -Force
    }
    mkdir $RegressionTestArtifactsPath

    # Verify artifacts' folder presence
    if (-not (Test-Path -Path $RegressionTestArtifactsPath)) {
        $ErrorMessage = "*** ERROR *** Regression test artifacts folder not found: $RegressionTestArtifactsPath)"
        Write-Log $ErrorMessage
        throw $ErrorMessage
    }

    # Download regression test artifacts for each version.
    $DownloadPath = "$RegressionTestArtifactsPath"
    $ArtifactName = "Release-v$ArtifactVersion/Build.$Configuration.x64.zip"
    $ArtifactUrl = "https://github.com/microsoft/ebpf-for-windows/releases/download/" + $ArtifactName

    if (Test-Path -Path $DownloadPath\Build-x64.$Configuration) {
        Remove-Item -Path $DownloadPath\Build-x64.$Configuration -Recurse -Force
    }

    Get-ZipFileFromUrl -Url $ArtifactUrl -DownloadFilePath "$DownloadPath\Build-x64.$Configuration.zip" -OutputDir $DownloadPath
    $DownloadedArtifactPath = "$DownloadPath\Build $Configuration x64"
    if (!(Test-Path -Path $DownloadedArtifactPath)) {
        throw ("Path ""$DownloadedArtifactPath"" not found.")
    }

    # Copy all the drivers, DLLs, exe and .o files to pwd.
    Write-Log "Copy regression test artifacts to main folder" -ForegroundColor Green
    Push-Location $DownloadedArtifactPath
    Get-ChildItem -Path .\* -Include *.sys | Move-Item -Destination $OriginalPath -Force
    Get-ChildItem -Path .\* -Include *.dll | Move-Item -Destination $OriginalPath -Force
    Get-ChildItem -Path .\* -Include *.exe | Move-Item -Destination $OriginalPath -Force
    Get-ChildItem -Path .\* -Include *.o | Move-Item -Destination $OriginalPath -Force
    Pop-Location

    Remove-Item -Path $DownloadPath -Force -Recurse

    # Delete ebpfapi.dll from the artifacts. ebpfapi.dll from the MSI installation should be used instead.
    Remove-Item -Path ".\ebpfapi.dll" -Force
}

# Copied from https://github.com/microsoft/msquic/blob/main/scripts/prepare-machine.ps1
function Get-CoreNetTools {
    param(
        [string] $Architecture = "x64"
    )
    # Download and extract https://github.com/microsoft/corenet-ci.
    $DownloadPath = "$pwd\corenet-ci"
    mkdir $DownloadPath
    Write-Log "Downloading CoreNet-CI to $DownloadPath"
    Get-ZipFileFromUrl -Url "https://github.com/microsoft/corenet-ci/archive/refs/heads/main.zip" -DownloadFilePath "$DownloadPath\corenet-ci.zip" -OutputDir $DownloadPath
    # DuoNic.
    if ($Architecture -eq "arm64") {
        $duoNicPath = "$DownloadPath\corenet-ci-main\vm-setup\duonic\arm64\*"
    } else {
        $duoNicPath = "$DownloadPath\corenet-ci-main\vm-setup\duonic\*"
    }
    Move-Item -Path $duoNicPath -Destination $pwd -Force
    # Procdump.
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\procdump64.exe" -Destination $pwd -Force
    # NotMyFault.
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\notmyfault64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse
}

# Download and extract PSExec to run tests as SYSTEM.
function Get-PSExec {
    $psExecPath = "$pwd\PsExec64.exe"
    # Check to see if PSExec already exists
    if (Test-Path -Path $psExecPath) {
        return $psExecPath
    }
    $url = "https://download.sysinternals.com/files/PSTools.zip"
    $DownloadPath = "$pwd\psexec"

    Get-ZipFileFromUrl -Url $url -DownloadFilePath "$pwd\pstools.zip" -OutputDir "$DownloadPath"
    Move-Item -Path "$DownloadPath\PsExec64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse -ErrorAction Ignore
    return $psExecPath
}
