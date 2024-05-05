# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $Admin,
       [Parameter(Mandatory=$True)] [SecureString] $AdminPassword,
       [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

$sleepSeconds = 10

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

#
# VM Initialization functions
#

function Wait-AllVMsToInitialize
{
    param([Parameter(Mandatory=$True)]$VMList,
          [Parameter(Mandatory=$True)][string] $UserName,
          [Parameter(Mandatory=$True)][SecureString] $AdminPassword)

    $totalSleepTime = 0
    $ReadyList = @{}
    do {
        foreach ($VM in $VMList) {
            $VMName= $VM.Name
            if ($ReadyList[$VMName] -ne $True) {
                $HeartBeat = (Get-VMIntegrationService $VMName | ?{$_.name -eq "Heartbeat"}).PrimaryStatusDescription
                if ($HeartBeat -eq "OK") {
                    $ReadyList += @{$VMName = $True}
                } else {
                    continue
                }
                Write-Log "Heartbeat OK on $VMName" -ForegroundColor Green
            }
        }
        if ($ReadyList.Count -ne $VMList.Count) {
            Write-Log ("{0} of {1} VMs are ready." -f $ReadyList.Count, $VMList.Count)
            # Sleep for sleepSeconds seconds.
            Start-Sleep -seconds $sleepSeconds
            $totalSleepTime += $sleepSeconds
        }
    }
    until (($ReadyList.Count -eq $VMList.Count) -or ($totalSleepTime -gt 5*60))

    if ($ReadyList.Count -ne $VMList.Count) {
        throw ("Did not get heartbeat from one or more VMs 5 minutes after starting")
    }

    $TestCredential = New-Credential -Username $UserName -AdminPassword $AdminPassword
    $ReadyList.Clear()
    $totalSleepTime = 0

    do {
        foreach($VM in $VMList) {
            $VMName = $VM.Name
            if ($ReadyList[$VMName] -ne $True) {
                Write-Log "Poking $VMName to see if it is ready to accept commands"
                $ret = Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {$True} -ErrorAction SilentlyContinue
                if ($ret -eq $True) {
                    $ReadyList += @{$VMName = $True}
                } else {
                    continue
                }
                Write-Log "VM $VMName is ready" -ForegroundColor Green
            }
        }
        if ($ReadyList.Count -ne $VMList.Count) {
            Write-Log "Waiting $sleepSeconds seconds for $VMName to be responsive."
            # Sleep for sleepSeconds seconds.
            Start-Sleep -seconds $sleepSeconds
            $totalSleepTime += $sleepSeconds
        }
    }
    until (($ReadyList.Count -eq $VMList.Count) -or ($totalSleepTime -gt 5*60))

    if ($ReadyList.Count -ne $VMList.Count) {
        throw ("One or more VMs not ready 5 minutes after initial heartbeat")
    }

    # Enable guest-services on each VM.
    $ReadyList.Clear()
    $totalSleepTime = 0

    do {
        foreach($VM in $VMList) {
            $VMName = $VM.Name
            if ((Get-VMIntegrationService $VMName | ?{$_.name -eq "Guest Service Interface"}).PrimaryStatusDescription -ne "OK") {
                Write-Log "Enabling guest services on $VMName"
                Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
                if ((Get-VMIntegrationService $VMName | ?{$_.name -eq "Guest Service Interface"}).PrimaryStatusDescription -eq "OK") {
                    $ReadyList += @{$VMName = $True}
                } else {
                    break
                }
                Write-Log "Guest services enabled on $VMName" -ForegroundColor Green
            } else {
                Write-Log "Guest services already enabled on $VMName"
                $ReadyList += @{$VMName = $True}
            }
        }
        if ($ReadyList.Count -ne $VMList.Count) {
            # Wait one second for guest services to start.
            Start-Sleep -seconds 1
            $totalSleepTime += 1
        }
    }
    until (($ReadyList.Count -eq $VMList.Count) -or ($totalSleepTime -gt 1*60))

    if ($ReadyList.Count -ne $VMList.Count) {
        throw ("Guest service failed to get enabled on one or more VMs after waiting for 1 minute.")
    }
}

function Restore-AllVMs
{
    param ([Parameter(Mandatory=$True)] $VMList)
    foreach ($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Restoring VM $VMName"
        Restore-VMSnapshot -Name 'baseline' -VMName $VMName -Confirm:$false
    }
}

function Start-AllVMs
{
    param ([Parameter(Mandatory=$True)] $VMList)
    foreach ($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Starting VM $VMName"
        Start-VM -VMName $VMName -ErrorAction Stop 2>&1 | Write-Log
    }
}

function Initialize-AllVMs
{
    param ([Parameter(Mandatory=$True)] $VMList)

    # Restore the VMs.
    Restore-AllVMs -VMList $VMList

    # Start the VMs.
    Start-AllVMs -VMList $VMList

    # Wait for VMs to be ready.
    Write-Log "Waiting for all the VMs to be in ready state..." -ForegroundColor Yellow
    Wait-AllVMsToInitialize -VMList $VMList -UserName $Admin -AdminPassword $AdminPassword
}

#
# VM Cleanup Functions
#

function Stop-AllVMs
{
    param ([Parameter(Mandatory=$True)] $VMList)

    foreach ($VM in $VMList) {
        # Stop the VM.
        $VMName = $VM.Name
        Write-Log "Stopping VM $VMName"
        Stop-VM -Name $VMName -Force -TurnOff -WarningAction Ignore  2>&1 | Write-Log
    }
}

#
# Export build artifacts.
#

function Export-BuildArtifactsToVMs
{
    param([Parameter(Mandatory=$True)] $VMList)

    $tempFileName = [System.IO.Path]::GetTempFileName() + ".tgz"
    Write-Log "Creating $tempFileName containing files in $pwd"
    &tar @("cfz", "$tempFileName", "*")
    Write-Log "Created $tempFileName containing files in $pwd"

    # Copy artifacts to the given VM list.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword
        $VMSession = New-PSSession -VMName $VMName -Credential $TestCredential
        if (!$VMSession) {
            throw "Failed to create PowerShell session on $VMName."
        } else {
            Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
                if(!(Test-Path "$Env:SystemDrive\eBPF")) {
                    New-Item -ItemType Directory -Path "$Env:SystemDrive\eBPF"
                }
                return $Env:SystemDrive
            }
            $VMSystemDrive = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:SystemDrive}
        }
        Write-Log "Copying $tempFileName to $VMSystemDrive\eBPF on $VMName"
        Copy-Item -ToSession $VMSession -Path $tempFileName -Destination "$VMSystemDrive\eBPF\ebpf.tgz" -Force 2>&1 -ErrorAction Stop | Write-Log
        Write-Log "Copied $tempFileName to $VMSystemDrive\eBPF on $VMName"

        Write-Log "Unpacking $tempFileName to $VMSystemDrive\eBPF on $VMName"
        Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
            cd $Env:SystemDrive\eBPF
            &tar @("xf", "ebpf.tgz")
        }
        Write-Log "Unpacked $tempFileName to $VMSystemDrive\eBPF on $VMName"
        Write-Log "Export completed." -ForegroundColor Green
    }

    Remove-Item -Force $tempFileName
}

#
# Install eBPF components on VM.
#
function Install-eBPFComponentsOnVM
{
    param([parameter(Mandatory=$true)][string] $VMName,
          [parameter(Mandatory=$true)][string] $TestMode,
          [parameter(Mandatory=$true)][bool] $KmTracing,
          [parameter(Mandatory=$true)][string] $KmTraceType)

    Write-Log "Installing eBPF components on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName,
              [Parameter(Mandatory=$true)] [bool] $KmTracing,
              [Parameter(Mandatory=$true)] [string] $KmTraceType,
              [parameter(Mandatory=$true)][string] $TestMode)
        $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Install-eBPFComponents -KmTracing $KmTracing -KmTraceType $KmTraceType -KMDFVerifier $true -TestMode $TestMode -ErrorAction Stop
    } -ArgumentList ("eBPF", $LogFileName, $KmTracing, $KmTraceType, $TestMode) -ErrorAction Stop
    Write-Log "eBPF components installed on $VMName" -ForegroundColor Green
}

function Uninstall-eBPFComponentsOnVM
{
    param([parameter(Mandatory=$true)][string] $VMName)

    Write-Log "Unnstalling eBPF components on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
        $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Uninstall-eBPFComponents
    } -ArgumentList ("eBPF", $LogFileName) -ErrorAction Stop
    Write-Log "eBPF components uninstalled on $VMName" -ForegroundColor Green
}

function Stop-eBPFComponentsOnVM
{
    param([parameter(Mandatory=$true)][string] $VMName)

    Write-Log "Stopping eBPF components on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command `
        -VMName $VMName `
        -Credential $TestCredential `
        -ScriptBlock {
            param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
                  [Parameter(Mandatory=$True)] [string] $LogFileName
            )

            $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
            Import-Module $WorkingDirectory\common.psm1 `
                -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

            Import-Module $WorkingDirectory\install_ebpf.psm1 `
                -ArgumentList($WorkingDirectory, $LogFileName) `
                -Force -WarningAction SilentlyContinue

            Stop-eBPFComponents

        } -ArgumentList ("eBPF", $LogFileName) -ErrorAction Stop

    Write-Log "eBPF components stopped on $VMName" -ForegroundColor Green
}

function ArchiveKernelModeDumpOnVM
{
    param (
        [Parameter(Mandatory = $True)] [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Invoke-Command -Session $Session -ScriptBlock {

        $KernelModeDumpFileSourcePath = "$Env:WinDir"
        $KernelModeDumpFileDestinationPath = "$Env:SystemDrive\KernelDumps"

        # Create the compressed dump folder if doesn't exist.
        if (!(Test-Path $KernelModeDumpFileDestinationPath)) {
            Write-Output "Creating $KernelModeDumpFileDestinationPath directory."
            New-Item -ItemType Directory -Path $KernelModeDumpFileDestinationPath | Out-Null

            # Make sure it was created
            if (!(Test-Path $KernelModeDumpFileDestinationPath)) {
                $ErrorMessage = `
                    "*** ERROR *** Create compressed dump file directory failed: $KernelModeDumpFileDestinationPath`n"
                Write-Output $ErrorMessage
                Start-Sleep -seconds 3
                Throw $ErrorMessage
            }
        }

        if (Test-Path $KernelModeDumpFileSourcePath\*.dmp -PathType Leaf) {
            Write-Output "Found kernel mode dump(s) in $($KernelModeDumpFileSourcePath):"
            $DumpFiles = get-childitem -Path $KernelModeDumpFileSourcePath\*.dmp
            foreach ($DumpFile in $DumpFiles) {
                Write-Output "`tName:$($DumpFile.Name), Size:$((($DumpFile.Length) / 1MB).ToString("F2")) MB"
            }
            Write-Output "`n"

            Write-Output `
                "Compressing kernel dump files: $KernelModeDumpFileSourcePath -> $KernelModeDumpFileDestinationPath"
            Compress-Archive `
                -Path $KernelModeDumpFileSourcePath\*.dmp `
                -DestinationPath $KernelModeDumpFileDestinationPath\km_dumps.zip `
                -CompressionLevel Fastest `
                -Force

            if (Test-Path $KernelModeDumpFileDestinationPath\km_dumps.zip -PathType Leaf) {
                $CompressedDumpFile = get-childitem -Path $KernelModeDumpFileDestinationPath\km_dumps.zip
                Write-Output "Found compressed kernel mode dump file in $($KernelModeDumpFileDestinationPath):"
                Write-Output `
                    "`tName:$($CompressedDumpFile.Name), Size:$((($CompressedDumpFile.Length) / 1MB).ToString("F2")) MB"
            } else {
                $ErrorMessage = "*** ERROR *** kernel mode dump compressed file not found.`n`n"
                Write-Output $ErrorMessage
                Start-Sleep -seconds 3
                throw $ErrorMessage
            }
        } else {
            Write-Output "`n"
            Write-Output "No kernel mode dump(s) in $($KernelModeDumpFileSourcePath)."
        }
    }
}

#
# Import test logs and dumps from VM.
#
function Import-ResultsFromVM
{
    param([Parameter(Mandatory=$True)] $VMList,
          [Parameter(Mandatory=$true)] $KmTracing)

    # Wait for all VMs to be in ready state, in case the test run caused any VM to crash.
    Wait-AllVMsToInitialize -VMList $VMList -UserName $Admin -AdminPassword $AdminPassword

    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Importing TestLogs from $VMName"
        if (!(Test-Path ".\TestLogs\$VMName")) {
            New-Item -ItemType Directory -Path ".\TestLogs\$VMName"
        }

        $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword
        $VMSession = New-PSSession -VMName $VMName -Credential $TestCredential
        if (!$VMSession) {
            throw "Failed to create PowerShell session on $VMName."
        }
        $VMSystemDrive = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:SystemDrive}

        # Archive and copy kernel crash dumps, if any.
        Write-Log "Processing kernel mode dump (if any) on VM $VMName"
        ArchiveKernelModeDumpOnVM -Session $VMSession

        $LocalKernelArchiveLocation = ".\TestLogs\$VMName\KernelDumps"
        Copy-Item `
            -FromSession $VMSession `
            -Path "$VMSystemDrive\KernelDumps" `
            -Destination $LocalKernelArchiveLocation `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log

        if (Test-Path $LocalKernelArchiveLocation\km_dumps.zip -PathType Leaf) {
            $LocalFile = get-childitem -Path $LocalKernelArchiveLocation\km_dumps.zip
            Write-Log "`n"
            Write-Log "Local copy of kernel mode dump archive in $($LocalKernelArchiveLocation) for VM $($VMName):"
            Write-Log "`tName:$($LocalFile.Name), Size:$((($LocalFile.Length) / 1MB).ToString("F2")) MB"
        } else {
            Write-Log "`n"
            Write-Log "No local copy of kernel mode dump archive in $($LocalKernelArchiveLocation) for VM $VMName."
        }

        # Copy user mode crash dumps if any.
        Copy-Item `
            -FromSession $VMSession `
            -Path "$VMSystemDrive\dumps" `
            -Destination ".\TestLogs\$VMName" `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log

        # Copy logs from Test VM.
        if (!(Test-Path ".\TestLogs\$VMName\Logs")) {
            New-Item -ItemType Directory -Path ".\TestLogs\$VMName\Logs"
        }
        $VMTemp = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:TEMP}
        Write-Log ("Copy $LogFileName from $VMTemp on $VMName to $pwd\TestLogs")
        Copy-Item `
            -FromSession $VMSession `
            -Path "$VMTemp\$LogFileName" `
            -Destination ".\TestLogs\$VMName\Logs" `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log

        Write-Log ("Copy CodeCoverage from eBPF on $VMName to $pwd\..\..")
        Copy-Item `
            -FromSession $VMSession `
            -Path "$VMSystemDrive\eBPF\ebpf_for_windows.xml" `
            -Destination "$pwd\..\.." `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log

        # Copy kernel mode traces, if enabled.
        if ($KmTracing) {
            $EtlFile = $LogFileName.Substring(0, $LogFileName.IndexOf('.')) + ".etl"
            # Stop KM ETW Traces.
            Invoke-Command -Session $VMSession -ScriptBlock {
                param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
                      [Parameter(Mandatory=$True)] [string] $LogFileName,
                      [Parameter(Mandatory=$True)] [string] $EtlFile)
                $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
                Import-Module `
                    $WorkingDirectory\common.psm1 `
                    -ArgumentList ($LogFileName) `
                    -Force `
                    -WarningAction SilentlyContinue

                Write-Log "Query KM ETL tracing status before trace stop"
                $ProcInfo = Start-Process -FilePath "wpr.exe" `
                    -ArgumentList "-status profiles collectors -details" `
                    -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOut .\StdOut.txt -RedirectStandardError .\StdErr.txt
                if ($ProcInfo.ExitCode -ne 0) {
                    Write-log ("wpr.exe query ETL trace status failed. Exit code: " + $ProcInfo.ExitCode)
                    Write-log "wpr.exe (query) error output: "
                    foreach ($line in get-content -Path .\StdErr.txt) {
                        write-log ( "`t" + $line)
                    }
                    throw "Query ETL trace status failed."
                } else {
                    Write-log "wpr.exe (query) results: "
                    foreach ($line in get-content -Path .\StdOut.txt) {
                        write-log ( "  `t" + $line)
                    }
                }
                Write-Log ("Query ETL trace status success. wpr.exe exit code: " + $ProcInfo.ExitCode + "`n" )

                Write-Log "Stop KM ETW tracing, create ETL file: $WorkingDirectory\$EtlFile"
                wpr.exe -stop $WorkingDirectory\$EtlFile

                $EtlFileSize = (Get-ChildItem $WorkingDirectory\$EtlFile).Length/1MB
                Write-Log "ETL file Size: $EtlFileSize MB"
            } -ArgumentList ("eBPF", $LogFileName, $EtlFile) -ErrorAction Ignore

            # Copy ETL from Test VM.
            Write-Log ("Copy $WorkingDirectory\$EtlFile on $VMName to $pwd\TestLogs\$VMName\Logs")
            Copy-Item `
                -FromSession $VMSession `
                -Path "$VMSystemDrive\eBPF\$EtlFile" `
                -Destination ".\TestLogs\$VMName\Logs" `
                -Recurse `
                -Force `
                -ErrorAction Ignore 2>&1 | Write-Log
        }

        # Copy performance results from Test VM.
        Write-Log ("Copy performance results from eBPF on $VMName to $pwd\TestLogs\$VMName\Logs")
        Copy-Item `
            -FromSession $VMSession `
            -Path "$VMSystemDrive\eBPF\*.csv" `
            -Destination ".\TestLogs\$VMName\Logs" `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log

        # Compress and copy the performance profile if present.
        Invoke-Command -Session $VMSession -ScriptBlock {
            if (Test-Path $Env:SystemDrive\eBPF\bpf_performance*.etl -PathType Leaf) {
                tar czf $Env:SystemDrive\eBPF\bpf_perf_etls.tgz -C $Env:SystemDrive\eBPF bpf_performance*.etl
                dir $Env:SystemDrive\eBPF\bpf_performance*.etl
                Remove-Item -Path $Env:SystemDrive\eBPF\bpf_performance*.etl
            }
        }
        Write-Log ("Copy performance profile from eBPF on $VMName to $pwd\TestLogs\$VMName\Logs")
        Copy-Item `
            -FromSession $VMSession `
            -Path "$VMSystemDrive\eBPF\bpf_perf_etls.tgz" `
            -Destination ".\TestLogs\$VMName\Logs" `
            -Recurse `
            -Force `
            -ErrorAction Ignore 2>&1 | Write-Log
    }
    # Move runner test logs to TestLogs folder.
    Write-Host ("Copy $LogFileName from $env:TEMP on host runner to $pwd\TestLogs")
    Move-Item "$env:TEMP\$LogFileName" -Destination ".\TestLogs" -Force -ErrorAction Ignore 2>&1 | Write-Log
}

#
# Configure network adapters on VMs.
#
function Initialize-NetworkInterfacesOnVMs
{
    param([parameter(Mandatory=$true)] $VMMap)

    foreach ($VM in $VMMap)
    {
        $VMName = $VM.Name

        Write-Log "Initializing network interfaces on $VMName"
        $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

        Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
            param([Parameter(Mandatory=$True)] [string] $WorkingDirectory)

            Push-Location "$env:SystemDrive\$WorkingDirectory"

            Write-Host "Installing DuoNic driver"
            .\duonic.ps1 -Install -NumNicPairs 2
            # Disable Duonic's fake checksum offload and force TCP/IP to calculate it.
            Set-NetAdapterAdvancedProperty duo? -DisplayName Checksum -RegistryValue 0

            Pop-Location
        } -ArgumentList ("eBPF") -ErrorAction Stop
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

        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $ArtifactUrl -OutFile "$DownloadPath\artifact.zip"

        Write-Log "Extracting $ArtifactName"
        Expand-Archive -Path "$DownloadPath\artifact.zip" -DestinationPath $DownloadPath -Force
        Expand-Archive -Path "$DownloadPath\build-NativeOnlyRelease.zip" -DestinationPath $DownloadPath -Force

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
    $ArtifactName = "Release-v$ArtifactVersion/Build-x64-$Configuration.zip"
    $ArtifactUrl = "https://github.com/microsoft/ebpf-for-windows/releases/download/" + $ArtifactName

    Write-Log "Downloading regression test artifacts for version $ArtifactVersion" -ForegroundColor Green
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $ArtifactUrl -OutFile "$DownloadPath\artifact.zip"

    Write-Log "Extracting $ArtifactName"
    Expand-Archive -Path "$DownloadPath\artifact.zip" -DestinationPath $DownloadPath -Force
    Write-Log "Extracting $DownloadPath\build-$Configuration.zip"
    Expand-Archive -Path "$DownloadPath\build-$Configuration.zip" -DestinationPath $DownloadPath -Force


    # Copy all the drivers, DLLs, exe and .o files to pwd.
    Write-Log "Copy regression test artifacts to main folder" -ForegroundColor Green
    $ArtifactPath = "$DownloadPath\$Configuration"
    Push-Location $ArtifactPath
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
function Get-Duonic {
    # Download and extract https://github.com/microsoft/corenet-ci.
    $DownloadPath = "$pwd\corenet-ci"
    mkdir $DownloadPath
    Write-Host "Downloading CoreNet-CI to $DownloadPath"
    Invoke-WebRequest -Uri "https://github.com/microsoft/corenet-ci/archive/refs/heads/main.zip" -OutFile "$DownloadPath\corenet-ci.zip"
    Expand-Archive -Path "$DownloadPath\corenet-ci.zip" -DestinationPath $DownloadPath -Force
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\duonic\*" -Destination $pwd -Force
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\procdump64.exe" -Destination $pwd -Force
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\notmyfault64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse
}

# Download the Visual C++ Redistributable.
function Get-VCRedistributable {
    $url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $DownloadPath = "$pwd\vc-redist"
    mkdir $DownloadPath
    Write-Host "Downloading Visual C++ Redistributable from $url to $DownloadPath"
    Invoke-WebRequest -Uri $url -OutFile "$DownloadPath\vc_redist.x64.exe"
    Move-Item -Path "$DownloadPath\vc_redist.x64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse
}
