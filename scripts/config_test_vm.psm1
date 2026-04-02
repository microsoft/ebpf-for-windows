# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

$sleepSeconds = 10

Push-Location $WorkingDirectory

Import-Module .\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue
Import-Module .\tracing_utils.psm1 -Force -ArgumentList ($LogFileName, $WorkingDirectory) -WarningAction SilentlyContinue

#
# VM Initialization functions
#

function Wait-AllVMsReadyForCommands
{
    param([Parameter(Mandatory=$True)]$VMList,
          [Parameter(Mandatory=$True)][PSCredential] $TestCredential,
          [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false)

    $totalSleepTime = 0
    $probeTimeout = 30  # Max seconds to wait for a single Invoke-Command probe.
    $ReadyList = @{}
    do {
        foreach($VM in $VMList) {
            $VMName = $VM.Name
            if ($ReadyList[$VMName] -ne $True) {
                Write-Log "Poking $VMName to see if it is ready to accept commands"
                $ret = $False
                try {
                    # Use -AsJob + Wait-Job to prevent Invoke-Command from blocking
                    # indefinitely when the VM is partially up (heartbeat OK but PS
                    # Direct transport hung).  Without this, the per-iteration sleep
                    # never runs and $totalSleepTime never increments, so the outer
                    # 5-minute timeout can never fire.
                    if ($VMIsRemote) {
                        $probeJob = Invoke-Command -ComputerName $VMName -Credential $TestCredential -ScriptBlock { $true } -AsJob -ErrorAction Stop
                    } else {
                        $probeJob = Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock { $true } -AsJob -ErrorAction Stop
                    }
                    $completed = $probeJob | Wait-Job -Timeout $probeTimeout
                    if ($completed) {
                        Receive-Job -Job $probeJob -ErrorAction Stop | Out-Null
                        $ret = $True
                    } else {
                        Write-Log "Probe of $VMName timed out after ${probeTimeout}s -- will retry."
                        Stop-Job -Job $probeJob -ErrorAction SilentlyContinue
                    }
                    Remove-Job -Job $probeJob -Force -ErrorAction SilentlyContinue
                } catch {
                        if (-not $VMIsRemote) {
                        # Transient PS Direct failures during restore/boot often look like this:
                        # "The credential is invalid." with PSDirectException / PSSessionStateBroken
                        $isTransient =
                            ($_.CategoryInfo.Reason -eq 'PSDirectException') -or
                            ($_.FullyQualifiedErrorId -eq 'PSSessionStateBroken') -or
                            ($_.Exception.Message -match 'credential is invalid')

                        if ($isTransient) {
                            Write-Log "PS Direct threw transient exception for $VMName - $($_.Exception.Message). Will retry."
                        } else {
                            Write-Log "PS Direct threw fatal exception for $VMName - $($_.Exception.Message)."
                            break
                        }
                    }
                }
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
        throw ("One or more VMs not ready after 5 minutes.")
    }
}

function Wait-AllVMsToInitialize
{
    param([Parameter(Mandatory=$True)]$VMList,
          [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false)

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

    $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
    Wait-AllVMsReadyForCommands -VMList $VMList -TestCredential $TestCredential -VMIsRemote:$VMIsRemote

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

    if (-not $VMIsRemote) {
        # Wait for VMs to be ready.
        Write-Log "Waiting for all the VMs to be in ready state..." -ForegroundColor Yellow
        Wait-AllVMsToInitialize -VMList $VMList
    } else {
        $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $true
        Wait-AllVMsReadyForCommands -VMList $VMList -TestCredential $TestCredential -VMIsRemote:$true
    }
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
    param(
        [Parameter(Mandatory=$True)] $VMList,
        [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false
    )

    $tempFileName = [System.IO.Path]::GetTempFileName() + ".tgz"
    Write-Log "Creating $tempFileName containing files in $pwd"
    &tar @("cfz", "$tempFileName", "*")
    Write-Log "Created $tempFileName containing files in $pwd"

    # Copy artifacts to the given VM list.
    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Exporting build artifacts to $VMName"
        $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
        try {
            $VMSession = New-SessionOnVM -VMName $VMName -VMIsRemote $VMIsRemote -Credential $TestCredential
        } catch {
            $VMSession = $null
        }
        if (!$VMSession) {
            ThrowWithErrorMessage -ErrorMessage "Failed to create PowerShell session on $VMName."
        } else {
            Write-Log "Created PowerShell session on $VMName"
            Invoke-Command -Session $VMSession -ScriptBlock {
                # Create working directory c:\eBPF.
                if(!(Test-Path "$Env:SystemDrive\eBPF")) {
                    New-Item -ItemType Directory -Path "$Env:SystemDrive\eBPF"
                }
                # Enable EULA for all SysInternals tools.
                $RegistryPath = 'HKCU:\Software\Sysinternals'
                if (-not (Test-Path $RegistryPath)) {
                    # Create the registry key if it doesn't exist
                    New-Item -Path $RegistryPath -Force
                }
                Set-ItemProperty -Path $RegistryPath -Name 'EulaAccepted' -Value 1

                # Enables full memory dump.
                # NOTE: This needs a VM with an explicitly created page file of *AT LEAST* (physical_memory + 1MB) in size.
                # The default value of the 'CrashDumpEnabled' key is 7 ('automatic' sizing of dump file size (system determined)).
                # https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value 1

                return $Env:SystemDrive
            }
            Write-Log "Created c:\eBPF, enabled SysInternals EULA and full memory dump on $VMName"
            $VMSystemDrive = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:SystemDrive}
            Write-Log "VM $VMName system drive is $VMSystemDrive"
        }
        Write-Log "Copying $tempFileName to $VMSystemDrive\eBPF on $VMName"
        Copy-Item -ToSession $VMSession -Path $tempFileName -Destination "$VMSystemDrive\eBPF\ebpf.tgz" -Force 2>&1 -ErrorAction Stop | Write-Log
        Write-Log "Copied $tempFileName to $VMSystemDrive\eBPF on $VMName"

        Write-Log "Unpacking $tempFileName to $VMSystemDrive\eBPF on $VMName"
        Invoke-Command -Session $VMSession -ScriptBlock {
            cd $Env:SystemDrive\eBPF
            &tar @("xf", "ebpf.tgz")
        }
        Write-Log "Unpacked $tempFileName to $VMSystemDrive\eBPF on $VMName"
        Write-Log "Export completed." -ForegroundColor Green

        Remove-PSSession $VMSession
    }

    Remove-Item -Force $tempFileName
}

#
# Install eBPF components on VM.
#
function Install-eBPFComponentsOnVM
{
    param(
        [parameter(Mandatory=$true)][string] $VMName,
        [parameter(Mandatory=$true)][string] $TestMode,
        [parameter(Mandatory=$true)][bool] $KmTracing,
        [parameter(Mandatory=$true)][string] $KmTraceType,
        [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false,
        [parameter(Mandatory=$false)][bool] $GranularTracing = $false
    )

    Write-Log "Installing eBPF components on $VMName"
    $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote

    $scriptBlock = {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName,
              [Parameter(Mandatory=$true)] [bool] $KmTracing,
              [Parameter(Mandatory=$true)] [string] $KmTraceType,
              [parameter(Mandatory=$true)][string] $TestMode,
              [parameter(Mandatory=$false)][bool] $GranularTracing = $false)
        $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Install-eBPFComponents -KmTracing $KmTracing -KmTraceType $KmTraceType -KMDFVerifier $true -TestMode $TestMode -GranularTracing $GranularTracing -ErrorAction Stop
    }

    Invoke-CommandOnVM -VMName $VMName -Credential $TestCredential -VMIsRemote $VMIsRemote -ScriptBlock $scriptBlock -ArgumentList  ("eBPF", $LogFileName, $KmTracing, $KmTraceType, $TestMode, $GranularTracing) -ErrorAction Stop

    Write-Log "eBPF components installed on $VMName" -ForegroundColor Green
}

function Uninstall-eBPFComponentsOnVM
{
    param([parameter(Mandatory=$true)][string] $VMName)

    Write-Log "Unnstalling eBPF components on $VMName"
    $TestCredential = Get-VMCredential -Username 'Administrator'

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
    param([parameter(Mandatory=$true)][string] $VMName,
          [parameter(Mandatory=$false)][bool] $GranularTracing = $false)

    Write-Log "Stopping eBPF components on $VMName"
    $TestCredential = Get-VMCredential -Username 'Administrator'

    Invoke-Command `
        -VMName $VMName `
        -Credential $TestCredential `
        -ScriptBlock {
            param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
                  [Parameter(Mandatory=$True)] [string] $LogFileName,
                  [Parameter(Mandatory=$false)] [bool] $GranularTracing = $false
            )

            $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
            Import-Module $WorkingDirectory\common.psm1 `
                -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

            Import-Module $WorkingDirectory\install_ebpf.psm1 `
                -ArgumentList($WorkingDirectory, $LogFileName) `
                -Force -WarningAction SilentlyContinue

            Stop-eBPFServiceAndDrivers -GranularTracing $GranularTracing

        } -ArgumentList ("eBPF", $LogFileName, $GranularTracing) -ErrorAction Stop

    Write-Log "eBPF components stopped on $VMName" -ForegroundColor Green
}

function Compress-KernelModeDumpOnVM
{
    param (
        [Parameter(Mandatory = $True)] [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)

        Import-Module $env:SystemDrive\$WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

        $KernelModeDumpFileSourcePath = "$Env:WinDir"
        $KernelModeDumpFileDestinationPath = "$Env:SystemDrive\KernelDumps"

        # Create the compressed dump folder if doesn't exist.
        if (!(Test-Path $KernelModeDumpFileDestinationPath)) {
            Write-Log "Creating $KernelModeDumpFileDestinationPath directory."
            Write-Log "Current user: $($env:USERNAME), SystemDrive: $($env:SystemDrive)"
            Write-Log "Working directory: $(Get-Location)"

            try {
                New-Item -ItemType Directory -Path $KernelModeDumpFileDestinationPath -Force -ErrorAction Stop | Out-Null
                Write-Log "Successfully created directory: $KernelModeDumpFileDestinationPath"
            } catch {
                $ErrorMessage = "*** ERROR *** Create compressed dump file directory failed: $KernelModeDumpFileDestinationPath. Error: $($_.Exception.Message)"
                Write-Log $ErrorMessage

                # Verify if directory creation failed and directory still doesn't exist
                if (!(Test-Path $KernelModeDumpFileDestinationPath)) {
                    Write-Log "*** ERROR *** Directory creation failed and directory does not exist. Treating as non-fatal and returning."
                    return
                }
            }
        }

        if (Test-Path $KernelModeDumpFileSourcePath\*.dmp -PathType Leaf) {
            Write-Log "Found kernel mode dump(s) in $($KernelModeDumpFileSourcePath):"
            $DumpFiles = get-childitem -Path $KernelModeDumpFileSourcePath\*.dmp
            foreach ($DumpFile in $DumpFiles) {
                Write-Log "`tName:$($DumpFile.Name), Size:$((($DumpFile.Length) / 1MB).ToString("F2")) MB"
            }

            Write-Log `
                "Compressing kernel dump files: $KernelModeDumpFileSourcePath -> $KernelModeDumpFileDestinationPath"

            $result = CompressOrCopy-File -SourcePath "$KernelModeDumpFileSourcePath\*.dmp" -DestinationDirectory $KernelModeDumpFileDestinationPath -CompressedFileName "km_dumps.zip"
            if ($result.Success) {
                Write-Log "Successfully compressed kernel dumps: $($result.FinalPath)"
            } else {
                Write-Log "Used uncompressed kernel dump fallback: $($result.FinalPath)"
            }
        } else {
            Write-Log "No kernel mode dump(s) in $($KernelModeDumpFileSourcePath)."
        }
    } -ArgumentList ("eBPF", $LogFileName) -ErrorAction Ignore
}

<#
.SYNOPSIS
    Ensures a PSSession to a VM is valid and usable, reconnecting if necessary.
.PARAMETER VMName
    The name of the VM.
.PARAMETER CurrentSession
    The current PSSession object (may be null or broken).
.PARAMETER TestCredential
    Credential to use for creating a new session.
.RETURNS
    A valid PSSession object, or $null if reconnection fails.
#>
function Get-ValidSession {
    param(
        [Parameter(Mandatory=$true)][string] $VMName,
        [Parameter(Mandatory=$false)][System.Management.Automation.Runspaces.PSSession] $CurrentSession,
        [Parameter(Mandatory=$true)][PSCredential] $TestCredential,
        [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false
    )

    # Check if current session is still usable.
    if ($CurrentSession -and $CurrentSession.State -eq 'Opened' -and $CurrentSession.Availability -eq 'Available') {
        return $CurrentSession
    }

    # Session is broken or unavailable - clean it up and create a new one.
    if ($CurrentSession) {
        $state = $CurrentSession.State
        $avail = $CurrentSession.Availability
        Write-Log "Session to $VMName is no longer valid (State: $state, Availability: $avail). Attempting to reconnect."
        try { Remove-PSSession $CurrentSession -ErrorAction SilentlyContinue } catch {}
    }

    # Try to create a new session with retries.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $newSession = New-SessionOnVM -VMName $VMName -VMIsRemote $VMIsRemote -Credential $TestCredential
            if ($newSession) {
                Write-Log "Successfully reconnected to $VMName (attempt $attempt)."
                return $newSession
            }
        } catch {
            Write-Log "Failed to reconnect to $VMName (attempt $attempt of 3): $($_.Exception.Message)"
            if ($attempt -lt 3) {
                Start-Sleep -Seconds (5 * $attempt)
            }
        }
    }

    Write-Log "*** WARNING *** Could not establish session to $VMName after 3 attempts."
    return $null
}

#
# Import test logs and dumps from VM.
#
function Import-ResultsFromVM
{
    param([Parameter(Mandatory=$True)] $VMList,
          [Parameter(Mandatory=$true)] $KmTracing,
          [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false)

    # NOTE: The caller (cleanup_ebpf_cicd_tests.ps1) already calls
    # Wait-AllVMsToInitialize with a try/catch before invoking this function.
    # Do NOT call it again here -- it adds up to 5 minutes of delay if the VM
    # is dead, and the caller has already determined whether the VM is reachable.

    foreach($VM in $VMList) {
        $VMName = $VM.Name
        Write-Log "Importing TestLogs from $VMName"
        if (!(Test-Path ".\TestLogs\$VMName")) {
            New-Item -ItemType Directory -Path ".\TestLogs\$VMName"
        }

        $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
        $VMSession = New-SessionOnVM -VMName $VMName -VMIsRemote $VMIsRemote -Credential $TestCredential
        if (!$VMSession) {
            Write-Log "*** WARNING *** Failed to create PowerShell session on $VMName. Skipping result import for this VM."
            continue
        }

        $VMSystemDrive = $null
        try {
            $VMSystemDrive = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:SystemDrive}
        } catch {
            Write-Log "*** WARNING *** Failed to get SystemDrive from ${VMName}: $($_.Exception.Message). Skipping this VM."
            continue
        }

        # --- Step 1: Kernel crash dumps ---
        Write-Log "[Step 1/6] Processing kernel crash dumps on $VMName"
        try {
            Compress-KernelModeDumpOnVM -Session $VMSession
        } catch {
            Write-Log "*** WARNING *** [Step 1/6] Failed to compress kernel dumps on ${VMName}: $($_.Exception.Message)"
        }

        $LocalKernelArchiveLocation = ".\TestLogs\$VMName\KernelDumps"
        if (!(Test-Path $LocalKernelArchiveLocation)) {
            New-Item -ItemType Directory -Path $LocalKernelArchiveLocation | Out-Null
        }

        try {
            $VMSession = Get-ValidSession -VMName $VMName -CurrentSession $VMSession -TestCredential $TestCredential -VMIsRemote $VMIsRemote
            if ($VMSession) {
                $result = CopyCompressedOrUncompressed-FileFromSession `
                    -VMSession $VMSession `
                    -CompressedSourcePath "$VMSystemDrive\KernelDumps\km_dumps.zip" `
                    -UncompressedSourcePath "$VMSystemDrive\Windows\*.dmp" `
                    -DestinationDirectory $LocalKernelArchiveLocation

                if ($result.Success) {
                    Write-Log "[Step 1/6] Copied compressed kernel dumps from ${VMName}: $($result.FinalPath)"
                } else {
                    Write-Log "[Step 1/6] Used uncompressed kernel dump fallback from ${VMName}: $($result.FinalPath)"
                }
            } else {
                Write-Log "*** WARNING *** [Step 1/6] Skipping kernel dump copy from $VMName - no valid session."
            }
        } catch {
            Write-Log "*** WARNING *** [Step 1/6] Failed to copy kernel dumps from ${VMName}: $($_.Exception.Message)"
        }

        # --- Step 2: User mode crash dumps ---
        Write-Log "[Step 2/6] Copying user-mode crash dumps from $VMName"
        try {
            $VMSession = Get-ValidSession -VMName $VMName -CurrentSession $VMSession -TestCredential $TestCredential -VMIsRemote $VMIsRemote
            if ($VMSession) {
                Copy-Item `
                    -FromSession $VMSession `
                    -Path "$VMSystemDrive\dumps" `
                    -Destination ".\TestLogs\$VMName" `
                    -Recurse `
                    -Force `
                    -ErrorAction Ignore 2>&1 | Write-Log

                # Copy performance results from Test VM.
                Write-Log "[Step 2/6] Copying performance CSVs from $VMName"
                Copy-Item `
                    -FromSession $VMSession `
                    -Path "$VMSystemDrive\eBPF\*.csv" `
                    -Destination ".\TestLogs\$VMName\Logs" `
                    -Recurse `
                    -Force `
                    -ErrorAction Ignore 2>&1 | Write-Log
            } else {
                Write-Log "*** WARNING *** [Step 2/6] Skipping dump/CSV copy from $VMName - no valid session."
            }
        } catch {
            Write-Log "*** WARNING *** [Step 2/6] Failed to copy dumps/CSVs from ${VMName}: $($_.Exception.Message)"
        }

        # --- Step 3: Test logs (LogFileName, app_output.log, app_error.log) ---
        Write-Log "[Step 3/6] Copying test logs from $VMName"
        if (!(Test-Path ".\TestLogs\$VMName\Logs")) {
            New-Item -ItemType Directory -Path ".\TestLogs\$VMName\Logs"
        }
        try {
            $VMSession = Get-ValidSession -VMName $VMName -CurrentSession $VMSession -TestCredential $TestCredential -VMIsRemote $VMIsRemote
            if ($VMSession) {
                $VMTemp = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:TEMP} -ErrorAction SilentlyContinue
                if ($VMTemp) {
                    Write-Log "[Step 3/6] Copy $LogFileName from $VMTemp on $VMName"
                    Copy-Item `
                        -FromSession $VMSession `
                        -Path "$VMTemp\$LogFileName" `
                        -Destination ".\TestLogs\$VMName\Logs" `
                        -Recurse `
                        -Force `
                        -ErrorAction Ignore 2>&1 | Write-Log

                    foreach ($testLog in @("app_output.log", "app_error.log")) {
                        $testLogPath = "$VMTemp\$testLog"
                        $exists = Invoke-Command -Session $VMSession -ScriptBlock { param($p) Test-Path $p } -ArgumentList $testLogPath -ErrorAction SilentlyContinue
                        if ($exists) {
                            Write-Log "[Step 3/6] Copy $testLog from $VMTemp on $VMName"
                            Copy-Item `
                                -FromSession $VMSession `
                                -Path $testLogPath `
                                -Destination ".\TestLogs\$VMName\Logs" `
                                -Force `
                                -ErrorAction Ignore 2>&1 | Write-Log
                        }
                    }
                }
            } else {
                Write-Log "*** WARNING *** [Step 3/6] Skipping log copy from $VMName - no valid session."
            }
        } catch {
            Write-Log "*** WARNING *** [Step 3/6] Failed to copy test logs from ${VMName}: $($_.Exception.Message)"
        }

        # --- Step 4: Stop kernel mode traces ---
        if ($KmTracing) {
            Write-Log "[Step 4/6] Stopping KM ETW traces on $VMName"
            try {
                $VMSession = Get-ValidSession -VMName $VMName -CurrentSession $VMSession -TestCredential $TestCredential -VMIsRemote $VMIsRemote
                if ($VMSession) {
                    $EtlFile = $LogFileName.Substring(0, $LogFileName.IndexOf('.')) + ".etl"
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
                        Import-Module `
                            $WorkingDirectory\tracing_utils.psm1 `
                            -ArgumentList ($LogFileName, $WorkingDirectory) `
                            -Force `
                            -WarningAction SilentlyContinue

                        $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($EtlFile)
                        Stop-WPRTrace -FileName $baseFileName
                    } -ArgumentList ("eBPF", $LogFileName, $EtlFile) -ErrorAction Ignore
                } else {
                    Write-Log "*** WARNING *** [Step 4/6] Skipping KM trace stop on $VMName - no valid session."
                }
            } catch {
                Write-Log "*** WARNING *** [Step 4/6] Failed to stop KM traces on ${VMName}: $($_.Exception.Message)"
            }
        } else {
            Write-Log "[Step 4/6] KM tracing not enabled, skipping."
        }

        # --- Step 5: ETL files ---
        Write-Log "[Step 5/6] Copying ETL trace files from $VMName"
        try {
            $VMSession = Get-ValidSession -VMName $VMName -CurrentSession $VMSession -TestCredential $TestCredential -VMIsRemote $VMIsRemote
            if ($VMSession) {
                Invoke-Command -Session $VMSession -ScriptBlock {
                    param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
                          [Parameter(Mandatory=$True)] [string] $LogFileName)
                    $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"

                    Import-Module "$WorkingDirectory\common.psm1" -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

                    if (Test-Path "$WorkingDirectory\TestLogs\*.etl" -PathType Leaf) {
                        Write-Log "Found ETL files in $WorkingDirectory\TestLogs"
                        Get-ChildItem "$WorkingDirectory\TestLogs\*.etl" | ForEach-Object {
                            Write-Log "  ETL file: $($_.Name), Size: $((($_.Length) / 1MB).ToString('F2')) MB"
                        }

                        Write-Log "Compressing ETL files..."
                        $compressionSucceeded = Compress-File -SourcePath "$WorkingDirectory\TestLogs\*.etl" -DestinationPath "$WorkingDirectory\traces.zip"
                        if (-not $compressionSucceeded -or -not (Test-Path "$WorkingDirectory\traces.zip")) {
                            Write-Log "*** WARNING *** ETL compression failed on VM. Will attempt to copy uncompressed ETL files."
                        } else {
                            Write-Log "Successfully compressed ETL files to traces.zip"
                        }
                    }
                } -ArgumentList ("eBPF", $LogFileName) -ErrorAction Ignore

                $tracingResult = CopyCompressedOrUncompressed-FileFromSession `
                    -VMSession $VMSession `
                    -CompressedSourcePath "$VMSystemDrive\eBPF\traces.zip" `
                    -UncompressedSourcePath "$VMSystemDrive\eBPF\TestLogs\*.etl" `
                    -DestinationDirectory ".\TestLogs\$VMName\Logs"
            } else {
                Write-Log "*** WARNING *** [Step 5/6] Skipping ETL copy from $VMName - no valid session."
            }
        } catch {
            Write-Log "*** WARNING *** [Step 5/6] Failed to copy ETL files from ${VMName}: $($_.Exception.Message)"
        }

        # --- Step 6: Performance profile ---
        Write-Log "[Step 6/6] Copying performance profile from $VMName"
        try {
            $VMSession = Get-ValidSession -VMName $VMName -CurrentSession $VMSession -TestCredential $TestCredential -VMIsRemote $VMIsRemote
            if ($VMSession) {
                Invoke-Command -Session $VMSession -ScriptBlock {
                    if (Test-Path $Env:SystemDrive\eBPF\bpf_performance*.etl -PathType Leaf) {
                        tar czf $Env:SystemDrive\eBPF\bpf_perf_etls.tgz -C $Env:SystemDrive\eBPF bpf_performance*.etl
                        dir $Env:SystemDrive\eBPF\bpf_performance*.etl
                        Remove-Item -Path $Env:SystemDrive\eBPF\bpf_performance*.etl
                    }
                }
                Copy-Item `
                    -FromSession $VMSession `
                    -Path "$VMSystemDrive\eBPF\bpf_perf_etls.tgz" `
                    -Destination ".\TestLogs\$VMName\Logs" `
                    -Recurse `
                    -Force `
                    -ErrorAction Ignore 2>&1 | Write-Log
            } else {
                Write-Log "*** WARNING *** [Step 6/6] Skipping perf profile copy from $VMName - no valid session."
            }
        } catch {
            Write-Log "*** WARNING *** [Step 6/6] Failed to copy performance profile from ${VMName}: $($_.Exception.Message)"
        }

        Write-Log "Completed importing results from $VMName"
    }
    # Move runner test logs to TestLogs folder.
    Write-Log "Copy $LogFileName from $env:TEMP on host runner to $pwd\TestLogs"
    Move-Item "$env:TEMP\$LogFileName" -Destination ".\TestLogs" -Force -ErrorAction Ignore 2>&1 | Write-Log
}

function Import-ResultsFromHost {
    param(
        [Parameter(Mandatory = $true)][bool] $KmTracing
    )
    Write-Log "Importing results from host..."
    $TestLogsDir = Join-Path $WorkingDirectory 'TestLogs'
    if (!(Test-Path $TestLogsDir)) {
        New-Item -ItemType Directory -Path $TestLogsDir | Out-Null
    }

    # Copy user mode crash dumps if any.
    if (Test-Path "$WorkingDirectory\dumps") {
        Copy-Item "$WorkingDirectory\dumps\*" "$TestLogsDir" -Recurse -Force -ErrorAction Ignore | Out-Null
    }

    # Stop and collect ETL trace if enabled.
    if ($KmTracing) {
        $EtlFile = $LogFileName.Substring(0, $LogFileName.IndexOf('.')) + ".etl"
        $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($EtlFile)
        Stop-WPRTrace -FileName $baseFileName
    }
    Write-Log "Completed Importing results from host..."
}

#
# Configure network adapters on VMs.
#
function Initialize-NetworkInterfaces {
    param(
        # Initialize network interfaces on VMs if set to true.
        # Initialize network interfaces directly on the host otherwise.
        [Parameter(Mandatory=$false)][bool] $ExecuteOnVM = $false,
        [Parameter(Mandatory=$false)] $VMList = @(),
        [Parameter(Mandatory=$true)][string] $TestWorkingDirectory,
        [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false
    )

    $commandScriptBlock = {
        param([Parameter(Mandatory=$true)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$true)][string] $LogFileName)
        Push-Location $WorkingDirectory
        Import-Module .\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Write-Log "Installing DuoNic driver"
        .\duonic.ps1 -Install -NumNicPairs 2
        Set-NetAdapterAdvancedProperty duo? -DisplayName Checksum -RegistryValue 0
        Pop-Location
    }

    $argumentList = @($TestWorkingDirectory, $LogFileName)

    if ($ExecuteOnVM) {
        # Execute on VMs.
        $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
        foreach ($VM in $VMList) {
            $VMName = $VM.Name
            Write-Log "Initializing network interfaces on $VMName"
            Invoke-CommandOnVM -VMName $VMName -VMIsRemote $VMIsRemote -Credential $TestCredential -ScriptBlock $commandScriptBlock -ArgumentList $argumentList -ErrorAction Stop
        }
    } else {
        Write-Log "Initializing network interfaces on host"
        & $commandScriptBlock @argumentList
    }

}

#
# Queries registry for OS build information and logs it.
#
function Log-OSBuildInformationOnVM
{
    param([parameter(Mandatory=$true)][string] $VMName,
          [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false)

    $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
    Invoke-CommandOnVM -VMName $VMName -VMIsRemote:$VMIsRemote -Credential $TestCredential -ScriptBlock {
        $buildLabEx = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'BuildLabEx'
        Write-Host "OS Build Information: $($buildLabEx.BuildLabEx)"
    }
}

<#
.SYNOPSIS
    Helper function to execute a command on a VM.

.DESCRIPTION
    This function executes a command on a specified VM using the provided credentials.

.PARAMETER VMName
    The name of the VM to execute the command on.

.PARAMETER Command
    The command to execute on the VM.
#>
function Execute-CommandOnVM {
    param (
        [Parameter(Mandatory=$True)][string]$VMName,
        [Parameter(Mandatory=$True)][string]$Command
    )

    try {
        $vmCredential = Get-VMCredential -Username 'Administrator'
        Write-Log "Executing command on VM: $VMName. Command: $Command"
        $result = Invoke-Command -VMName $VMName -Credential $VmCredential -ScriptBlock {
            param($Command)
            Invoke-Expression $Command
        } -ArgumentList $Command
        Write-Log "Successfully executed command on VM: $VMName. Command: $Command. Result: $result"
    } catch {
        throw "Failed to execute command on VM: $VMName with error: $_"
    }
}


<#
.SYNOPSIS
    Helper function to create a VM.

.DESCRIPTION
    This function creates a new VM with the specified parameters.

.PARAMETER VmName
    The name of the VM to create.

.PARAMETER VhdPath
    The path to the VHD file to use for the VM.

.PARAMETER VmStoragePath
    The storage path for the VM.

.PARAMETER VMMemory
    The amount of memory to allocate for the VM.

.PARAMETER UnattendPath
    The path to the unattend file to use for the VM. This will notably be used for configuring the user accounts and passwords.

.PARAMETER VmSwitchName
    The name of the switch to use for the VM.

.EXAMPLE
    Create-VM -VmName "MyVM" -VhdPath "C:\MyVHD.vhd" -VmStoragePath "C:\VMStorage" -VMMemory 2GB -UnattendPath "C:\MyUnattend.xml" -VmSwitchName "VMInternalSwitch"
#>
function Create-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][string]$VhdPath,
        [Parameter(Mandatory=$True)][string]$VmStoragePath,
        [Parameter(Mandatory=$True)][Int64]$VMMemory,
        [Parameter(Mandatory=$True)][string]$UnattendPath,
        [Parameter(Mandatory=$True)][string]$VmSwitchName
    )

    try {
        Write-Log "Creating VM: with Name: $VmName VhdPath: $VhdPath VmStoragePath: $VmStoragePath Memory: $VMMemory UnattendPath: $UnattendPath VMSwitchName: $VmSwitchName"
        ## Check for any pre-requisites
        # Check that the VHD exists
        if (-not (Test-Path -Path $VhdPath)) {
            throw "VHD not found at $VhdPath"
        }

        ## Create the VM
        # Create storage directory for the VM
        Create-DirectoryIfNotExists -Path $VmStoragePath

        # Move the VHD to the path
        Write-Log "Moving $VhdPath to $VmStoragePath"
        Move-Item -Path $VhdPath -Destination $VmStoragePath -Force
        $VmVhdPath = Join-Path -Path $VmStoragePath -ChildPath (Split-Path -Path $VhdPath -Leaf)

        # Move unattend to the path and replace placeholder strings
        Write-Log "Moving $UnattendPath file to $VmStoragePath"
        Move-Item -Path $UnattendPath -Destination $VmStoragePath -Force
        $VmUnattendPath = Join-Path -Path $VmStoragePath -ChildPath (Split-Path -Path $UnattendPath -Leaf)

        # Replace password placeholder in unattend.xml with the canonical password from Get-VMPassword.
        $password = Get-VMPassword
        (Get-Content -Path $VmUnattendPath -Raw).Replace('PLACEHOLDER_PASSWORD', $password) | Set-Content -Path $VmUnattendPath

        # Configure the VHD with the unattend file.
        Write-Log "Mounting VHD and applying unattend file"
        $VmMountPath = Join-Path -Path $VmStoragePath -ChildPath 'mountedVhd'
        if (-not (Test-Path -Path $VmMountPath)) {
            New-Item -ItemType Directory -Path $VmMountPath
        }
        Mount-WindowsImage -ImagePath $VmVhdPath -Index 1 -Path $VmMountPath -ErrorAction Stop | Out-Null
        Copy-Item -Path $VmUnattendPath -Destination $VmMountPath\Unattend.xml
        Apply-WindowsUnattend -Path $VmMountPath -UnattendPath $VmMountPath\Unattend.xml -ErrorAction Stop | Out-Null
        Dismount-WindowsImage -Path $VmMountPath -Save -ErrorAction Stop

        # Create the VM as Generation 2 with Secure Boot disabled so unsigned test drivers can load.
        Write-Log "Creating the VM (Generation 2)"
        New-VM -Name $VmName -VhdPath $VmVhdPath -SwitchName $VmSwitchName -Generation 2
        Set-VMFirmware -VMName $VmName -EnableSecureBoot Off
        Set-VMMemory -VMName $VmName -DynamicMemoryEnabled $false -StartupBytes $VMMemory

        if ((Get-VM -VMName $vmName) -eq $null) {
            throw "Failed to create VM: $VMName"
        }

        Write-Log "Successfully created VM: $VMName" -ForegroundColor Green
    } catch {
        throw "Failed to create VM: $VmName with error: $_"
    }
}

<#
.SYNOPSIS
    Helper function to configure a VM after creation.

.DESCRIPTION
    This function configures a VM after it has been created, including setting the processor count, enabling the Guest Service Interface, and executing a setup script.

.PARAMETER VmName
    The name of the VM to configure.

.PARAMETER VMCpuCount
    The number of processors to allocate for the VM.

.PARAMETER VMWorkingDirectory
    The working directory on the VM to use for executing the setup script. Defaults to 'C:\ebpf_cicd'.

.PARAMETER VMSetupScript
    The path to the setup script to execute on the VM. Defaults to '.\configure_vm.ps1'.

.EXAMPLE
    Initialize-VM -VmName "MyVM" -VMCpuCount 4
#>
function Initialize-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][int]$VMCpuCount,
        [Parameter(Mandatory=$False)][string]$VMWorkingDirectory='C:\ebpf_cicd',
        [Parameter(Mandatory=$False)][string]$VMSetupScript='.\configure_vm.ps1'
    )

    try {
        Write-Log "Configuring VM: $VmName"
        $vmList = @(
            @{
                Name = $VmName
            }
        )

        # Post VM creation configuration steps.
        Write-Log "Setting VM processor count to $VMCpuCount"
        Set-VMProcessor -VMName $VmName -Count $VMCpuCount
        Write-Log "Enabling Guest Service Interface"
        Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface'
        Write-Log "Enabling Time Synchronization"
        Enable-VMIntegrationService -VMName $VMName -Name 'Time Synchronization'

        # Log the final host-side VM configuration for diagnostics.
        $vmInfo = Get-VM -VMName $VmName
        $vmMemMB = [math]::Round($vmInfo.MemoryStartup / 1MB)
        $vmCpus = (Get-VMProcessor -VMName $VmName).Count
        $integrationServices = Get-VMIntegrationService -VMName $VmName | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name
        Write-Log "=== Host-side VM Configuration for $VmName ==="
        Write-Log "  Generation:            $($vmInfo.Generation)"
        Write-Log "  Memory:                ${vmMemMB} MB (Dynamic: $($vmInfo.DynamicMemoryEnabled))"
        Write-Log "  Processors:            $vmCpus"
        Write-Log "  Integration Services:  $($integrationServices -join ', ')"
        Write-Log "================================================"

        # Start the VM
        Write-Log "Starting VM: $VmName"
        Start-VM -Name $VmName
        Wait-AllVMsToInitialize -VMList $vmList

        # Copy setup script to the VM and execute it.
        Write-Log "Executing VM configuration script ($VMSetupScript) on VM: $VmName"
        Copy-VMFile -VMName $VmName -FileSource Host -SourcePath $VMSetupScript -DestinationPath "$VMWorkingDirectory\$VMSetupScript" -CreateFullPath
        Execute-CommandOnVM -VMName $VmName -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine; cd $VMWorkingDirectory; .\$VMSetupScript"
        Write-Log "Successfully executed VM configuration script ($VMSetupScript) on VM: $VmName" -ForegroundColor Green

        Wait-AllVMsToInitialize -VMList $vmList

        # Checkpoint the VM. This can sometimes fail if other operations are in progress, so retry a few times to ensure a successful checkpoint.
        for ($i = 0; $i -lt 5; $i += 1) {
            try {
                Write-Log "Checkpointing VM: $VmName"
                Checkpoint-VM -Name $VMName -SnapshotName 'baseline'
                $checkpoint = Get-VMSnapshot -VMName $vmName | Where-Object { $_.Name -eq 'baseline' }
                if ($checkpoint -eq $null) {
                    throw "Failed to create checkpoint for VM: $VmName"
                }
                Write-Log "Successfully added 'baseline' checkpoint for VM: $VMName" -ForegroundColor Green
                break
            } catch {
                Write-Log "Failed to checkpoint VM: $VmName. Retrying..."
                Start-Sleep -Seconds 5
                continue
            }
        }

        Write-Log "Successfully configured VM: $VmName" -ForegroundColor Green
    } catch {
        throw "Failed to configure VM: $VmName with error: $_"
    }
}

########## Helpers for the host machine ##########
<#
.SYNOPSIS
    Extracts .zip files in the specified directory and returns paths to .vhd and .vhdx files.

.DESCRIPTION
    This function takes an input directory as a parameter, looks inside the directory for any .zip files, extracts them, and returns a PowerShell string array of all full paths to .vhd and .vhdx files. It suppresses any output and throws errors if any exceptions are found.

.PARAMETER InputDirectory
    The directory to search for .zip files and extract them.

.EXAMPLE
    $vhdFiles = Prepare-VhdFiles -InputDirectory "C:\MyDirectory"
#>
function Prepare-VhdFiles {
    param (
        [Parameter(Mandatory=$true)][string]$InputDirectory
    )

    try {
        $zipFiles = Get-ChildItem -Path $InputDirectory -Filter *.zip -Recurse
        foreach ($zipFile in $zipFiles) {
            Expand-Archive -Path $zipFile.FullName -DestinationPath $InputDirectory *> $null 2>&1
        }

        # Get all .vhd and .vhdx files
        $vhdFiles = (Get-ChildItem -Path $InputDirectory -Recurse -Include *.vhd, *.vhdx) | Select-Object -ExpandProperty FullName

        if ($vhdFiles.Count -eq 0) {
            throw "No VHD files found in $InputDirectory"
        }

        return [string[]]$vhdFiles
    }
    catch {
        Get-ChildItem -Path $InputDirectory -Recurse
        throw "Failed to prepare VHD files with error: $_"
    }
}

<#
.SYNOPSIS
    Helper function to create a VM switch if it does not already exist.

.DESCRIPTION
    Checks if a VM switch with the given name and type already exists. If not, it creates a new switch of the specified type.

.PARAMETER SwitchName
    The name of the switch to create.

.PARAMETER SwitchType
    The type of switch to create. Can be 'External' or 'Internal'.

.EXAMPLE
    Create-VMSwitchIfNeeded -SwitchName 'VMInternalSwitch' -SwitchType 'Internal'
    Create-VMSwitchIfNeeded -SwitchName 'VMExternalSwitch' -SwitchType 'External'
#>
function Create-VMSwitchIfNeeded {
    param (
        [Parameter(Mandatory=$true)][string]$SwitchName,
        [Parameter(Mandatory=$true)][string]$SwitchType
    )

    if ($SwitchType -eq 'External') {
        # Check to see if an external switch already exists
        $ExternalSwitches = (Get-VMSwitch -SwitchType External -ErrorAction Ignore)
        if ($ExternalSwitches -ne $null) {
            Write-Log "External switch already exists: $($ExternalSwitches[0].Name)"
            return
        }

        # Try to create the external switch
        $NetAdapterNames = (Get-NetAdapter -Name 'Ethernet*' | Where-Object { $_.Status -eq 'Up' }).Name
        $index = 0
        foreach ($NetAdapterName in $NetAdapterNames) {
            try {
                if ([string]::IsNullOrEmpty($NetAdapterName)) {
                    continue
                }
                $currSwitchName = $SwitchName + '-' + $index
                Write-Log "Attempting to creating external switch: $currSwitchName with NetAdapter: $NetAdapterName"
                New-VMSwitch -Name $currSwitchName -NetAdapterName $NetAdapterName -AllowManagementOS $true
                $index += 1
            } catch {
                Write-Log "Failed to create external switch for NetAdapter: $NetAdapterName with error: $_"
            }
        }
    } elseif ($SwitchType -eq 'Internal') {
        # Check to see if an internal switch already exists
        $InternalSwitches = (Get-VMSwitch -SwitchType Internal -Name $SwitchName -ErrorAction Ignore)
        if ($InternalSwitches -ne $null) {
            Write-Log "Internal switch already exists: $($InternalSwitches[0].Name)"
            return
        }

        # Try to create the internal switch
        try {
            Write-Log "Creating internal switch"
            New-VMSwitch -Name $SwitchName -SwitchType Internal
        } catch {
            throw "Failed to create internal switch with error: $_"
        }
    } else {
        throw "Invalid switch type: $SwitchType"
    }

    Write-Log "Successfully created $SwitchType switch with name: $SwitchName" -ForegroundColor Green
}

<#
.SYNOPSIS
    Helper function to enable HVCI on the target VM.

.DESCRIPTION
    This function enables Hypervisor-protected Code Integrity (HVCI) on the specified VM.

.PARAMETER VmName
    The name of the VM on which to enable HVCI.

.EXAMPLE
    Enable-HVCIOnVM -VmName 'MyVM'
#>
function Enable-HVCIOnVM {
    param (
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false
    )

    try {
        Write-Log "Enabling HVCI on VM: $VmName"
        $vmCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
        $commandScriptBlock = {
            # Enable HVCI
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -ItemType Directory -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Force
            # Restart the VM to apply changes
            Restart-Computer -Force -ErrorAction Stop
        }
        Invoke-CommandOnVM -VMName $VmName -VMIsRemote $VMIsRemote -Credential $vmCredential -ScriptBlock $commandScriptBlock
    } catch {
        throw "Failed to enable HVCI on VM: $VmName with error: $_"
    }

    # Wait 1 minute for the VM to restart
    Write-Log "Waiting for 1 minute for VM: $VmName to restart"
    Start-Sleep -Seconds 60

    $VMList = @(@{ Name = $VmName })
    if (-not $VMIsRemote){
        # Wait for the VM to restart and be ready again
        Write-Log "Waiting for VM: $VmName to restart and be ready again"
        Wait-AllVMsToInitialize -VMList $VMList
    } else {
        $TestCredential = Get-VMCredential -Username 'Administrator' -VMIsRemote $VMIsRemote
        Wait-AllVMsReadyForCommands -VMList $VMList -TestCredential $TestCredential -VMIsRemote:$VMIsRemote
    }

    Write-Log "HVCI enabled successfully on VM: $VmName" -ForegroundColor Green
}