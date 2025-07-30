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
        $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword
        if ($VMIsRemote) {
            $VMSession = New-PSSession -ComputerName $VMName -Credential $TestCredential
        }
        else {
            $VMSession = New-PSSession -VMName $VMName -Credential $TestCredential
        }
        if (!$VMSession) {
            throw "Failed to create PowerShell session on $VMName."
        } else {
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
            $VMSystemDrive = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:SystemDrive}
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
        [Parameter(Mandatory=$false)][bool] $VMIsRemote = $false
    )

    Write-Log "Installing eBPF components on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    $scriptBlock = {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName,
              [Parameter(Mandatory=$true)] [bool] $KmTracing,
              [Parameter(Mandatory=$true)] [string] $KmTraceType,
              [parameter(Mandatory=$true)][string] $TestMode)
        $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Install-eBPFComponents -KmTracing $KmTracing -KmTraceType $KmTraceType -KMDFVerifier $true -TestMode $TestMode -ErrorAction Stop
    }

    Invoke-CommandOnVM -VMName $VMName -Credential $TestCredential -VMIsRemote $VMIsRemote -ScriptBlock $scriptBlock -ArgumentList  ("eBPF", $LogFileName, $KmTracing, $KmTraceType, $TestMode) -ErrorAction Stop

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

function Compress-KernelModeDumpOnVM
{
    param (
        [Parameter(Mandatory = $True)] [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory)

        Import-Module $env:SystemDrive\$WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

        $KernelModeDumpFileSourcePath = "$Env:WinDir"
        $KernelModeDumpFileDestinationPath = "$Env:SystemDrive\KernelDumps"

        # Create the compressed dump folder if doesn't exist.
        if (!(Test-Path $KernelModeDumpFileDestinationPath)) {
            Write-Log "Creating $KernelModeDumpFileDestinationPath directory."
            New-Item -ItemType Directory -Path $KernelModeDumpFileDestinationPath | Out-Null

            # Make sure it was created
            if (!(Test-Path $KernelModeDumpFileDestinationPath)) {
                $ErrorMessage = `
                    "*** ERROR *** Create compressed dump file directory failed: $KernelModeDumpFileDestinationPath`n"
                Write-Log $ErrorMessage
                Throw $ErrorMessage
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

            Compress-File -SourcePath $KernelModeDumpFileSourcePath\*.dmp -DestinationPath $KernelModeDumpFileDestinationPath\km_dumps.zip
            if (Test-Path $KernelModeDumpFileDestinationPath\km_dumps.zip -PathType Leaf) {
                $CompressedDumpFile = get-childitem -Path $KernelModeDumpFileDestinationPath\km_dumps.zip
                Write-Log "Found compressed kernel mode dump file in $($KernelModeDumpFileDestinationPath):"
                Write-Log `
                    "`tName:$($CompressedDumpFile.Name), Size:$((($CompressedDumpFile.Length) / 1MB).ToString("F2")) MB"
            } else {
                $ErrorMessage = "*** ERROR *** kernel mode dump compressed file not found.`n`n"
                Write-Log $ErrorMessage
                throw $ErrorMessage
            }
        } else {
            Write-Log "No kernel mode dump(s) in $($KernelModeDumpFileSourcePath)."
        }
    } -ArgumentList ("eBPF") -ErrorAction Ignore
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
        Compress-KernelModeDumpOnVM -Session $VMSession

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
            Write-Log "Local copy of kernel mode dump archive in $($LocalKernelArchiveLocation) for VM $($VMName):"
            Write-Log "`tName:$($LocalFile.Name), Size:$((($LocalFile.Length) / 1MB).ToString("F2")) MB"
        } else {
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

                Write-Log "Compressing $WorkingDirectory\$EtlFile ..."
                Compress-File -SourcePath "$WorkingDirectory\$EtlFile" -DestinationPath "$WorkingDirectory\$EtlFile.zip"
            } -ArgumentList ("eBPF", $LogFileName, $EtlFile) -ErrorAction Ignore

            # Copy ETL from Test VM.
            Write-Log ("Copy $VMSystemDrive\eBPF\$EtlFile.zip on $VMName to $pwd\TestLogs\$VMName\Logs")
            Copy-Item `
                -FromSession $VMSession `
                -Path "$VMSystemDrive\eBPF\$EtlFile.zip" `
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
        Write-Log "Query KM ETL tracing status before trace stop (host)"
        $ProcInfo = Start-Process -FilePath "wpr.exe" -ArgumentList "-status profiles collectors -details" -NoNewWindow -Wait -PassThru -RedirectStandardOut "$WorkingDirectory\StdOut.txt" -RedirectStandardError "$WorkingDirectory\StdErr.txt"
        if ($ProcInfo.ExitCode -ne 0) {
            Write-Log ("wpr.exe query ETL trace status failed. Exit code: " + $ProcInfo.ExitCode)
            Write-Log "wpr.exe (query) error output: "
            foreach ($line in Get-Content -Path "$WorkingDirectory\StdErr.txt") {
                Write-Log ( "\t" + $line)
            }
        } else {
            Write-Log "wpr.exe (query) results: "
            foreach ($line in Get-Content -Path "$WorkingDirectory\StdOut.txt") {
                Write-Log ( "  \t" + $line)
            }
        }
        Write-Log ("Query ETL trace status success. wpr.exe exit code: " + $ProcInfo.ExitCode + "`n" )
        Write-Log "Stop KM ETW tracing, create ETL file: $WorkingDirectory\$EtlFile"
        wpr.exe -stop "$WorkingDirectory\$EtlFile"
        $EtlFileSize = (Get-ChildItem "$WorkingDirectory\$EtlFile").Length/1MB
        Write-Log "ETL file Size: $EtlFileSize MB"
        Write-Log "Compressing $WorkingDirectory\$EtlFile ..."
        Compress-File -SourcePath "$WorkingDirectory\$EtlFile" -DestinationPath "$WorkingDirectory\$EtlFile.zip"
        $LogsDir = Join-Path $TestLogsDir 'Logs'
        if (!(Test-Path $LogsDir)) {
            New-Item -ItemType Directory -Path $LogsDir | Out-Null
        }
        Copy-Item "$WorkingDirectory\$EtlFile.zip" $LogsDir -Force -ErrorAction Ignore | Out-Null
    }
}

#
# Configure network adapters on VMs.
#
function Initialize-NetworkInterfaces {
    param(
        # Initialize network interfaces directly on the host
        [Parameter(Mandatory=$false)][bool] $ExecuteOnHost = $false,
        # Initialize network interfaces on VMs.
        [Parameter(Mandatory=$false)][bool] $ExecuteOnVM = $true,
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

    if ($ExecuteOnHost) {
        Write-Log "Initializing network interfaces on host"
        & $commandScriptBlock @argumentList
    } elseif ($ExecuteOnVM) {
        $TestCredential = New-Credential -Username $script:Admin -AdminPassword $script:AdminPassword
        foreach ($VM in $VMList) {
            $VMName = $VM.Name
            Write-Log "Initializing network interfaces on $VMName"

            Invoke-CommandOnVM -VMName $VMName -Credential $TestCredential -VMIsRemote $VMIsRemote  -ScriptBlock $commandScriptBlock -ArgumentList $argumentList -ErrorAction Stop
        }
    } else {
        throw "Either ExecuteOnHost or ExecuteOnVM must be set."
    }
}

#
# Queries registry for OS build information and logs it.
#
function Log-OSBuildInformationOnVM
{
    param([parameter(Mandatory=$true)][string] $VMName)

    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword
    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
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
        $vmCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword
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

.PARAMETER UserPassword
    The plain text password to use for the user accounts on the VM.

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
    Create-VM -VmName "MyVM" -UserPassword "Password -VhdPath "C:\MyVHD.vhd" -VmStoragePath "C:\VMStorage" -VMMemory 2GB -UnattendPath "C:\MyUnattend.xml" -VmSwitchName "VMInternalSwitch"
#>
function Create-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][string]$UserPassword,
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
        Replace-PlaceholderStrings -FilePath $VmUnattendPath -SearchString 'PLACEHOLDER_ADMIN_PASSWORD' -ReplaceString $UserPassword
        Replace-PlaceholderStrings -FilePath $VmUnattendPath -SearchString 'PLACEHOLDER_STANDARDUSER_PASSWORD' -ReplaceString $UserPassword

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

        # Create the VM
        Write-Log "Creating the VM"
        New-VM -Name $VmName -VhdPath $VmVhdPath -SwitchName $VmSwitchName
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

        # Start the VM
        Write-Log "Starting VM: $VmName"
        Start-VM -Name $VmName
        Wait-AllVMsToInitialize -VMList $vmList -UserName $Admin -AdminPassword $AdminPassword

        # Copy setup script to the VM and execute it.
        Write-Log "Executing VM configuration script ($VMSetupScript) on VM: $VmName"
        Copy-VMFile -VMName $VmName -FileSource Host -SourcePath $VMSetupScript -DestinationPath "$VMWorkingDirectory\$VMSetupScript" -CreateFullPath
        Execute-CommandOnVM -VMName $VmName -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine; cd $VMWorkingDirectory; .\$VMSetupScript"
        Write-Log "Successfully executed VM configuration script ($VMSetupScript) on VM: $VmName" -ForegroundColor Green

        Wait-AllVMsToInitialize -VMList $vmList -UserName $Admin -AdminPassword $AdminPassword

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
        [Parameter(Mandatory=$True)][string]$VmName
    )

    try {
        Write-Log "Enabling HVCI on VM: $VmName"
        $vmCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword
        Invoke-Command -VMName $VmName -Credential $vmCredential -ScriptBlock {
            # Enable HVCI
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -ItemType Directory -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Force
            # Restart the VM to apply changes
            Restart-Computer -Force -ErrorAction Stop
        }
    } catch {
        throw "Failed to enable HVCI on VM: $VmName with error: $_"
    }

    # Wait 1 minute for the VM to restart
    Write-Log "Waiting for 1 minute for VM: $VmName to restart"
    Start-Sleep -Seconds 60

    # Wait for the VM to restart and be ready again
    Write-Log "Waiting for VM: $VmName to restart and be ready again"
    Wait-AllVMsToInitialize -VMList @(@{ Name = $VmName }) -UserName $Admin -AdminPassword $AdminPassword

    Write-Log "HVCI enabled successfully on VM: $VmName" -ForegroundColor Green
}


function Invoke-CommandOnVM {
    param(
        [Parameter(Mandatory = $true)][ScriptBlock] $ScriptBlock,
        [Parameter(Mandatory = $false)][object[]] $ArgumentList = @(),
        [Parameter(Mandatory = $false)][bool] $VMIsRemote = $false,
        [Parameter(Mandatory = $true)][string] $VMName,
        [Parameter(Mandatory = $true)] $Credential
    )
    if ($VMIsRemote) {
        Invoke-Command -ComputerName $VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    } else {
        Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }
}