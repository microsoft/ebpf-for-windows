# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$True)] [string] $Admin,
       [Parameter(Mandatory=$True)] [SecureString] $AdminPassword,
       [Parameter(Mandatory=$True)] [string] $LogFileName)

Import-Module $PSScriptRoot\common.psm1 -Force -ArgumentList ($LogFileName) -WarningAction SilentlyContinue

$sleepSeconds = 10

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
        Write-Log "Restoring VM $VMName"
        Restore-VMSnapshot -Name 'baseline' -VMName $VM.Name -Confirm:$false
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

    $WorkingDirectory = $pwd.ToString()

    # Files to copy, in format "destination in VM" = "source path in host".
    $filesToCopy =
    @{
        "common.psm1" = "$PSScriptRoot\common.psm1";
        "run_driver_tests.psm1" = "$PSScriptRoot\run_driver_tests.psm1";
        "vm_run_tests.psm1" = "$PSScriptRoot\vm_run_tests.psm1";
        "ebpf-for-windows.msi" = "$WorkingDirectory\ebpf-for-windows-0.4.0.msi";
    }

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

        $filesToCopy.GetEnumerator() | ForEach-Object {
            $srcFile = $_.Value
            $dstFile = $VMSystemDrive + "\eBPF\" + $_.Name
            Write-Log "Copying $srcFile to $dstFile on $VMName"
            Copy-Item -ToSession $VMSession -Path $srcFile -Destination $dstFile -Force 2>&1 -ErrorAction Stop | Write-Log
            Write-Log "Copied $srcFile to $dstFile on $VMName"
        }

        Write-Log "Export completed." -ForegroundColor Green
    }
}

#
# Import test logs from VM.
#

function Import-ResultsFromVM
{
    param([Parameter(Mandatory=$True)] $VMList)

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

        # Copy kernel crash dumps if any.
        Invoke-Command -Session $VMSession -ScriptBlock {
            if (!(Test-Path "$Env:SystemDrive\KernelDumps")) {
                New-Item -ItemType Directory -Path "$Env:SystemDrive\KernelDumps"
            }
            Move-Item $Env:WinDir\*.dmp $Env:SystemDrive\KernelDumps -ErrorAction Ignore
        }
        Copy-Item -FromSession $VMSession "$VMSystemDrive\KernelDumps" -Destination ".\TestLogs\$VMName" -Recurse -Force -ErrorAction Ignore 2>&1 | Write-Log

        # Copy user mode crash dumps if any.
        Copy-Item -FromSession $VMSession "$VMSystemDrive\dumps" -Destination ".\TestLogs\$VMName" -Recurse -Force -ErrorAction Ignore 2>&1 | Write-Log

        # Copy logs from Test VM.
        if (!(Test-Path ".\TestLogs\$VMName\Logs")) {
            New-Item -ItemType Directory -Path ".\TestLogs\$VMName\Logs"
        }

        $VMTemp = Invoke-Command -Session $VMSession -ScriptBlock {return $Env:TEMP}
        Write-Log ("Copy $LogFileName from $VMTemp on $VMName to $pwd\TestLogs")
        Copy-Item -FromSession $VMSession "$VMTemp\$LogFileName" -Destination ".\TestLogs\$VMName\Logs" -Recurse -Force -ErrorAction Ignore 2>&1 | Write-Log

        Write-Log ("Copy CodeCoverage from eBPF on $VMName to $pwd\..\..")
        Copy-Item -FromSession $VMSession "$VMSystemDrive\eBPF\ebpf_for_windows.xml" -Destination "$pwd\..\.." -Recurse -Force -ErrorAction Ignore 2>&1 | Write-Log

        $EtlFile = $LogFileName.Substring(0, $LogFileName.IndexOf('.')) + ".etl"

        # Stop ETW Traces.
        Invoke-Command -Session $VMSession -ScriptBlock {
            param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
                  [Parameter(Mandatory=$True)] [string] $LogFileName,
                  [Parameter(Mandatory=$True)] [string] $EtlFile)
            $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

            Write-Log ("Stopping ETW tracing, creating file: " + $EtlFile)
            Start-Process -FilePath "wpr.exe" -ArgumentList @("-stop", "$WorkingDirectory\$EtlFile") -NoNewWindow -Wait
        } -ArgumentList ("eBPF", $LogFileName, $EtlFile) -ErrorAction Ignore

        # Copy ETL from Test VM.
        Write-Log ("Copy $EtlFile from eBPF on $VMName to $pwd\TestLogs")
        Copy-Item -FromSession $VMSession -Path "$VMSystemDrive\eBPF\$EtlFile" -Destination ".\TestLogs\$VMName\Logs" -Recurse -Force -ErrorAction Ignore 2>&1 | Write-Log
    }
    # Move runner test logs to TestLogs folder.
    Move-Item $LogFileName -Destination ".\TestLogs" -Force -ErrorAction Ignore 2>&1 | Write-Log
}

function Install-eBPFComponentsOnVM
{
    param([parameter(Mandatory=$true)] [string] $VMName)

    Write-Log "Installing eBPF components on $VMName"
    $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
        param([Parameter(Mandatory=$True)] [string] $WorkingDirectory,
              [Parameter(Mandatory=$True)] [string] $LogFileName)
        $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"

        # TODO: remove the following DEBUG output line.
        dir $WorkingDirectory

        # Enable driver verifier on the drivers we'll be installing.
        $EbpfDrivers =
        @{
            "EbpfCore" = "ebpfcore.sys";
            "NetEbpfExt" = "netebpfext.sys";
            "SampleEbpfExt" = "sample_ebpf_ext.sys"
        }
        $EbpfDrivers.GetEnumerator() | ForEach-Object {
            New-Item -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Force -ErrorAction Stop
            New-ItemProperty -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Name "VerifierOn" -Value 1 -PropertyType DWord -Force -ErrorAction Stop
            New-ItemProperty -Path ("HKLM:\System\CurrentControlSet\Services\{0}\Parameters\Wdf" -f $_.Name) -Name "TrackHandles" -Value "*" -PropertyType MultiString -Force  -ErrorAction Stop
        }

        Write-Host -NoNewLine "Checking credentials: "
        whoami /groups | findstr Label

        # Specify ADDLOCAL=All to install all features, to make sure we get the testing component needed by tests.
        Write-Host "executing : msiexec.exe /i '$WorkingDirectory\ebpf-for-windows.msi' /quiet /qn /l*v '$WorkingDirectory\$LogFileName' ADDLOCAL=All" -ForegroundColor Green
        msiexec.exe /i "$WorkingDirectory\ebpf-for-windows.msi" /quiet /qn /l*v "$WorkingDirectory\$LogFileName" ADDLOCAL=All
        sleep 5

        # If the install succeeded, this should show bpftool usage.
        # TODO: this step currently fails!
        bpftool.exe

        # TODO: remove the following DEBUG output lines.
        $EbpfPath = $env:ProgramFiles + "\ebpf-for-windows"
        $TestingPath = $EbpfPath + "\testing\testing"
        ls -R $EbpfPath
        ls -R $TestingPath

    } -ArgumentList ("eBPF", $LogFileName) -ErrorAction Stop
    Write-Log "eBPF components installed on $VMName" -ForegroundColor Green
}

function Initialize-NetworkInterfacesOnVMs
{
    param([parameter(Mandatory=$true)] $MultiVMTestConfig)

    foreach ($VM in $MultiVMTestConfig)
    {
        $VMName = $VM.Name
        $Interfaces = $VM.Interfaces

        # TODO: remove DEBUG output lines.
        Write-Output "DEBUG0 $VMName"
        Write-Log "Initializing network interfaces on $VMName"
        $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

        Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
            param([Parameter(Mandatory=$True)] $InterfaceList,
                  [Parameter(Mandatory=$True)] [string] $WorkingDirectory,
                  [Parameter(Mandatory=$True)] [string] $LogFileName)
            $WorkingDirectory = "$env:SystemDrive\$WorkingDirectory"
            Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue

            foreach ($Interface in $InterfaceList) {
                $InterfaceAlias = $Interface.Alias
                $V4Address = $Interface.V4Address
                Write-Log "Adding $V4Address on $InterfaceAlias"
                Remove-NetIPAddress -ifAlias "$InterfaceAlias" -IPAddress $V4Address -PolicyStore "All" -Confirm:$false -ErrorAction Ignore | Out-Null
                New-NetIPAddress -ifAlias "$InterfaceAlias" -IPAddress $V4Address -PrefixLength 24 -ErrorAction Stop | Out-Null
                Write-Log "Address configured."

                $V6Address = $Interface.V6Address
                Write-Log "Adding $V6Address on $InterfaceAlias"
                Remove-NetIPAddress -ifAlias "$InterfaceAlias" -IPAddress $V6Address* -PolicyStore "All" -Confirm:$false -ErrorAction Ignore | Out-Null
                New-NetIPAddress -ifAlias "$InterfaceAlias" -IPAddress $V6Address -PrefixLength 64 -ErrorAction Stop | Out-Null
                Write-Log "Address configured."
                Write-Log "DEBUG1"
            }
            Write-Output "DEBUG2a"
            Write-Log "DEBUG2"
            Write-Output "DEBUG2b"
        } -ArgumentList ($Interfaces, "eBPF", $LogFileName) -ErrorAction Stop
        Write-Output "DEBUG3a"
        Write-Log "DEBUG3"
        Write-Output "DEBUG3b"
    }
    Write-Output "DEBUG4a"
    Write-Log "DEBUG4"
    Write-Output "DEBUG4b"
}
