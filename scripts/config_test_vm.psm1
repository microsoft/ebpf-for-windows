# Copyright (c) Microsoft Corporation
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

    $tempFileName = [System.IO.Path]::GetTempFileName() + ".tgz"
    Write-Log "Creating $tempFileName containing files in $pwd"
    &tar @("cfz", "$tempFileName", "*")
    Write-Log "Created $tempFileName containing files in $pwd"

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
        Import-Module $WorkingDirectory\common.psm1 -ArgumentList ($LogFileName) -Force -WarningAction SilentlyContinue
        Import-Module $WorkingDirectory\install_ebpf.psm1 -ArgumentList ($WorkingDirectory, $LogFileName) -Force -WarningAction SilentlyContinue

        Install-eBPFComponents -Tracing $true -KMDFVerifier $true
        Enable-KMDFVerifier
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
            }
        } -ArgumentList ($Interfaces, "eBPF", $LogFileName) -ErrorAction Stop
    }
}
