# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
$ErrorActionPreference = "Stop"

function Log-Message {
    param(
        [Parameter(Mandatory=$True)][string]$Message,
        [Parameter(Mandatory=$False)][string]$ForegroundColor='White'
    )

    # Get timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Host "[$timestamp] - $Message" -ForegroundColor $ForegroundColor
}

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
        throw "Failed to create directory: $Path. $_"
    }
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

function Execute-CommandOnVM {
    param (
        [Parameter(Mandatory=$True)][string]$VMName,
        [Parameter(Mandatory=$True)][System.Management.Automation.PSCredential]$VmCredential,
        [Parameter(Mandatory=$True)][string]$Command
    )

    try {
        $result = Invoke-Command -VMName $VMName -Credential $VmCredential -ScriptBlock {
            param($Command)
            Invoke-Expression $Command
        } -ArgumentList $Command

        Log-Message -Message "Executed command on VM: $VMName. Command: $Command. Result: $result"
    } catch {
        throw "Failed to execute command on VM: $VMName. Error: $_"
    }
}

function Wait-ForVMReady {
    param (
        [Parameter(Mandatory=$True)][string]$VMName,
        [Parameter(Mandatory=$True)][System.Management.Automation.PSCredential]$VmCredential,
        [Parameter(Mandatory=$False)][int]$TimeoutInMinutes=30
    )

    # Attempt for a maximum of 30 minutes
    $limit = (Get-Date).AddMinutes($TimeoutInMinutes)
    while ((Get-Date) -le $limit) {
        try {
            # Ensure the VM is in running state
            while ((Get-VM -Name $VMName).State -ne 'Running') {
                Log-Message -Message "Waiting for $VMName to reach running state..."
                Start-Sleep -Seconds 5
            }

            # Trivial command to ensure that we can connect to the VM.
            try {
                Execute-CommandOnVM -VMName $VMName -VmCredential $VmCredential -Command 'hostname'
            } catch {
                Log-Message -Message "Failed to connect to $VMName. Retrying..."
                Start-Sleep -Seconds 5
                continue
            }

            Log-Message -Message "Successfully connected to $VMName"
            return
        } catch {
            # Do nothing. We will retry if we failed to connect to the VM.
        }

        Log-Message -Message "Failed to connect to $VMName. Retrying..."
        Start-Sleep -Seconds 5
    }

    # If we reached here, we failed to connect to the VM.
    throw "Failed to connect to $VMName after timeout..."
}

# function Update-VM {
#     param (
#         [Parameter(Mandatory=$True)][string]$VMName,
#         [Parameter(Mandatory=$True)][System.Management.Automation.PSCredential]$VmCredential
#     )

# # TODO debugging output - remove later
#     Get-VMNetworkAdapter -All
#     try { Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "ipconfig /all" } catch { Log-Message -Message "Failed to query IP config: $_" -ForegroundColor Red }

#     try { Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "Invoke-WebRequest bing.com" } catch { Log-Message -Message "Failed to connect to the internet: $_" -ForegroundColor Red }

#     try { Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "Install-PackageProvider -Name NuGet -Force" } catch { Log-Message -Message "Failed to install NuGet provider: $_" -ForegroundColor Red }
#     try { Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "Install-Module -Name PSWindowsUpdate -Force" } catch { Log-Message -Message "Failed to install PSWindowsUpdate module: $_" -ForegroundColor Red }
#     try { Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "Get-WindowsUpdate -Install -AcceptAll -AutoReboot" } catch { Log-Message -Message "Failed to install updates: $_" -ForegroundColor Red }

#     Sleep -Seconds 300 # Sleep for 5 minutes to let the VM start fetching updates, etc...
#     Wait-ForVMReady -VMName $VMName -VmCredential $VmCredential
#     Log-Message -Message "Successfully updated VM: $VMName" -ForegroundColor Green
# }

function Create-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][string]$VmUsername,
        [Parameter(Mandatory=$True)][string]$VmPassword,
        [Parameter(Mandatory=$True)][string]$VhdPath,
        [Parameter(Mandatory=$True)][string]$VmStoragePath,
        [Parameter(Mandatory=$True)][string]$ExternalVMSwitchName,
        [Parameter(Mandatory=$True)][Int64]$VMMemory,
        [Parameter(Mandatory=$True)][string]$UnattendPath
    )

    try {
        ## Check for any pre-requisites
        # Check that the VHD exists
        if (-not (Test-Path -Path $VhdPath)) {
            throw "VHD not found at $VhdPath"
        }

        ## Create the VM
        # Create storage directory for the VM
        Create-DirectoryIfNotExists -Path $VmStoragePath

        # Move the VHD to the path
        Log-Message "Moving $VhdPath to $VmStoragePath"
        Move-Item -Path $VhdPath -Destination $VmStoragePath -Force
        $VmVhdPath = Join-Path -Path $VmStoragePath -ChildPath (Split-Path -Path $VhdPath -Leaf)

        # Move unattend to the path
        Log-Message "Moving $UnattendPath file to $VmStoragePath"
        Move-Item -Path $UnattendPath -Destination $VmStoragePath -Force
        $VmUnattendPath = Join-Path -Path $VmStoragePath -ChildPath (Split-Path -Path $UnattendPath -Leaf)
        Replace-PlaceholderStrings -FilePath $VmUnattendPath -SearchString 'PLACEHOLDER_USERNAME' -ReplaceString $VmUsername
        Replace-PlaceholderStrings -FilePath $VmUnattendPath -SearchString 'PLACEHOLDER_PASSWORD' -ReplaceString $VmPassword

        # Configure the VHD with the unattend file.
        Log-Message "Mounting VHD and applying unattend file"
        $VmMountPath = Join-Path -Path $VmStoragePath -ChildPath 'mountedVhd'
        if (-not (Test-Path -Path $VmMountPath)) {
            New-Item -ItemType Directory -Path $VmMountPath
        }
        Mount-WindowsImage -ImagePath $VmVhdPath -Index 1 -Path $VmMountPath -ErrorAction Stop | Out-Null
        Copy-Item -Path $VmUnattendPath -Destination $VmMountPath\Unattend.xml
        Apply-WindowsUnattend -Path $VmMountPath -UnattendPath $VmMountPath\Unattend.xml -ErrorAction Stop | Out-Null
        Dismount-WindowsImage -Path $VmMountPath -Save -ErrorAction Stop

        # Create the VM
        Log-Message "Creating the VM"
        New-VM -Name $VmName -VhdPath $VmVhdPath
        $vmSwitches = Get-VMSwitch
        foreach ($switch in $vmSwitches) {
            Log-Message "Adding network adapter to VM: $VmName with switch: $($switch.Name)"
            Add-VMNetworkAdapter -VMName $VmName -SwitchName $switch.Name
        }
        Set-VMMemory -VMName $VmName -DynamicMemoryEnabled $false -StartupBytes $VMMemory

        if ((Get-VM -VMName $vmName) -eq $null) {
            throw "Failed to create VM: $VMName"
        }

        Log-Message -Message "Successfully created VM: $VMName" -ForegroundColor Green
    } catch {
        throw "Failed to create VM: $VmName. Error: $_"
    }
}

function Configure-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][string]$VmUsername,
        [Parameter(Mandatory=$True)][string]$VmPassword,
        [Parameter(Mandatory=$True)][int]$CpuCount,
        [Parameter(Mandatory=$False)][string]$VMWorkingDirectory='C:\ebpf_cicd',
        [Parameter(Mandatory=$False)][string]$VMSetupScript='.\configure_vm.ps1'
    )

    try {
        Log-Message "Configuring VM: $VmName"

        # Post VM creation configuration steps.
        Log-Message "Setting VM processor count to $CpuCount"
        Set-VMProcessor -VMName $VmName -Count $CpuCount
        Log-Message "Enabling Guest Service Interface"
        Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface'

        # Get the VM credential
        $VmCredential = Create-VMCredential -VmUsername $VmUsername -VmPassword $VmPassword

        # Start the VM
        Log-Message "Starting VM: $VmName"
        Start-VM -Name $VmName
        Wait-ForVMReady -VMName $VmName -VmCredential $VmCredential

        Log-Message "Sleeping for 1 minute to let the VM get into a steady state"
        Sleep -Seconds 60 # Sleep for 1 minute to let the VM get into a steady state.

        # Fetch all updates on the VM
        Log-Message "Fetching Updates on the VM"
        # Update-VM -VMName $VmName -VmCredential $VmCredential
        Log-Message -Message "Successfully updated VM: $VMName" -ForegroundColor Green

        # Copy setup script to the VM and execute it.
        Log-Message "Executing VM configuration script ($VMSetupScript) on VM: $VmName"
        Copy-VMFile -VMName $VmName -FileSource Host -SourcePath $VMSetupScript -DestinationPath "$VMWorkingDirectory\$VMSetupScript" -CreateFullPath
        Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "cd $VMWorkingDirectory; .\$VMSetupScript"
        Log-Message "Sleeping for 1 minute to let the VM get into a steady state"
        Sleep -Seconds 60 # Sleep for 1 minute to let the VM get into a steady state.
        Log-Message -Message "Successfully executed VM configuration script ($VMSetupScript) on VM: $VmName" -ForegroundColor Green

        Wait-ForVMReady -VMName $VmName -VmCredential $VmCredential

        # Checkpoint the VM. This can sometimes fail if other operations are in progress.
        for ($i = 0; $i -lt 5; $i += 1) {
            try {
                Log-Message "Checkpointing VM: $VmName"
                Checkpoint-VM -Name $VMName -SnapshotName 'baseline'
                Log-Message -Message "Successfully added 'baseline' checkpoint for VM: $VMName" -ForegroundColor Green
                break
            } catch {
                Log-Message "Failed to checkpoint VM: $VmName. Retrying..."
                Start-Sleep -Seconds 5
                continue
            }
        }
    } catch {
        throw "Failed to configure VM: $VmName. Error: $_"
    }
}

########## Helpers for the host machine ##########
function Install-HyperVIfNeeded {
    try {
        if ((Get-WindowsFeature -Name 'Hyper-V').Installed) {
            Log-Message -Message 'Hyper-V is already installed on this host'
        } else {
            Log-Message -Message 'Hyper-V is not installed on this host. Installing now...'

            Import-Module ServerManager
            Install-WindowsFeature -Name 'Hyper-V' -IncludeManagementTools
            Restart-Computer -Force
            exit 1
        }
    } catch {
        throw "Failed to install Hyper-V: $_"
    }
}

function Create-VMSwitchIfNeeded {
    param (
        [Parameter(Mandatory=$False)][string]$SwitchName='VMInternalSwitch',
        [Parameter(Mandatory=$False)][string]$SwitchType='Internal'
    )
    try {
        if ($SwitchType -eq 'External') {
            # Check to see if an external switch already exists
            $ExternalSwitches = (Get-VMSwitch -SwitchType External)
            if ($ExternalSwitches -ne $null) {
                Log-Message -Message "External switch already exists: $($ExternalSwitches[0].Name)"
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
                    $switchName = $ExternalSwitchName + '-' + $index
                    Log-Message "Attempting to creating external switch: $switchName with NetAdapter: $NetAdapterName"
                    New-VMSwitch -Name $switchName -NetAdapterName $NetAdapterName -AllowManagementOS $true
                    # break
                } catch {
                    Log-Message "Failed to create external switch for NetAdapter: $NetAdapterName $_"
                }
            }
        } elseif ($SwitchType -eq 'Internal') {
            # Check to see if an internal switch already exists
            $InternalSwitches = (Get-VMSwitch -SwitchType Internal)
            if ($InternalSwitches -ne $null) {
                Log-Message -Message "Internal switch already exists: $($InternalSwitches[0].Name)"
                return
            }

            # Try to create the internal switch
            Log-Message "Creating internal switch"
            New-VMSwitch -Name 'VMInternalSwitch' -SwitchType Internal
        } else {
            throw "Invalid switch type: $SwitchType"
        }
    } catch {
        throw "Failed to create external switch: $_"
    }
}

function Create-VMStoredCredential {
    param (
        [Parameter(Mandatory=$True)][string]$CredentialName,
        [Parameter(Mandatory=$True)][string]$Username,
        [Parameter(Mandatory=$True)][string]$Password
    )
    try {
        Install-Module -Name CredentialManager -Scope AllUsers -Force
        Import-Module CredentialManager -Force

        New-StoredCredential -Target $CredentialName -UserName $Username -Password $Password -Type Generic -Persist LocalMachine
    } catch {
        Log-Message "Failed to create stored credential: $_" -ForegroundColor Red
        # throw "Failed to create stored credential: $_"
    }
}