# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Helper function to execute a command on a VM.

.DESCRIPTION
    This function executes a command on a specified VM using the provided credentials.

.PARAMETER VMName
    The name of the VM to execute the command on.

.PARAMETER VmCredential
    The credentials to use for executing the command on the VM.

.PARAMETER Command
    The command to execute on the VM.
#>
function Execute-CommandOnVM {
    param (
        [Parameter(Mandatory=$True)][string]$VMName,
        [Parameter(Mandatory=$True)][System.Management.Automation.PSCredential]$VmCredential,
        [Parameter(Mandatory=$True)][string]$Command
    )

    try {
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
    Helper function to wait for a VM to be ready.

.DESCRIPTION
    This function waits for a VM to be in the 'Running' state and then connects to it using a simple command.

.PARAMETER VMName
    The name of the VM to wait for.

.PARAMETER VmCredential
    The credentials to use for connecting to the VM.

.PARAMETER TimeoutInMinutes
    The maximum time to wait for the VM to be ready, in minutes. Defaults to 30 minutes.

.EXAMPLE
    Wait-ForVMReady -VMName "MyVM" -VmCredential $myCredential -TimeoutInMinutes 20
#>
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
                Write-Log "Waiting for $VMName to reach running state..."
                Start-Sleep -Seconds 5
            }

            # Trivial command to ensure that we can connect to the VM.
            try {
                Execute-CommandOnVM -VMName $VMName -VmCredential $VmCredential -Command 'hostname'
            } catch {
                Write-Log "Failed to connect to $VMName. Retrying..."
                Start-Sleep -Seconds 5
                continue
            }

            Write-Log "Successfully connected to $VMName"
            return
        } catch {
            # Do nothing. We will retry if we failed to connect to the VM.
        }

        Write-Log "Failed to connect to $VMName. Retrying..."
        Start-Sleep -Seconds 5
    }

    # If we reached here, we failed to connect to the VM.
    throw "Failed to connect to $VMName after timeout..."
}

<#
.SYNOPSIS
    Helper function to create a VM.

.DESCRIPTION
    This function creates a new VM with the specified parameters.

.PARAMETER VmName
    The name of the VM to create.

.PARAMETER AdminUserCredential
    The credentials for the admin user to use for the VM.

.PARAMETER StandardUserCredential
    The credentials for the standard user to use for the VM.

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
    Create-VM -VmName "MyVM" -AdminUserCredential $adminCredential -StandardUserCredential $userCredential -VhdPath "C:\MyVHD.vhd" -VmStoragePath "C:\VMStorage" -VMMemory 2GB -UnattendPath "C:\MyUnattend.xml" -VmSwitchName "VMInternalSwitch"
#>
function Create-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][PSCredential]$AdminUserCredential,
        [Parameter(Mandatory=$True)][PSCredential]$StandardUserCredential,
        [Parameter(Mandatory=$True)][string]$VhdPath,
        [Parameter(Mandatory=$True)][string]$VmStoragePath,
        [Parameter(Mandatory=$True)][Int64]$VMMemory,
        [Parameter(Mandatory=$True)][string]$UnattendPath,
        [Parameter(Mandatory=$True)][string]$VmSwitchName
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
        Write-Log "Moving $VhdPath to $VmStoragePath"
        Move-Item -Path $VhdPath -Destination $VmStoragePath -Force
        $VmVhdPath = Join-Path -Path $VmStoragePath -ChildPath (Split-Path -Path $VhdPath -Leaf)

        # Move unattend to the path and replace placeholder strings
        Write-Log "Moving $UnattendPath file to $VmStoragePath"
        Move-Item -Path $UnattendPath -Destination $VmStoragePath -Force
        $VmUnattendPath = Join-Path -Path $VmStoragePath -ChildPath (Split-Path -Path $UnattendPath -Leaf)
        Replace-PlaceholderStrings -FilePath $VmUnattendPath -SearchString 'PLACEHOLDER_ADMIN_PASSWORD' -ReplaceString $AdminUserCredential.GetNetworkCredential().Password
        Replace-PlaceholderStrings -FilePath $VmUnattendPath -SearchString 'PLACEHOLDER_STANDARDUSER_PASSWORD' -ReplaceString $StandardUserCredential.GetNetworkCredential().Password

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

.PARAMETER VmCredential
    The credentials to use for connecting to the VM.

.PARAMETER VMCpuCount
    The number of processors to allocate for the VM.

.PARAMETER VMWorkingDirectory
    The working directory on the VM to use for executing the setup script. Defaults to 'C:\ebpf_cicd'.

.PARAMETER VMSetupScript
    The path to the setup script to execute on the VM. Defaults to '.\configure_vm.ps1'.

.EXAMPLE
    Configure-VM -VmName "MyVM" -VmCredential $myCredential -VMCpuCount 4
#>
function Configure-VM {
    param(
        [Parameter(Mandatory=$True)][string]$VmName,
        [Parameter(Mandatory=$True)][PSCredential]$VmCredential,
        [Parameter(Mandatory=$True)][int]$VMCpuCount,
        [Parameter(Mandatory=$False)][string]$VMWorkingDirectory='C:\ebpf_cicd',
        [Parameter(Mandatory=$False)][string]$VMSetupScript='.\configure_vm.ps1'
    )

    try {
        Write-Log "Configuring VM: $VmName"

        # Post VM creation configuration steps.
        Write-Log "Setting VM processor count to $VMCpuCount"
        Set-VMProcessor -VMName $VmName -Count $VMCpuCount
        Write-Log "Enabling Guest Service Interface"
        Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface'

        # Start the VM
        Write-Log "Starting VM: $VmName"
        Start-VM -Name $VmName
        Wait-ForVMReady -VMName $VmName -VmCredential $VmCredential

        Write-Log "Sleeping for 1 minute to let the VM get into a steady state"
        Sleep -Seconds 60

        # Copy setup script to the VM and execute it.
        Write-Log "Executing VM configuration script ($VMSetupScript) on VM: $VmName"
        Copy-VMFile -VMName $VmName -FileSource Host -SourcePath $VMSetupScript -DestinationPath "$VMWorkingDirectory\$VMSetupScript" -CreateFullPath
        Execute-CommandOnVM -VMName $VmName -VmCredential $VmCredential -Command "cd $VMWorkingDirectory; .\$VMSetupScript"
        Write-Log "Sleeping for 1 minute to let the VM get into a steady state"
        Sleep -Seconds 60 # Sleep for 1 minute to let the VM get into a steady state.
        Write-Log "Successfully executed VM configuration script ($VMSetupScript) on VM: $VmName" -ForegroundColor Green

        Wait-ForVMReady -VMName $VmName -VmCredential $VmCredential

        # Checkpoint the VM. This can sometimes fail if other operations are in progress.
        for ($i = 0; $i -lt 5; $i += 1) {
            try {
                Write-Log "Checkpointing VM: $VmName"
                Checkpoint-VM -Name $VMName -SnapshotName 'baseline'
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
        [Parameter(Mandatory=$true)]
        [string]$InputDirectory
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
