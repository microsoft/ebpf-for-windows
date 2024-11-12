# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

########## Helper Functions ##########
# Download and extract PSExec to run tests as SYSTEM.
function Get-PSExec {
    $url = "https://download.sysinternals.com/files/PSTools.zip"
    $DownloadPath = "$pwd\psexec"
    mkdir $DownloadPath
    Write-Host "Downloading PSExec from $url to $DownloadPath"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $url -OutFile "$DownloadPath\pstools.zip"
    cd $DownloadPath
    Expand-Archive -Path "$DownloadPath\pstools.zip" -Force
    cd ..
    Move-Item -Path "$DownloadPath\PSTools\PsExec64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse
}

function Get-ZipFileFromUrl {
    param(
        [Parameter(Mandatory=$True)][string] $Url,
        [Parameter(Mandatory=$True)][string] $DownloadFilePath,
        [Parameter(Mandatory=$True)][string] $OutputDir
    )

    for ($i = 0; $i -lt 5; $i++) {
        try {
            Write-Host "Downloading $Url to $DownloadFilePath"
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $DownloadFilePath

            Write-Host "Extracting $DownloadFilePath to $OutputDir"
            Expand-Archive -Path $DownloadFilePath -DestinationPath $OutputDir -Force
            break
        } catch {
            Write-Host "Iteration $i failed to download $Url. Removing $DownloadFilePath" -ForegroundColor Red
            Remove-Item -Path $DownloadFilePath -Force -ErrorAction Ignore
            Start-Sleep -Seconds 5
        }
    }
}

# Copied from https://github.com/microsoft/msquic/blob/main/scripts/prepare-machine.ps1
function Get-Duonic {
    # Download and extract https://github.com/microsoft/corenet-ci.
    $DownloadPath = "$pwd\corenet-ci"
    mkdir $DownloadPath
    Write-Host "Downloading CoreNet-CI to $DownloadPath"
    Get-ZipFileFromUrl -Url "https://github.com/microsoft/corenet-ci/archive/refs/heads/main.zip" -DownloadFilePath "$DownloadPath\corenet-ci.zip" -OutputDir $DownloadPath
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\duonic\*" -Destination $pwd -Force
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\procdump64.exe" -Destination $pwd -Force
    Move-Item -Path "$DownloadPath\corenet-ci-main\vm-setup\notmyfault64.exe" -Destination $pwd -Force
    Remove-Item -Path $DownloadPath -Force -Recurse
}

function Initialize-NetworkInterfacesOnVMs
{
    # param([parameter(Mandatory=$true)] $VMMap)

    # foreach ($VM in $VMMap)
    # {
    #     $VMName = $VM.Name

    #     Write-Log "Initializing network interfaces on $VMName"
    #     $TestCredential = New-Credential -Username $Admin -AdminPassword $AdminPassword

    #     Invoke-Command -VMName $VMName -Credential $TestCredential -ScriptBlock {
    #         param([Parameter(Mandatory=$True)] [string] $WorkingDirectory)

    #         Push-Location "$env:SystemDrive\$WorkingDirectory"

    Write-Host "Installing DuoNic driver"
    .\duonic.ps1 -Install -NumNicPairs 2
    # Disable Duonic's fake checksum offload and force TCP/IP to calculate it.
    Set-NetAdapterAdvancedProperty duo? -DisplayName Checksum -RegistryValue 0

    #         Pop-Location
    #     } -ArgumentList ("eBPF") -ErrorAction Stop
    # }
}

########## Main Execution ##########

# Enable test signing.
bcdedit -set TESTSIGNING ON

# Enable user-mode dumps.
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "c:\dumps" -PropertyType ExpandString -ErrorAction SilentlyContinue -Force

# Enable kernel dumps.
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue

# Enable driver verifier on the eBPF platform drivers.
verifier /standard /bootmode persistent /driver ebpfcore.sys netebpfext.sys sample_ebpf_ext.sys

# TODO - this will either need to be done post VM creation, or run on the host and copied into the VM
# # Install duonic and configure it.
# Get-Duonic
# Initialize-NetworkInterfacesOnVMs

# # Get PSExec to run tests as SYSTEM.
# Get-PSExec

# Reboot the machine to apply the changes.
Restart-Computer -Force