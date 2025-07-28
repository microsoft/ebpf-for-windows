# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Enable Test Signed Binaries
Write-Host "Enabling test signing for binaries..."
bcdedit.exe -set TESTSIGNING ON

# Set Network Profile to Private
Write-Host "Setting public network profiles to private..."
$profiles = Get-NetConnectionProfile
foreach ($profile in $profiles) {
    if ($profile.NetworkCategory -eq 'Public') {
        Write-Host "Changing network '$($profile.Name)' to Private..."
        Set-NetConnectionProfile -Name $profile.Name -NetworkCategory Private
    }
}

# Enable PowerShell Remoting
Write-Host "Enabling PowerShell remoting..."
Enable-PSRemoting -Force

# Restart the VM
Write-Host "Restarting the computer..."
Restart-Computer
