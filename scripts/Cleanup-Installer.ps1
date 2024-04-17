# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# This script exists to forcefully remove all eBPF components when an uninstall is not possible.
# This script is not intended to be run on a production system. It is intended to be run on a test system where the eBPF components are being tested.

# Find the registry key for the eBPF for Windows product and remove it.
$keyName = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" | Where-Object { $_.GetValue("DisplayName") -eq "eBPF for Windows"}).Name
if ($keyName.Length -gt 0) {
  $keyName = $keyName.Substring(0, $keyName.LastIndexOf("\"))
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\" + $keyName.Substring($keyName.LastIndexOf("\") + 1)
  Remove-Item -Path $registryPath -Recurse
}

# Find the registry key for the eBPF for Windows product and remove it.
$keyName = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.GetValue("DisplayName") -eq "eBPF for Windows"}).Name
if ($keyName.Length -gt 0) {
  $keyName = $keyName.SubString($keyName.LastIndexOf("\") + 1)
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + $keyName
  Remove-Item -Path $registryPath -Recurse
}

# Stop and remove the eBPF services.
net.exe stop ebpfsvc
sc.exe delete ebpfsvc

# Stop and remove the eBPF core driver.
net.exe stop ebpfcore
sc.exe delete ebpfcore

# Stop and remove the eBPF extension driver.
net.exe stop netebpfext
sc.exe delete netebpfext

# Remove the eBPF for Windows installation directory.
$installPath = "C:\Program Files\ebpf-for-windows"
if (Test-Path $installPath) {
  Remove-Item -Path "C:\Program Files\ebpf-for-windows" -Recurse -Force
}

# Set the exit code to 0 to indicate success.
$global:LASTEXITCODE = 0