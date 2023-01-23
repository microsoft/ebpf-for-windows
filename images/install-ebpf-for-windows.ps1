# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Make sure the script is running in a HostProcess container.
if ($env:CONTAINER_SANDBOX_MOUNT_POINT) {
    $ns = $env:CONTAINER_SANDBOX_MOUNT_POINT
    write-host ("Install script is running in a HostProcess container. This sandbox mount point is {0}" -f $ns)
} else {
    throw "Install script is NOT running in a HostProcess container."
}

Write-Host "Install ebpf-for-windows ..."
.\ebpf-for-windows.msi /quiet

# Make sure netsh ebpf works.
Write-Host "ebpf-for-windows installation completed. Show program..."
netsh ebpf show program

# Sleep until the container is required to exit explicitly. This is for dev only.
# TODO: If this container is running as an init container of a daemonset,
# this section is not required.
$filePath = 'C:\exit-ebpfwin-install-container.txt'
while (-not (Test-Path -Path $filePath)) {
    Start-Sleep -Seconds 30
}

write-host "All done."
exit 0
