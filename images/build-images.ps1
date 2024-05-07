# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Download and copy release archive to local directory as ./ebpf-for-windows.msi before running this script.

param ([parameter(Mandatory=$false)][string] $TEMPDir = "c:\temp",
    [parameter(Mandatory=$true)][string] $Repository = "",
    [parameter(Mandatory=$true)][string] $Tag = "",
    [parameter(Mandatory=$true)][string] $OSVersion = "1809")

$svc = Get-Service | where Name -EQ 'docker'
if ($svc -EQ $null) {
    throw "Docker service is not installed."
}
if ($svc.Status -NE 'Running') {
    throw "Docker service is not running."
}

docker build -t $Repository/ebpfwin-install:$Tag  -f .\Dockerfile.install --build-arg WINDOWS_VERSION=$OSVersion .
