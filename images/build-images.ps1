# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

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

Compress-Archive -Update -Path $TEMPDir -DestinationPath ebpf-for-windows-c-temp.zip

docker build -t $Repositry/ebpfwin-install:$Tag  -f .\Dockerfile.install --build-arg WINDOWS_VERSION=$OSVersion .
