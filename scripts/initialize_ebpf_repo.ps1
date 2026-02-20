# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Accept architecture as a parameter (e.g., X64, ARM64)
param (
    [parameter(Mandatory = $false)][string] $Architecture = "x64"
)

# Ensure errors are treated as terminating exceptions
$ErrorActionPreference = "Stop"

# This script assumes it is called from the root of the repository, but it can be called from any directory.
# To handle this, we first get the directory where the script is located and then change the parent directory to the root of the repository.

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..

# Define the commands to run
$cmakeCommonArgs = "-G `"Visual Studio 17 2022`" -A $Architecture"
$commands = @(
    "git submodule update --init --recursive",
    "cmake $cmakeCommonArgs -S external\ebpf-verifier -B external\ebpf-verifier\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build_fuzzer -DUBPF_ENABLE_LIBFUZZER=on",
    "msbuild ebpf-for-windows.sln /t:Restore /m /p:Platform=$Architecture /p:Configuration=Debug",
    "msbuild installer\ebpf-for-windows.wixproj /t:Restore /m",
    "if (!(Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\wix\3.14.1\build\wix.props')) -and !(Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\wix.3.14.1\build\wix.props'))) { nuget install WiX -Version 3.14.1 -OutputDirectory (Join-Path $env:USERPROFILE '.nuget\packages') }",
    "if (!(Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\wix\3.14.1\build\wix.props')) -and (Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\wix.3.14.1\build\wix.props'))) { New-Item -ItemType Directory -Path (Join-Path $env:USERPROFILE '.nuget\packages\wix\3.14.1') -Force | Out-Null; Copy-Item -Path (Join-Path $env:USERPROFILE '.nuget\packages\wix.3.14.1\*') -Destination (Join-Path $env:USERPROFILE '.nuget\packages\wix\3.14.1') -Recurse -Force }",
    "if (!(Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\everparse\2022.6.13\lib\native\win-x86_64\everparse.cmd')) -and !(Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\everparse.2022.6.13\lib\native\win-x86_64\everparse.cmd'))) { nuget install EverParse -Version 2022.6.13 -OutputDirectory (Join-Path $env:USERPROFILE '.nuget\packages') }",
    "if (!(Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\everparse\2022.6.13\lib\native\win-x86_64\everparse.cmd')) -and (Test-Path (Join-Path $env:USERPROFILE '.nuget\packages\everparse.2022.6.13\lib\native\win-x86_64\everparse.cmd'))) { New-Item -ItemType Directory -Path (Join-Path $env:USERPROFILE '.nuget\packages\everparse\2022.6.13') -Force | Out-Null; Copy-Item -Path (Join-Path $env:USERPROFILE '.nuget\packages\everparse.2022.6.13\*') -Destination (Join-Path $env:USERPROFILE '.nuget\packages\everparse\2022.6.13') -Recurse -Force }",
    "if (Test-Path external\usersim\packages.config) { nuget restore external\usersim\packages.config -PackagesDirectory packages }",
    "if (Test-Path external\usersim\cxplat\src\cxplat_winkernel\packages.config) { nuget restore external\usersim\cxplat\src\cxplat_winkernel\packages.config -PackagesDirectory packages }"
)

# Loop through each command and run them sequentially without opening a new window
foreach ($command in $commands) {
    Write-Host ">> Running command: $command"
    Invoke-Expression -Command $command

    # Check the exit code
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Command failed. Exit code: $LASTEXITCODE"
        Exit  $LASTEXITCODE
    }
}

Write-Host "All commands succeeded."
