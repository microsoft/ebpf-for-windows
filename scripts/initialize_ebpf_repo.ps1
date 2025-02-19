# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Accept architecture as a parameter (e.g., X64, ARM64)
param (
    [parameter(Mandatory = $false)][string] $Architecture = "x64"
)

# This script assumes it is called from the root of the repository, but it can be called from any directory.
# To handle this, we first get the directory where the script is located and then change the parent directory to the root of the repository.

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..

# Define the commands to run
$cmakeCommonArgs = "-G 'Visual Studio 17 2022' -A $Architecture"
$commands = @(
    "git submodule update --init --recursive",
    "cmake $cmakeCommonArgs -S external\ebpf-verifier -B external\ebpf-verifier\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>DLL",
    "cmake $cmakeCommonArgs -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build_fuzzer -DUBPF_ENABLE_LIBFUZZER=on",
    "nuget restore ebpf-for-windows.sln"
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
