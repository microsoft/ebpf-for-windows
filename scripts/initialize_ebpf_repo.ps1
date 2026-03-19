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

# Find msbuild.exe using vswhere
$vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswherePath) {
    $msbuildPath = & $vswherePath -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\amd64\MSBuild.exe" | Select-Object -First 1
}
if (-not $msbuildPath -or -not (Test-Path $msbuildPath)) {
    # Fall back to assuming msbuild is on PATH.
    $msbuildPath = "msbuild"
}
Write-Host "Using MSBuild: $msbuildPath"

# Helper to run a command, check exit code, and abort on failure.
function Invoke-NativeCommand {
    param([string]$Command)
    Write-Host ">> Running command: $Command"
    Invoke-Expression -Command $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Command failed. Exit code: $LASTEXITCODE"
        Exit $LASTEXITCODE
    }
}

# Helper to run msbuild with the correct path (cannot use Invoke-Expression
# because PowerShell interprets '/' in msbuild arguments as a division operator).
function Invoke-MSBuild {
    param([string[]]$Arguments)
    $cmd = "& `"$msbuildPath`" $($Arguments -join ' ')"
    Write-Host ">> Running command: $msbuildPath $($Arguments -join ' ')"
    & $msbuildPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Command failed. Exit code: $LASTEXITCODE"
        Exit $LASTEXITCODE
    }
}

# Define the commands to run
$cmakeCommonArgs = "-G `"Visual Studio 17 2022`" -A $Architecture"
$commands = @(
    "git submodule update --init --recursive",
    "cmake $cmakeCommonArgs -S external\ebpf-verifier -B external\ebpf-verifier\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build_fuzzer -DUBPF_ENABLE_LIBFUZZER=on",
    "nuget restore ebpf-for-windows.sln"
)

# Run non-msbuild commands via Invoke-Expression.
foreach ($command in $commands) {
    Invoke-NativeCommand -Command $command
}

# Run msbuild restore commands using the call operator to avoid '/' parsing issues.
Invoke-MSBuild -Arguments "/t:restore", "external\usersim\src\usersim.vcxproj", "/p:Platform=$Architecture"
Invoke-MSBuild -Arguments "/t:restore", "external\usersim\usersim_dll_skeleton\usersim_dll_skeleton.vcxproj", "/p:Platform=$Architecture"

Write-Host "All commands succeeded."
