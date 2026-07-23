# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Accept architecture as a parameter (e.g., X64, ARM64)
param (
    [parameter(Mandatory = $false)][string] $Architecture = "x64",
    # Visual Studio version to target: "2022"/"17" or "2026"/"18". Defaults to the latest installed.
    # Use this on a machine with multiple Visual Studio versions installed to set up a build for a
    # specific toolset, so the CMake generator, platform toolset, and NuGet/MSBuild restore all match
    # the Visual Studio version you intend to build with.
    [parameter(Mandatory = $false)][string] $VisualStudioVersion = ""
)

# Ensure errors are treated as terminating exceptions
$ErrorActionPreference = "Stop"

# This script assumes it is called from the root of the repository, but it can be called from any directory.
# To handle this, we first get the directory where the script is located and then change the parent directory to the root of the repository.

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..

# Resolve the Visual Studio instance to use for MSBuild, the CMake generator, and NuGet/MSBuild restore.
# By default the latest installed instance is used; -VisualStudioVersion selects a specific one so a
# machine with multiple Visual Studio versions installed can target the toolset it intends to build with.
$vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

# Map the requested version onto a vswhere instance selector.
$vsSelector = @("-latest")
switch -Regex ($VisualStudioVersion) {
    '^(2022|17)$' { $vsSelector = @("-latest", "-version", "[17.0,18.0)") }
    '^(2026|18)$' { $vsSelector = @("-latest", "-version", "[18.0,19.0)") }
    '^$'          { $vsSelector = @("-latest") }
    default       { Write-Warning "Unrecognized -VisualStudioVersion '$VisualStudioVersion'; using the latest installed Visual Studio." }
}

# Resolve MSBuild and the matching CMake generator from the SAME selected instance, so we don't
# hardcode a specific VS version (e.g. "Visual Studio 17 2022") or mix toolsets across tools.
$msbuildPath = $null
$cmakeGenerator = "Visual Studio 17 2022"
if (Test-Path $vswherePath) {
    $msbuildPath = & $vswherePath @vsSelector -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\amd64\MSBuild.exe" | Select-Object -First 1
    $vsMajor = ((& $vswherePath @vsSelector -property installationVersion | Select-Object -First 1) -split '\.' | Select-Object -First 1)
    switch ($vsMajor) {
        "18" { $cmakeGenerator = "Visual Studio 18 2026" }
        "17" { $cmakeGenerator = "Visual Studio 17 2022" }
        default {
            if ($vsMajor) {
                Write-Warning "Unrecognized Visual Studio major version '$vsMajor'; defaulting to the Visual Studio 2022 generator."
            }
        }
    }
} else {
    Write-Warning "vswhere.exe not found at '$vswherePath'; defaulting to msbuild on PATH and the Visual Studio 2022 generator."
}
if (-not $msbuildPath -or -not (Test-Path $msbuildPath)) {
    # Fall back to assuming msbuild is on PATH.
    $msbuildPath = "msbuild"
}
Write-Host "Using MSBuild: $msbuildPath"
Write-Host "Using CMake generator: $cmakeGenerator"

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
$cmakeCommonArgs = "-G `"$cmakeGenerator`" -A $Architecture"
# Restore the solution with the selected MSBuild so PackageReference projects (e.g. usersim's
# cxplat_winkernel) resolve their WDK version against the intended Visual Studio version. Without
# -MSBuildPath, nuget auto-detects the latest installed MSBuild, which can pin a different toolset's
# WDK than the one we build with.
$msbuildDir = if ($msbuildPath -and (Test-Path $msbuildPath)) { Split-Path -Parent $msbuildPath } else { $null }
$nugetRestoreCommand = if ($msbuildDir) {
    "nuget restore ebpf-for-windows.sln -MSBuildPath `"$msbuildDir`""
} else {
    "nuget restore ebpf-for-windows.sln"
}
$commands = @(
    "git submodule update --init --recursive",
    "cmake $cmakeCommonArgs -S external\ebpf-verifier -B external\ebpf-verifier\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>",
    "cmake $cmakeCommonArgs -S external\ubpf -B external\ubpf\build_fuzzer -DUBPF_ENABLE_LIBFUZZER=on",
    $nugetRestoreCommand
)

# When switching between Visual Studio versions, an existing CMake build directory configured with a
# different generator cannot be reused (CMake errors on a generator mismatch). Remove any such stale
# build directory so it is regenerated with the selected generator.
function Clear-StaleCMakeBuildDir {
    param([string]$BuildDir, [string]$Generator)
    $cachePath = Join-Path $BuildDir "CMakeCache.txt"
    if (Test-Path $cachePath) {
        $cachedGenerator = (Select-String -Path $cachePath -Pattern '^CMAKE_GENERATOR:INTERNAL=(.*)$' |
            Select-Object -First 1).Matches.Groups[1].Value
        if ($cachedGenerator -and ($cachedGenerator -ne $Generator)) {
            Write-Host "Removing stale CMake build dir '$BuildDir' (generator '$cachedGenerator' != '$Generator')."
            Remove-Item $BuildDir -Recurse -Force
        }
    }
}
foreach ($buildDir in @(
        "external\ebpf-verifier\build",
        "external\catch2\build",
        "external\ubpf\build",
        "external\ubpf\build_fuzzer")) {
    Clear-StaleCMakeBuildDir -BuildDir $buildDir -Generator $cmakeGenerator
}

# Run non-msbuild commands via Invoke-Expression.
foreach ($command in $commands) {
    Invoke-NativeCommand -Command $command
}

# Run msbuild restore commands using the call operator to avoid '/' parsing issues.
Invoke-MSBuild -Arguments "/t:restore", "external\usersim\src\usersim.vcxproj", "/p:Platform=$Architecture"
Invoke-MSBuild -Arguments "/t:restore", "external\usersim\usersim_dll_skeleton\usersim_dll_skeleton.vcxproj", "/p:Platform=$Architecture"
Invoke-MSBuild -Arguments "/t:restore", "external\usersim\cxplat\src\cxplat_winkernel\cxplat_winkernel.vcxproj", "/p:Platform=$Architecture"

Write-Host "All commands succeeded."
