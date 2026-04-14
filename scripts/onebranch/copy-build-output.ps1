# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param (
    [switch]$CopyClangRt
)

# Copies MSBuild output from the standard Visual Studio output directory to the
# OneBranch output directory so that build artifacts are published correctly.
# This script is intended for test/CI builds that compile the full solution
# (as opposed to the /t:tools\onebranch target used by official builds).
#
# Environment variables (set by OneBranch):
#   ONEBRANCH_ARCH             - Build architecture (e.g., x64, arm64)
#   ONEBRANCH_CONFIG           - Build configuration (e.g., Debug, Release, FuzzerDebug)
#   ONEBRANCH_OUTPUTDIRECTORY  - OneBranch artifact output directory

$ErrorActionPreference = 'Stop'

$arch   = $env:ONEBRANCH_ARCH
$config = $env:ONEBRANCH_CONFIG
$dst    = $env:ONEBRANCH_OUTPUTDIRECTORY

if (-not $arch -or -not $config -or -not $dst) {
    throw "Required environment variables (ONEBRANCH_ARCH, ONEBRANCH_CONFIG, ONEBRANCH_OUTPUTDIRECTORY) are not set."
}

$src = Join-Path $arch $config

if (-not (Test-Path $src)) {
    throw "Source directory '$src' does not exist. Build may have failed."
}

Write-Host "Copying build output from '$src' to '$dst'..."

if (-not (Test-Path $dst)) {
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
}

# Use robocopy for reliable directory mirroring. Exit codes 0-7 are success.
robocopy $src $dst /E /NP /NFL /NDL
if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed with exit code $LASTEXITCODE"
}
# Robocopy returns 1 when files are copied successfully. Reset so ADO does not
# treat the non-zero exit code as a failure.
$global:LASTEXITCODE = 0

# For Fuzzer and AddressSanitizer builds, copy clang runtime DLLs that are
# required at test execution time. Pass -CopyClangRt to enable.
if ($CopyClangRt) {
    $vsBasePath = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    $clangDlls = Get-ChildItem "$vsBasePath\VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.*.dll" -ErrorAction SilentlyContinue
    if ($clangDlls) {
        Write-Host "Copying $($clangDlls.Count) clang runtime DLL(s)..."
        foreach ($dll in $clangDlls) {
            Copy-Item $dll.FullName $dst -Force
        }
    } else {
        Write-Warning "No clang runtime DLLs found. Fuzzer/ASAN tests may fail at runtime."
    }
}

Write-Host "Build output copy complete."
exit 0
