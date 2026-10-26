# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

$ErrorActionPreference = "Stop"

$version = "18.1.8"
$archiveName = "clang+llvm-18.1.8-x86_64-pc-windows-msvc.tar.xz"
$archiveRoot = "clang+llvm-18.1.8-x86_64-pc-windows-msvc"
$releaseUrl = "https://github.com/llvm/llvm-project/releases/download/llvmorg-$version"
$archiveUrl = "$releaseUrl/$($archiveName.Replace('+', '%2B'))"
$resourceVersion = ([System.Version]::Parse($version)).Major
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$installRoot = Join-Path $repositoryRoot "llvm"

function Get-ToolVersion {
    param([string] $ToolPath)

    try {
        $versionOutput = @(& $ToolPath --version 2>&1)
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
    }
    catch {
        return $null
    }

    $match = [regex]::Match(($versionOutput -join "`n"), '\bversion\s+(?<version>\d+\.\d+\.\d+)(?:\s|$)')
    return $(if ($match.Success) { $match.Groups["version"].Value } else { $null })
}

function Test-PublicClangInstall {
    param([string] $Root)

    $compilerPath = Join-Path $Root "bin\clang.exe"
    $formatterPath = Join-Path $Root "bin\clang-format.exe"
    $resourceHeaderPath = Join-Path $Root "lib\clang\$resourceVersion\include\stdint.h"

    return (Test-Path -LiteralPath $compilerPath -PathType Leaf) -and
        (Test-Path -LiteralPath $formatterPath -PathType Leaf) -and
        (Test-Path -LiteralPath $resourceHeaderPath -PathType Leaf) -and
        ((Get-ToolVersion -ToolPath $compilerPath) -eq $version) -and
        ((Get-ToolVersion -ToolPath $formatterPath) -eq $version)
}

function Assert-PublicClangInstall {
    param([string] $Root)

    $compilerPath = Join-Path $Root "bin\clang.exe"
    $formatterPath = Join-Path $Root "bin\clang-format.exe"
    $resourceHeaderPath = Join-Path $Root "lib\clang\$resourceVersion\include\stdint.h"

    foreach ($requiredPath in @($compilerPath, $formatterPath, $resourceHeaderPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "The extracted Public Clang toolchain is missing '$requiredPath'."
        }
    }

    $compilerVersion = Get-ToolVersion -ToolPath $compilerPath
    if ($compilerVersion -ne $version) {
        throw "The extracted clang version '$compilerVersion' does not match the expected version '$version'."
    }

    $formatterVersion = Get-ToolVersion -ToolPath $formatterPath
    if ($formatterVersion -ne $version) {
        throw "The extracted clang-format version '$formatterVersion' does not match the expected version '$version'."
    }
}

if (Test-PublicClangInstall -Root $installRoot) {
    Write-Host "Using repo-local Public Clang $version at '$installRoot'."
    return
}

$curlCommand = Get-Command curl.exe -ErrorAction Stop
$temporaryDownloadRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "ebpf-for-windows-llvm-{0}" -f [guid]::NewGuid().ToString("N"))
$temporaryInstallRoot = Join-Path $repositoryRoot (
    ".llvm-install-{0}" -f [guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $temporaryDownloadRoot $archiveName

try {
    New-Item -ItemType Directory -Path $temporaryDownloadRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $temporaryInstallRoot -Force | Out-Null

    Write-Host "Downloading Public Clang $version from '$archiveUrl'."
    $curlArguments = @(
        "--fail",
        "--location",
        "--retry", "3",
        "--connect-timeout", "30",
        "--speed-limit", "1024",
        "--speed-time", "120",
        "--output", $archivePath,
        $archiveUrl)
    & $curlCommand.Source @curlArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Public Clang archive download failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "Public Clang archive download did not create '$archivePath'."
    }

    $tarCommand = Get-Command tar.exe -ErrorAction SilentlyContinue
    if (-not $tarCommand) {
        throw "tar.exe is required to extract the Public Clang archive."
    }

    Write-Host "Extracting the Public Clang compiler, resource headers, and formatter to '$installRoot'."
    & $tarCommand.Source -xf $archivePath -C $temporaryInstallRoot --strip-components=1 `
        "$archiveRoot/bin/clang.exe" `
        "$archiveRoot/bin/clang-format.exe" `
        "$archiveRoot/lib/clang/$resourceVersion/include"
    if ($LASTEXITCODE -ne 0) {
        throw "Public Clang archive extraction failed with exit code $LASTEXITCODE."
    }

    Assert-PublicClangInstall -Root $temporaryInstallRoot

    if (Test-Path -LiteralPath $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    [System.IO.Directory]::Move($temporaryInstallRoot, $installRoot)
    Assert-PublicClangInstall -Root $installRoot
}
finally {
    if (Test-Path -LiteralPath $temporaryDownloadRoot) {
        Remove-Item -LiteralPath $temporaryDownloadRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $temporaryInstallRoot) {
        Remove-Item -LiteralPath $temporaryInstallRoot -Recurse -Force
    }
}

Write-Host "Provisioned repo-local Public Clang $version at '$installRoot'."
