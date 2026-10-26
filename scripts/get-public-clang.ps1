# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param (
    [parameter(Mandatory = $false)][string] $CacheRoot =
        (Join-Path $env:LOCALAPPDATA "ebpf-for-windows\llvm")
)

$ErrorActionPreference = "Stop"
$manifestPath = Join-Path $PSScriptRoot "clang-toolchain.props"
$manifest = [xml](Get-Content -Path $manifestPath -Raw)
$namespaceManager = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
$namespaceManager.AddNamespace("m", "http://schemas.microsoft.com/developer/msbuild/2003")

function Get-ManifestValue {
    param([string] $Name)

    $node = $manifest.SelectSingleNode("/m:Project/m:PropertyGroup/m:$Name", $namespaceManager)
    if (-not $node -or [string]::IsNullOrWhiteSpace($node.InnerText)) {
        throw "The Clang toolchain manifest is missing '$Name'."
    }

    return $node.InnerText
}

function Get-ClangVersion {
    param([string] $CompilerPath)

    $versionOutput = @(& $CompilerPath --version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $match = [regex]::Match(($versionOutput -join "`n"), '(?m)^clang version (?<version>\d+\.\d+\.\d+)(?:\s|$)')
    return $(if ($match.Success) { $match.Groups["version"].Value } else { $null })
}

function Test-PublicClangCache {
    param(
        [string] $InstallRoot,
        [string] $ExpectedVersion
    )

    $compilerPath = Join-Path $InstallRoot "bin\clang.exe"
    $resourceDirectory = Join-Path $InstallRoot "lib\clang\$([System.Version]::Parse($ExpectedVersion).Major)"
    return (Test-Path $compilerPath) -and
        (Test-Path (Join-Path $resourceDirectory "include\stdint.h")) -and
        ((Get-ClangVersion -CompilerPath $compilerPath) -eq $ExpectedVersion)
}

function Enter-FileLock {
    param([string] $LockPath)

    for ($attempt = 0; $attempt -lt 1200; $attempt++) {
        try {
            return [System.IO.File]::Open(
                $LockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            Start-Sleep -Milliseconds 500
        }
    }

    throw "Timed out after 10 minutes waiting for the Public Clang cache lock '$LockPath'."
}

$version = Get-ManifestValue "EbpfPublicClangVersion"
$archiveName = (Get-ManifestValue "EbpfPublicClangPortableArchiveName").Replace("{version}", $version)
$archiveRoot = (Get-ManifestValue "EbpfPublicClangPortableArchiveRoot").Replace("{version}", $version)
$archiveUrl = (Get-ManifestValue "EbpfPublicClangPortableArchiveUrl").Replace("{version}", $version)
$archiveSha256 = Get-ManifestValue "EbpfPublicClangPortableArchiveSha256"
$installRoot = Join-Path $CacheRoot $version
$compilerPath = Join-Path $installRoot "bin\clang.exe"
$resourceDirectory = Join-Path $installRoot "lib\clang\$([System.Version]::Parse($version).Major)"

if (Test-PublicClangCache -InstallRoot $installRoot -ExpectedVersion $version) {
    Write-Host "Using cached Public Clang $version at '$installRoot'."
    return [pscustomobject]@{
        Version = $version
        InstallRoot = $installRoot
        CompilerPath = $compilerPath
        ResourceDirectory = $resourceDirectory
    }
}

New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
$lock = Enter-FileLock -LockPath (Join-Path $CacheRoot "$version.lock")
$temporaryInstallRoot = Join-Path $CacheRoot (".{0}.{1}" -f $version, [guid]::NewGuid().ToString("N"))
try {
    if (Test-PublicClangCache -InstallRoot $installRoot -ExpectedVersion $version) {
        Write-Host "Using cached Public Clang $version at '$installRoot'."
        return [pscustomobject]@{
            Version = $version
            InstallRoot = $installRoot
            CompilerPath = $compilerPath
            ResourceDirectory = $resourceDirectory
        }
    }

    $downloadDirectory = Join-Path $CacheRoot "downloads"
    New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null
    $archivePath = Join-Path $downloadDirectory $archiveName
    if (Test-Path $archivePath) {
        $actualHash = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $archiveSha256) {
            Remove-Item -LiteralPath $archivePath -Force
        }
    }

    if (-not (Test-Path $archivePath)) {
        $temporaryArchivePath = "$archivePath.$([guid]::NewGuid().ToString("N")).tmp"
        try {
            Write-Host "Downloading Public Clang $version from '$archiveUrl'."
            Invoke-WebRequest -Uri $archiveUrl -OutFile $temporaryArchivePath -UseBasicParsing
            $actualHash = (Get-FileHash -Path $temporaryArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $archiveSha256) {
                throw "Public Clang archive hash mismatch. Expected $archiveSha256 but found $actualHash."
            }
            Move-Item -LiteralPath $temporaryArchivePath -Destination $archivePath -Force
        }
        finally {
            Remove-Item -LiteralPath $temporaryArchivePath -Force -ErrorAction SilentlyContinue
        }
    }

    $actualHash = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $archiveSha256) {
        throw "Public Clang archive hash mismatch. Expected $archiveSha256 but found $actualHash."
    }

    $tar = (Get-Command tar.exe -ErrorAction Stop).Source
    New-Item -ItemType Directory -Path $temporaryInstallRoot -Force | Out-Null
    Write-Host "Extracting the Public Clang compiler and resource headers to '$installRoot'."
    & $tar -xf $archivePath -C $temporaryInstallRoot --strip-components=1 `
        "$archiveRoot/bin/clang.exe" `
        "$archiveRoot/lib/clang/$([System.Version]::Parse($version).Major)/include"
    if ($LASTEXITCODE -ne 0) {
        throw "Public Clang archive extraction failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-PublicClangCache -InstallRoot $temporaryInstallRoot -ExpectedVersion $version)) {
        throw "The extracted Public Clang toolchain is incomplete or has the wrong version."
    }

    if (Test-Path $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    Move-Item -LiteralPath $temporaryInstallRoot -Destination $installRoot
    Remove-Item -LiteralPath $archivePath -Force
}
finally {
    Remove-Item -LiteralPath $temporaryInstallRoot -Recurse -Force -ErrorAction SilentlyContinue
    $lock.Dispose()
}

Write-Host "Provisioned Public Clang $version at '$installRoot'."
return [pscustomobject]@{
    Version = $version
    InstallRoot = $installRoot
    CompilerPath = $compilerPath
    ResourceDirectory = $resourceDirectory
}
