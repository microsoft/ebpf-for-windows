# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param (
    [parameter(Mandatory = $true)][ValidateSet("Auto", "Public", "Internal")][string] $Channel,
    [parameter(Mandatory = $false)]
    [ValidateSet("Auto", "Installed", "Portable")]
    [string] $PublicClangSource = "Installed",
    [parameter(Mandatory = $false)][string] $MSBuildPath
)

$ErrorActionPreference = "Stop"
$publicClangSourceSpecified = $PSBoundParameters.ContainsKey("PublicClangSource")
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $PSScriptRoot "clang-toolchain.props"
$generatedPropertiesPath = Join-Path $repositoryRoot "build\ebpf-clang-toolchain.props"
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

function Get-PersistedClangChannel {
    if (-not (Test-Path $generatedPropertiesPath)) {
        return $null
    }

    try {
        $state = [xml](Get-Content -Path $generatedPropertiesPath -Raw -Encoding UTF8)
        $stateNamespaceManager = New-Object System.Xml.XmlNamespaceManager($state.NameTable)
        $stateNamespaceManager.AddNamespace("m", "http://schemas.microsoft.com/developer/msbuild/2003")
        $schemaNode = $state.SelectSingleNode(
            "/m:Project/m:PropertyGroup/m:EbpfConfiguredClangStateSchemaVersion", $stateNamespaceManager)
        $channelNode =
            $state.SelectSingleNode("/m:Project/m:PropertyGroup/m:EbpfConfiguredClangChannel", $stateNamespaceManager)
        $currentSchemaVersion = Get-ManifestValue "EbpfClangToolchainStateSchemaVersion"
        if ($schemaNode -and
            $schemaNode.InnerText -in @("1", $currentSchemaVersion) -and
            $channelNode -and
            $channelNode.InnerText -in @("Public", "Internal")) {
            if ($schemaNode.InnerText -ne $currentSchemaVersion) {
                Write-Warning (
                    "Reusing the persisted $($channelNode.InnerText) channel from stale toolchain state; " +
                    "the state will be refreshed.")
            }
            return $channelNode.InnerText
        }

        Write-Warning "Ignoring stale or unrecognized persisted Clang toolchain state at '$generatedPropertiesPath'."
    }
    catch {
        Write-Warning "Ignoring unreadable persisted Clang toolchain state at '$generatedPropertiesPath': $_"
    }

    return $null
}

function Get-PersistedPublicClangSelection {
    if (-not (Test-Path $generatedPropertiesPath)) {
        return $null
    }

    try {
        $state = [xml](Get-Content -Path $generatedPropertiesPath -Raw -Encoding UTF8)
        $stateNamespaceManager = New-Object System.Xml.XmlNamespaceManager($state.NameTable)
        $stateNamespaceManager.AddNamespace("m", "http://schemas.microsoft.com/developer/msbuild/2003")
        $schemaNode = $state.SelectSingleNode(
            "/m:Project/m:PropertyGroup/m:EbpfConfiguredClangStateSchemaVersion", $stateNamespaceManager)
        $channelNode =
            $state.SelectSingleNode("/m:Project/m:PropertyGroup/m:EbpfConfiguredClangChannel", $stateNamespaceManager)
        $versionNode =
            $state.SelectSingleNode("/m:Project/m:PropertyGroup/m:EbpfConfiguredClangVersion", $stateNamespaceManager)
        $pathNode =
            $state.SelectSingleNode("/m:Project/m:PropertyGroup/m:EbpfConfiguredClangPath", $stateNamespaceManager)
        $sourceNode =
            $state.SelectSingleNode("/m:Project/m:PropertyGroup/m:EbpfConfiguredClangSource", $stateNamespaceManager)
        if ($schemaNode -and
            $schemaNode.InnerText -eq (Get-ManifestValue "EbpfClangToolchainStateSchemaVersion") -and
            $channelNode -and
            $channelNode.InnerText -eq "Public" -and
            $versionNode -and
            $versionNode.InnerText -eq (Get-ManifestValue "EbpfPublicClangVersion") -and
            $pathNode -and
            (Test-Path $pathNode.InnerText) -and
            $sourceNode -and
            $sourceNode.InnerText -in @("Installed", "Portable")) {
            return [pscustomobject]@{
                CompilerPath = $pathNode.InnerText
                Source = $sourceNode.InnerText
            }
        }
    }
    catch {
        Write-Warning "Unable to reuse the persisted Public Clang path from '$generatedPropertiesPath': $_"
    }

    return $null
}

function Get-InternalNuGetSource {
    $configPath = Join-Path $PSScriptRoot "onebranch\Nuget.config"
    $config = [xml](Get-Content -Path $configPath -Raw)
    $sourceNode =
        @($config.configuration.packageSources.add) |
            Where-Object { $_.key -eq "undock_PublicPackages" } |
            Select-Object -First 1
    if (-not $sourceNode -or [string]::IsNullOrWhiteSpace($sourceNode.value)) {
        throw "The Internal Clang package source is missing from '$configPath'."
    }

    return $sourceNode.value
}

function Normalize-NuGetSource {
    param([string] $Source)

    $sourceValue = $Source.Trim().TrimEnd([char[]]"/\")
    $sourceUri = $null
    if ([System.Uri]::TryCreate($sourceValue, [System.UriKind]::Absolute, [ref]$sourceUri) -and
        ($sourceUri.Scheme -eq "http" -or $sourceUri.Scheme -eq "https")) {
        return $sourceUri.AbsoluteUri.TrimEnd("/").ToLowerInvariant()
    }

    return $sourceValue.ToLowerInvariant()
}

function Get-EnabledNuGetSources {
    $nuget = Get-Command nuget -ErrorAction Stop
    $currentLocation = Get-Location
    try {
        Set-Location $repositoryRoot
        $sourceOutput = @(& $nuget.Source sources list -Format Short -NonInteractive 2>&1)
        $sourceExitCode = $LASTEXITCODE
    }
    finally {
        Set-Location $currentLocation
    }
    if ($sourceExitCode -ne 0) {
        throw "NuGet could not list the effective package sources. Output: $($sourceOutput -join ' ')"
    }

    $enabledSources = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $sourceOutput) {
        $match = [regex]::Match([string]$line, '^\s*E\S*\s+(?<source>.+?)\s*$')
        if ($match.Success) {
            $enabledSources.Add((Normalize-NuGetSource $match.Groups["source"].Value))
        }
    }

    return $enabledSources
}

function Resolve-ClangChannel {
    param([string] $RequestedChannel)

    if ($RequestedChannel -ne "Auto") {
        return [pscustomobject]@{
            Channel = $RequestedChannel
            Reason = "explicitly requested"
        }
    }

    $persistedChannel = Get-PersistedClangChannel
    if ($persistedChannel) {
        return [pscustomobject]@{
            Channel = $persistedChannel
            Reason = "reusing the persisted $persistedChannel selection for this worktree"
        }
    }

    try {
        $internalSource = Normalize-NuGetSource (Get-InternalNuGetSource)
        $enabledSources = @(Get-EnabledNuGetSources)
        if ($enabledSources -contains $internalSource) {
            return [pscustomobject]@{
                Channel = "Internal"
                Reason = "the configured Internal package source is enabled"
            }
        }
    }
    catch {
        Write-Warning "Unable to inspect effective NuGet package sources while resolving the Clang channel: $_"
    }

    return [pscustomobject]@{
        Channel = "Public"
        Reason = "no persisted selection or enabled Internal package source was found"
    }
}

function Get-ClangVersion {
    param([string] $CompilerPath)

    $versionOutput = & $CompilerPath --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not run '$CompilerPath --version'. Output: $($versionOutput -join ' ')"
    }

    $match = [regex]::Match(($versionOutput -join "`n"), '(?m)^clang version (?<version>\d+\.\d+\.\d+)(?:\s|$)')
    if (-not $match.Success) {
        throw "Could not parse the Clang version from '$CompilerPath'. Output: $($versionOutput -join ' ')"
    }

    return $match.Groups["version"].Value
}

function Get-ClangResourceDirectory {
    param([string] $CompilerPath)

    $resourceOutput = @(& $CompilerPath -print-resource-dir 2>&1)
    if ($LASTEXITCODE -ne 0 -or $resourceOutput.Count -ne 1) {
        throw "Could not determine the Clang resource directory from '$CompilerPath'. Output: $($resourceOutput -join ' ')"
    }

    return [System.IO.Path]::GetFullPath($resourceOutput[0].Trim())
}

function Test-ClangToolchain {
    param(
        [string] $CompilerPath,
        [string] $ResourceDirectory,
        [string] $ExpectedVersion
    )

    if (-not (Test-Path $CompilerPath)) {
        throw "The selected Clang executable does not exist: $CompilerPath"
    }

    $resourceHeader = Join-Path $ResourceDirectory "include\stdint.h"
    if (-not (Test-Path $resourceHeader)) {
        throw "The selected Clang resource directory does not contain '$resourceHeader'."
    }

    $actualVersion = Get-ClangVersion $CompilerPath
    if ($actualVersion -ne $ExpectedVersion) {
        throw "Selected Clang '$CompilerPath' reports version $actualVersion, but version $ExpectedVersion is required."
    }

    $temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    try {
        $sourcePath = Join-Path $temporaryDirectory "clang_bpf_smoke_test.c"
        $objectPath = Join-Path $temporaryDirectory "clang_bpf_smoke_test.o"
        Set-Content -Path $sourcePath -Encoding Ascii -Value @"
#include <stdint.h>
uint32_t ebpf_clang_smoke_test(uint32_t value) { return value + 1; }
"@

        $compileOutput = & $CompilerPath -target bpf -resource-dir $ResourceDirectory -Werror -O2 -c $sourcePath -o $objectPath 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $objectPath)) {
            throw "The selected Clang toolchain could not produce a BPF object. Output: $($compileOutput -join ' ')"
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}

function Get-MSBuildExecutable {
    if ($MSBuildPath) {
        $candidate = if ([System.IO.Path]::GetExtension($MSBuildPath) -ieq ".exe") {
            $MSBuildPath
        } else {
            Join-Path $MSBuildPath "msbuild.exe"
        }
        if (-not (Test-Path $candidate)) {
            throw "MSBuild was not found at '$candidate'."
        }
        return $candidate
    }

    return (Get-Command msbuild -ErrorAction Stop).Source
}

function Get-InternalClangPackagePaths {
    param([string] $PackageVersion)

    $projectPath = Join-Path $PSScriptRoot "clang-toolchain\clang-toolchain.vcxproj"
    $projectDirectory = Split-Path -Parent $projectPath
    $extensionsDirectory = Join-Path $projectDirectory "obj\clang-toolchain"
    if (Test-Path $extensionsDirectory) {
        Remove-Item -LiteralPath $extensionsDirectory -Recurse -Force
    }

    $nuget = Get-Command nuget -ErrorAction Stop
    $msbuild = Get-MSBuildExecutable
    $msbuildDirectory = Split-Path -Parent $msbuild
    $restoreArguments = @("restore", $projectPath, "-NonInteractive")
    $restoreArguments += @("-MSBuildPath", $msbuildDirectory)

    Write-Host "Restoring Internal Clang $PackageVersion through PackageReference."
    $currentLocation = Get-Location
    try {
        Set-Location $repositoryRoot
        $restoreOutput = & $nuget.Source @restoreArguments 2>&1
        $restoreExitCode = $LASTEXITCODE
    }
    finally {
        Set-Location $currentLocation
    }
    if ($restoreExitCode -ne 0) {
        throw "Internal Clang PackageReference restore failed with exit code $restoreExitCode. NuGet output: $($restoreOutput -join "`n")"
    }

    $assetsPath = Join-Path $extensionsDirectory "project.assets.json"
    $generatedPropsPath = Join-Path $extensionsDirectory "clang-toolchain.vcxproj.nuget.g.props"
    if (-not (Test-Path $assetsPath) -or -not (Test-Path $generatedPropsPath)) {
        throw "Internal Clang restore did not produce the expected assets and generated properties under '$extensionsDirectory'. NuGet output: $($restoreOutput -join "`n")"
    }

    $resolvedPathsFile = Join-Path ([System.IO.Path]::GetTempPath()) ("ebpf-clang-paths-{0}.txt" -f [guid]::NewGuid().ToString("N"))
    try {
        & $msbuild $projectPath /t:WriteResolvedClangPackagePaths /p:Configuration=Release /p:Platform=x64 "/p:ResolvedClangPackagePathsFile=$resolvedPathsFile" /nologo /v:minimal
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $resolvedPathsFile)) {
            throw "MSBuild could not evaluate the restored Clang package paths."
        }

        $paths = @{}
        foreach ($line in (Get-Content $resolvedPathsFile)) {
            $separator = $line.IndexOf("=")
            if ($separator -le 0) {
                throw "Unexpected resolved Clang package path line: '$line'."
            }
            $paths[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
        }

        if (-not $paths["llvm.tools"] -or -not $paths["clang.headers"]) {
            throw "The restored Clang package paths were incomplete."
        }

        return @{
            CompilerPath = Join-Path $paths["llvm.tools"] "clang.exe"
            ResourceDirectory = $paths["clang.headers"]
        }
    }
    finally {
        Remove-Item -LiteralPath $resolvedPathsFile -Force -ErrorAction SilentlyContinue
    }
}

$stateSchemaVersion = Get-ManifestValue "EbpfClangToolchainStateSchemaVersion"
$publicVersion = Get-ManifestValue "EbpfPublicClangVersion"
$internalVersion = Get-ManifestValue "EbpfInternalClangVersion"
$internalPackageRevision = Get-ManifestValue "EbpfInternalClangPackageRevision"
$internalPackageVersion = "$internalVersion-$internalPackageRevision"
$requestedChannel = $Channel
$channelResolution = Resolve-ClangChannel -RequestedChannel $requestedChannel
$Channel = $channelResolution.Channel
Write-Host "Requested Clang channel: $requestedChannel"
Write-Host "Resolved Clang channel: $Channel ($($channelResolution.Reason))."
$requestedPublicClangSource = if ($publicClangSourceSpecified) { $PublicClangSource } else { "<not specified>" }
Write-Host "Requested Public Clang source: $requestedPublicClangSource"
$persistedPublicSelection = if ($Channel -eq "Public") { Get-PersistedPublicClangSelection } else { $null }
$effectivePublicClangSource = $null
$reusePersistedPublicSelection = $false
if ($Channel -eq "Internal") {
    if ($publicClangSourceSpecified) {
        throw (
            "PublicClangSource applies only to the Public Clang channel, but the resolved channel is Internal. " +
            "Specify -Channel Public to select a Public Clang source.")
    }
} elseif (-not $publicClangSourceSpecified -and
    $requestedChannel -eq "Auto" -and
    $persistedPublicSelection) {
    $effectivePublicClangSource = $persistedPublicSelection.Source
    $reusePersistedPublicSelection = $true
    Write-Host "Resolved Public Clang source: $effectivePublicClangSource (reusing the persisted selection)."
} else {
    $effectivePublicClangSource = $PublicClangSource
    $sourceReason = if ($publicClangSourceSpecified) { "explicitly requested" } else { "default selection" }
    Write-Host "Resolved Public Clang source: $effectivePublicClangSource ($sourceReason)."
}
$compilerPath = ""
$resourceDirectory = ""
$packageVersion = ""
$expectedVersion = ""
$selectedSource = ""

if ($Channel -eq "Internal") {
    $packagePaths = Get-InternalClangPackagePaths -PackageVersion $internalPackageVersion
    $compilerPath = $packagePaths.CompilerPath
    $resourceDirectory = $packagePaths.ResourceDirectory
    $packageVersion = $internalPackageVersion
    $expectedVersion = $internalVersion
    $selectedSource = "InternalNuGet"
} else {
    $candidatePaths = [System.Collections.Generic.List[object]]::new()
    if ($effectivePublicClangSource -ne "Portable" -and
        $persistedPublicSelection -and
        $persistedPublicSelection.Source -eq "Installed") {
        $candidatePaths.Add($persistedPublicSelection)
    }
    if ($effectivePublicClangSource -ne "Portable") {
        $programFilesCompiler = Join-Path $env:ProgramFiles "LLVM\bin\clang.exe"
        if (Test-Path $programFilesCompiler) {
            $candidatePaths.Add([pscustomobject]@{
                CompilerPath = $programFilesCompiler
                Source = "Installed"
            })
        }
        foreach ($command in (Get-Command clang.exe -All -ErrorAction SilentlyContinue)) {
            if ($command.Source -and (Test-Path $command.Source)) {
                $candidatePaths.Add([pscustomobject]@{
                    CompilerPath = $command.Source
                    Source = "Installed"
                })
            }
        }
    }
    if ($persistedPublicSelection -and
        $persistedPublicSelection.Source -eq "Portable" -and
        ($effectivePublicClangSource -eq "Auto" -or $reusePersistedPublicSelection)) {
        $candidatePaths.Add($persistedPublicSelection)
    }

    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rejections = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in $candidatePaths) {
        $candidatePath = [System.IO.Path]::GetFullPath($candidate.CompilerPath)
        if (-not $seenPaths.Add($candidatePath)) {
            continue
        }
        if ($candidatePath -match '\\VC\\Tools\\Llvm\\bin\\clang\.exe$') {
            $rejections.Add("$candidatePath (Visual Studio's bundled Clang is not supported for BPF)")
            continue
        }

        try {
            $candidateVersion = Get-ClangVersion $candidatePath
            if ($candidateVersion -ne $publicVersion) {
                $rejections.Add("$candidatePath (version $candidateVersion; expected $publicVersion)")
                continue
            }
            $candidateResourceDirectory = Get-ClangResourceDirectory $candidatePath
            Test-ClangToolchain `
                -CompilerPath $candidatePath `
                -ResourceDirectory $candidateResourceDirectory `
                -ExpectedVersion $publicVersion
            $compilerPath = $candidatePath
            $resourceDirectory = $candidateResourceDirectory
            $selectedSource = $candidate.Source
            break
        }
        catch {
            $rejections.Add("$candidatePath ($($_.Exception.Message))")
        }
    }

    if (-not $compilerPath -and $effectivePublicClangSource -eq "Installed") {
        $details = if ($rejections.Count) {
            "`nChecked candidates:`n - " + ($rejections -join "`n - ")
        } else {
            "`nNo Clang executables were found on PATH or in '$env:ProgramFiles\LLVM\bin'."
        }
        throw (
            "No usable installed Public Clang $publicVersion installation was found. " +
            "Install that version or explicitly select -PublicClangSource Auto or Portable.$details")
    }

    if (-not $compilerPath) {
        $publicClang = & (Join-Path $PSScriptRoot "get-public-clang.ps1")
        $compilerPath = $publicClang.CompilerPath
        $resourceDirectory = $publicClang.ResourceDirectory
        $selectedSource = "Portable"
    }
    $expectedVersion = $publicVersion
}

Test-ClangToolchain -CompilerPath $compilerPath -ResourceDirectory $resourceDirectory -ExpectedVersion $expectedVersion

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $generatedPropertiesPath) | Out-Null
$generatedProperties = [ordered]@{
    EbpfConfiguredClangStateSchemaVersion = $stateSchemaVersion
    EbpfConfiguredClangChannel = $Channel
    EbpfConfiguredClangSource = $selectedSource
    EbpfConfiguredClangPath = $compilerPath
    EbpfConfiguredClangVersion = $expectedVersion
    EbpfConfiguredClangPackageVersion = $packageVersion
    EbpfConfiguredClangResourceDir = $resourceDirectory
}

$document = New-Object System.Xml.XmlDocument
$project = $document.CreateElement("Project", "http://schemas.microsoft.com/developer/msbuild/2003")
$null = $document.AppendChild($project)
$propertyGroup = $document.CreateElement("PropertyGroup", $project.NamespaceURI)
$null = $project.AppendChild($propertyGroup)
foreach ($property in $generatedProperties.GetEnumerator()) {
    $node = $document.CreateElement($property.Key, $project.NamespaceURI)
    $node.InnerText = $property.Value
    $null = $propertyGroup.AppendChild($node)
}

$settings = New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.Encoding = New-Object System.Text.UTF8Encoding($false)
$temporaryPropertiesPath = "{0}.{1}.tmp" -f $generatedPropertiesPath, [guid]::NewGuid().ToString("N")
$writer = [System.Xml.XmlWriter]::Create($temporaryPropertiesPath, $settings)
try {
    $document.Save($writer)
}
finally {
    $writer.Dispose()
}

$existingContent = if (Test-Path $generatedPropertiesPath) {
    Get-Content -Path $generatedPropertiesPath -Raw -Encoding UTF8
} else {
    ""
}
$newContent = Get-Content -Path $temporaryPropertiesPath -Raw -Encoding UTF8
if ($existingContent -ne $newContent) {
    Move-Item -LiteralPath $temporaryPropertiesPath -Destination $generatedPropertiesPath -Force
} else {
    Remove-Item -LiteralPath $temporaryPropertiesPath -Force
}

Write-Host "Configured $Channel Clang $expectedVersion from $selectedSource at '$compilerPath'."
Write-Host "Using Clang resource directory '$resourceDirectory'."
