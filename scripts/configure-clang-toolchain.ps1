# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param (
    [parameter(Mandatory = $true)][ValidateSet("Public", "Internal")][string] $Channel,
    [parameter(Mandatory = $false)][string] $MSBuildPath
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
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
    $rootNuGetConfig = Join-Path $repositoryRoot "nuget.config"
    if (Test-Path $rootNuGetConfig) {
        $restoreArguments += @("-ConfigFile", $rootNuGetConfig)
    }
    $restoreArguments += @("-MSBuildPath", $msbuildDirectory)

    Write-Host "Restoring Internal Clang $PackageVersion through PackageReference."
    $restoreOutput = & $nuget.Source @restoreArguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Internal Clang PackageReference restore failed with exit code $LASTEXITCODE. NuGet output: $($restoreOutput -join "`n")"
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
$compilerPath = ""
$resourceDirectory = ""
$packageVersion = ""
$expectedVersion = ""

if ($Channel -eq "Internal") {
    $packagePaths = Get-InternalClangPackagePaths -PackageVersion $internalPackageVersion
    $compilerPath = $packagePaths.CompilerPath
    $resourceDirectory = $packagePaths.ResourceDirectory
    $packageVersion = $internalPackageVersion
    $expectedVersion = $internalVersion
} else {
    $candidatePaths = [System.Collections.Generic.List[string]]::new()
    $programFilesCompiler = Join-Path $env:ProgramFiles "LLVM\bin\clang.exe"
    if (Test-Path $programFilesCompiler) {
        $candidatePaths.Add($programFilesCompiler)
    }
    foreach ($command in (Get-Command clang.exe -All -ErrorAction SilentlyContinue)) {
        if ($command.Source -and (Test-Path $command.Source)) {
            $candidatePaths.Add($command.Source)
        }
    }

    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rejections = [System.Collections.Generic.List[string]]::new()
    foreach ($candidatePath in $candidatePaths) {
        $candidatePath = [System.IO.Path]::GetFullPath($candidatePath)
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
            Test-ClangToolchain -CompilerPath $candidatePath -ResourceDirectory $candidateResourceDirectory -ExpectedVersion $publicVersion
            $compilerPath = $candidatePath
            $resourceDirectory = $candidateResourceDirectory
            break
        }
        catch {
            $rejections.Add("$candidatePath ($($_.Exception.Message))")
        }
    }

    if (-not $compilerPath) {
        $details = if ($rejections.Count) {
            "`nChecked candidates:`n - " + ($rejections -join "`n - ")
        } else {
            "`nNo Clang executables were found on PATH or in '$env:ProgramFiles\LLVM\bin'."
        }
        throw "No usable Public Clang $publicVersion installation was found. Install the pinned LLVM version or, with access to the configured internal feed, rerun initialization with -LlvmChannel Internal.$details"
    }

    $expectedVersion = $publicVersion
}

Test-ClangToolchain -CompilerPath $compilerPath -ResourceDirectory $resourceDirectory -ExpectedVersion $expectedVersion

$generatedPropertiesPath = Join-Path $repositoryRoot "build\ebpf-clang-toolchain.props"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $generatedPropertiesPath) | Out-Null
$generatedProperties = [ordered]@{
    EbpfConfiguredClangStateSchemaVersion = $stateSchemaVersion
    EbpfConfiguredClangChannel = $Channel
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
    Get-Content -Path $generatedPropertiesPath -Raw
} else {
    ""
}
$newContent = Get-Content -Path $temporaryPropertiesPath -Raw
if ($existingContent -ne $newContent) {
    Move-Item -LiteralPath $temporaryPropertiesPath -Destination $generatedPropertiesPath -Force
} else {
    Remove-Item -LiteralPath $temporaryPropertiesPath -Force
}

Write-Host "Configured $Channel Clang $expectedVersion at '$compilerPath'."
Write-Host "Using Clang resource directory '$resourceDirectory'."
