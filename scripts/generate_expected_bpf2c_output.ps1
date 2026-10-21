# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Whenever either the BPF2C code changes or any of the sample programs changes,
# bpf2c_tests will fail unless the expected files in tests\bpf2c_tests\expected
# are updated. This script can be used to regenerate the expected files.
#
# Usage:
# .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
# Example:
# .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

$ErrorActionPreference = "Stop"

<#
TrimAndExport-Output does the following:
1. Parses the buffer and converts the absolute file path present in "#line" pragma statements
   to relative paths. This helps reducing churn in the generated files.
2. Exports the buffer to the provided output file.
3. Changes the encoding of the output file to Ascii.
#>
function TrimAndExport-Output
{
    param([String[]] $InputBuffer, [String]$OutputFile)

    $OutputBuffer = New-Object System.Collections.ArrayList
    foreach ($line in $InputBuffer)
    {
        if (!$line.StartsWith("#line"))
        {
            [void]$OutputBuffer.Add($line)
            continue
        }

        if ($line.IndexOf('"') -eq -1)
        {
            [void]$OutputBuffer.Add($line)
            continue
        }

        [void]$OutputBuffer.Add($line.Substring(0, $line.IndexOf('"') + 1) + $line.Substring($line.LastIndexOf('sample/')).Replace("\\", "/"));
    }

    $OutputBuffer > $OutputFile

    # Change output file format to Ascii.
    (Get-Content -Path $OutputFile) | Set-Content -Encoding Ascii -Path $OutputFile
}

function Invoke-Bpf2c
{
    param(
        [string] $ExecutablePath,
        [string[]] $Arguments,
        [string] $OutputFile
    )

    $errorFile = Join-Path ([System.IO.Path]::GetTempPath()) ("bpf2c-{0}.err" -f [guid]::NewGuid().ToString("N"))
    try
    {
        $output = @(& $ExecutablePath @Arguments 2> $errorFile)
        $exitCode = $LASTEXITCODE
        $errorOutput = if (Test-Path $errorFile) { @(Get-Content $errorFile) } else { @() }
        if ($exitCode -ne 0)
        {
            throw "bpf2c failed with exit code $exitCode for arguments '$($Arguments -join ' ')'. Output: $($errorOutput -join ' ')"
        }
        if ($output.Count -eq 0)
        {
            throw "bpf2c produced no output for arguments '$($Arguments -join ' ')'."
        }

        TrimAndExport-Output -InputBuffer $output -OutputFile $OutputFile
    }
    finally
    {
        Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
    }
}

<#
Update-ExpectedOutput updates the expected result files (raw, sys, dll) for all the
sample programs present in test\samples.
#>
function Update-ExpectedOutput
{
    param([string]$BuildPath)

    $PSRoot = $PSScriptRoot
    $SamplePath = $PSRoot + "\..\tests\sample"
    $ExpectedOutputPath = $PSRoot + "\..\tests\bpf2c_tests\expected"
    $Bpf2cCommand = Join-Path $BuildPath "bpf2c.exe"
    if (-not (Test-Path $Bpf2cCommand))
    {
        throw "bpf2c was not found at '$Bpf2cCommand'."
    }

    ## Get all files in the sample path
    $SampleFiles = @(Get-ChildItem -Path $SamplePath | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name)
    $CustomSampleFiles = @(Get-ChildItem -Path $SamplePath\custom_program_type | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name)
    $UndockedSampleFiles = @(Get-ChildItem -Path $SamplePath\undocked | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name)

    $SampleFiles += $CustomSampleFiles
    $SampleFiles += $UndockedSampleFiles

    $stagingPath = Join-Path ([System.IO.Path]::GetTempPath()) ("ebpf-bpf2c-expected-{0}" -f [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $stagingPath | Out-Null
    try
    {
        foreach ($file in $SampleFiles)
        {
            $additionalOptions = @()
            # If file is in the set $CustomSampleFiles, add the --type bind option.
            if ($CustomSampleFiles -contains $file)
            {
                $additionalOptions = @("--type", "bind")
            }

            $ext = [System.IO.Path]::GetExtension($file.Name)
            if (($ext -ne ".c") -and ($ext -ne ".C") -and ($ext -ne ".o") -and ($ext -ne ".O"))
            {
                continue
            }

            $FileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $ObjectFileWithPath = Join-Path $BuildPath ($FileName + ".o")
            if (-not (Test-Path $ObjectFileWithPath))
            {
                throw "The required BPF object was not generated: $ObjectFileWithPath"
            }

            Write-Host "Generating output for $ObjectFileWithPath"
            $StagedSysFile = Join-Path $stagingPath ($FileName + "_sys.c")
            $StagedDllFile = Join-Path $stagingPath ($FileName + "_dll.c")
            $StagedRawFile = Join-Path $stagingPath ($FileName + "_raw.c")

            Invoke-Bpf2c -ExecutablePath $Bpf2cCommand -Arguments (@("--bpf", $ObjectFileWithPath, "--sys", "--hash", "none") + $additionalOptions) -OutputFile $StagedSysFile
            Invoke-Bpf2c -ExecutablePath $Bpf2cCommand -Arguments (@("--bpf", $ObjectFileWithPath, "--dll", "--hash", "none") + $additionalOptions) -OutputFile $StagedDllFile
            Invoke-Bpf2c -ExecutablePath $Bpf2cCommand -Arguments (@("--bpf", $ObjectFileWithPath, "--hash", "none") + $additionalOptions) -OutputFile $StagedRawFile
        }

        Get-ChildItem -Path $stagingPath -File | Copy-Item -Destination $ExpectedOutputPath -Force
    }
    finally
    {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($args.Count -ne 1) {
    throw "Usage: .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>"
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$resolvedBuildPath = (Get-Item $args[0]).FullName
$configuration = Split-Path $resolvedBuildPath -Leaf
$platform = Split-Path (Split-Path $resolvedBuildPath -Parent) -Leaf
if ($configuration -eq "FuzzerDebug") {
    throw "FuzzerDebug does not build the complete sample set required for expected bpf2c output generation."
}
$supportedConfigurations = @("Debug", "Release", "NativeOnlyDebug", "NativeOnlyRelease")
if ($configuration -notin $supportedConfigurations -or $platform -notin @("x64", "ARM64")) {
    throw "The build output path must end in a supported <platform>\<configuration> pair."
}

$expectedBuildPath = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "$platform\$configuration"))
if (Test-Path $expectedBuildPath) {
    $expectedBuildPath = (Get-Item $expectedBuildPath).FullName
}
if (-not [System.String]::Equals(
        $resolvedBuildPath.TrimEnd("\"),
        $expectedBuildPath.TrimEnd("\"),
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The build output path must be the repository output directory '$expectedBuildPath'."
}

$toolchainPropertiesPath = Join-Path $repositoryRoot "build\ebpf-clang-toolchain.props"
if (-not (Test-Path $toolchainPropertiesPath)) {
    throw "The BPF Clang toolchain is not configured. Run .\scripts\initialize_ebpf_repo.ps1 before regenerating expected output."
}

function Get-XmlProperty {
    param(
        [xml] $Document,
        [string] $Name
    )

    $namespaceManager = New-Object System.Xml.XmlNamespaceManager($Document.NameTable)
    $namespaceManager.AddNamespace("m", "http://schemas.microsoft.com/developer/msbuild/2003")
    $node = $Document.SelectSingleNode("/m:Project/m:PropertyGroup/m:$Name", $namespaceManager)
    if (-not $node) {
        throw "The property '$Name' is missing."
    }
    return $node.InnerText
}

[xml]$toolchainProperties = Get-Content -Path $toolchainPropertiesPath -Raw
[xml]$manifest = Get-Content -Path (Join-Path $PSScriptRoot "clang-toolchain.props") -Raw
$channel = Get-XmlProperty -Document $toolchainProperties -Name "EbpfConfiguredClangChannel"
$version = Get-XmlProperty -Document $toolchainProperties -Name "EbpfConfiguredClangVersion"
$resourceDirectory = Get-XmlProperty -Document $toolchainProperties -Name "EbpfConfiguredClangResourceDir"
$publicVersion = Get-XmlProperty -Document $manifest -Name "EbpfPublicClangVersion"
if ($channel -ne "Public" -or $version -ne $publicVersion) {
    throw "Expected bpf2c outputs must be generated with Public Clang $publicVersion; the configured toolchain is $channel Clang $version."
}
if (-not (Test-Path (Join-Path $resourceDirectory "include\stdint.h"))) {
    throw "The configured Public Clang resource headers are missing. Run repository initialization again."
}

$hostPlatform = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$currentLocation = Get-Location
try {
    Set-Location $repositoryRoot
    & msbuild ebpf-for-windows.sln /m /t:tests\sample "/p:Configuration=$configuration" "/p:Platform=$platform" "/p:HostPlatform=$hostPlatform"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to rebuild BPF sample objects with Public Clang $publicVersion."
    }
}
finally {
    Set-Location $currentLocation
}

Update-ExpectedOutput $resolvedBuildPath
