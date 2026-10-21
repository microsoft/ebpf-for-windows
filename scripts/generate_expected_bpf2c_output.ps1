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
    $Bpf2cCommand = ".\bpf2c.exe"

    $CurrentLocation = Get-Location

    ## Get all files in the sample path
    $SampleFiles = Get-ChildItem -Path $SamplePath | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name
    $CustomSampleFiles = Get-ChildItem -Path $SamplePath\custom_program_type | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name
    $UndockedSampleFiles = Get-ChildItem -Path $SamplePath\undocked | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name

    $SampleFiles += $CustomSampleFiles
    $SampleFiles += $UndockedSampleFiles

    Set-Location $BuildPath
    foreach ($file in $SampleFiles)
    {
        $additional_options = ""
        # If file is in the set $CustomSampleFiles, then add the --type bind option.
        if ($CustomSampleFiles -contains $file)
        {
            $additional_options = "--type bind"
        }

        $ext = [System.IO.Path]::GetExtension($file.Name)
        if (($ext -ne ".c") -and ($ext -ne ".C") -and ($ext -ne ".o") -and ($ext -ne ".O"))
        {
            continue
        }

        $FileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $ObjectFileWithPath = $FileName + ".o"
        Write-Host "Generating output for $ObjectFileWithPath"
        $ExpectedSysFileWithPath = $ExpectedOutputPath + "\" + $FileName + "_sys.c"
        $ExpectedDllFileWithPath = $ExpectedOutputPath + "\" + $FileName + "_dll.c"
        $ExpectedRawFileWithPath = $ExpectedOutputPath + "\" + $FileName + "_raw.c"

        $SysCommand = $Bpf2cCommand + " --bpf " + $ObjectFileWithPath + " --sys" + " --hash none" + " " + $additional_options
        $Output = Invoke-Expression $SysCommand
        TrimAndExport-Output -InputBuffer $Output -OutputFile $ExpectedSysFileWithPath

        $DllCommand = $Bpf2cCommand + " --bpf " + $ObjectFileWithPath + " --dll" + " --hash none" + " " + $additional_options
        $Output = Invoke-Expression $DllCommand
        TrimAndExport-Output -InputBuffer $Output -OutputFile $ExpectedDllFileWithPath

        $RawCommand = $Bpf2cCommand + " --bpf " + $ObjectFileWithPath + " --hash none" + " " + $additional_options
        $Output = Invoke-Expression $RawCommand
        TrimAndExport-Output -InputBuffer $Output -OutputFile $ExpectedRawFileWithPath
    }
    Set-Location $CurrentLocation
}

if ($args.Count -ne 1) {
    throw "Usage: .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>"
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
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

$resolvedBuildPath = (Resolve-Path $args[0]).Path
$configuration = Split-Path $resolvedBuildPath -Leaf
$platform = Split-Path (Split-Path $resolvedBuildPath -Parent) -Leaf
$supportedConfigurations = @("Debug", "Release", "NativeOnlyDebug", "NativeOnlyRelease", "FuzzerDebug")
if ($configuration -notin $supportedConfigurations -or $platform -notin @("x64", "ARM64")) {
    throw "The build output path must end in a supported <platform>\<configuration> pair."
}

# The generated state is an incremental input, but remove all BPF objects here to guarantee that
# expected output is regenerated from objects produced by the configured Public compiler.
Get-ChildItem -Path $resolvedBuildPath -Filter *.o -File -ErrorAction SilentlyContinue | Remove-Item -Force
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
