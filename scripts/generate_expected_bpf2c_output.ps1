# Copyright (c) Microsoft Corporation
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

        [void]$OutputBuffer.Add($line.Substring(0, $line.IndexOf('"') + 1) +   $line.Substring($line.LastIndexOf('\\') + 2));
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

    Set-Location $BuildPath
    foreach ($file in $SampleFiles)
    {
        $ext = [System.IO.Path]::GetExtension($file.Name)
        if (($ext -ne ".c") -and ($ext -ne ".C"))
        {
            continue
        }

        $FileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $ObjectFileWithPath = $FileName + ".o"
        Write-Host "Generating output for $ObjectFileWithPath"
        $ExpectedSysFileWithPath = $ExpectedOutputPath + "\" + $FileName + "_sys.c"
        $ExpectedDllFileWithPath = $ExpectedOutputPath + "\" + $FileName + "_dll.c"
        $ExpectedRawFileWithPath = $ExpectedOutputPath + "\" + $FileName + "_raw.c"

        $SysCommand = $Bpf2cCommand + " --bpf " + $ObjectFileWithPath + " --sys" + " --hash none"
        $Output = Invoke-Expression $SysCommand
        TrimAndExport-Output -InputBuffer $Output -OutputFile $ExpectedSysFileWithPath

        $DllCommand = $Bpf2cCommand + " --bpf " + $ObjectFileWithPath + " --dll" + " --hash none"
        $Output = Invoke-Expression $DllCommand
        TrimAndExport-Output -InputBuffer $Output -OutputFile $ExpectedDllFileWithPath

        $RawCommand = $Bpf2cCommand + " --bpf " + $ObjectFileWithPath + " --hash none"
        $Output = Invoke-Expression $RawCommand
        TrimAndExport-Output -InputBuffer $Output -OutputFile $ExpectedRawFileWithPath
    }
    Set-Location $CurrentLocation
}

Update-ExpectedOutput $args[0]
