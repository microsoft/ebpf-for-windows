# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

function filter_and_emit_output
{
    param([String[]] $input_buffer, [String]$output_file)

    $output_buffer = New-Object System.Collections.ArrayList
    foreach ($line in $input_buffer)
    {
        if (!$line.StartsWith("#line"))
        {
            [void]$output_buffer.Add($line)
            continue
        }

        if ($line.IndexOf('"') -eq -1)
        {
            [void]$output_buffer.Add($line)
            continue
        }

        [void]$output_buffer.Add($line.Substring(0, $line.IndexOf('"') + 1) +   $line.Substring($line.LastIndexOf('\\') + 2));
    }

    $output_buffer > $output_file
}

function generate_expected_output
{
    param([string]$build_path)

    $ps_root = $PSScriptRoot
    $sample_path = $ps_root + "\..\tests\sample"
    $expected_output_path = $ps_root + "\..\tests\bpf2c_tests\expected"
    $bpf2c_command = ".\bpf2c.exe"
    $bpf_option = "--bpf"
    $sys_option = "--sys"

    $current_location = Get-Location

    ## Get all files in the sample path
    $sample_files = Get-ChildItem -Path $sample_path | Where-Object {$_.PSIsContainer -eq $false} | Select-Object -Property Name

    Set-Location $build_path
    foreach ($file in $sample_files)
    {
        $ext = [System.IO.Path]::GetExtension($file.Name)
        if (($ext -ne ".c") -and ($ext -ne ".C"))
        {
            continue
        }

        $file_name = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $object_file_with_path = $file_name + ".o"
        Write-Host "Generating output for $object_file_with_path"
        $expected_file_with_path_sys = $expected_output_path + "\" + $file_name + "_sys.txt"
        $expected_file_with_path_dll = $expected_output_path + "\" + $file_name + "_dll.txt"
        $expected_file_with_path_raw = $expected_output_path + "\" + $file_name + "_raw.txt"

        $sys_command = $bpf2c_command + " --bpf " + $object_file_with_path + " --sys"
        $output = Invoke-Expression $sys_command
        filter_and_emit_output -input_buffer $output -output_file $expected_file_with_path_sys

        $dll_command = $bpf2c_command + " --bpf " + $object_file_with_path + " --dll"
        $output = Invoke-Expression $dll_command
        filter_and_emit_output -input_buffer $output -output_file $expected_file_with_path_dll

        $raw_command = $bpf2c_command + " --bpf " + $object_file_with_path
        $output = Invoke-Expression $raw_command
        filter_and_emit_output -input_buffer $output -output_file $expected_file_with_path_raw
    }
    Set-Location $current_location
}

generate_expected_output $args[0]
##generate_expected_output E:\git\github\ebpf-for-windows-1\x64\Debug
