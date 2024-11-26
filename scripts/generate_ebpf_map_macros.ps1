# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# param ([parameter(Mandatory = $true)][string] $AdminTarget = "TEST_VM",
#        [parameter(Mandatory = $false)][string] $StandardUserTarget = "TEST_VM_STANDARD",
#        [parameter(Mandatory = $false)][string] $LogFileName = "TestLog.log",
#        [parameter(Mandatory = $false)][string] $WorkingDirectory = $pwd.ToString(),
#        [parameter(Mandatory = $false)][string] $TestExecutionJsonFileName = "test_execution.json",
#        [parameter(Mandatory = $false)][bool] $Coverage = $false,
#        [parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
#        [parameter(Mandatory = $false)][string[]] $Options = @("None"),
#        [parameter(Mandatory = $false)][string] $SelfHostedRunnerName = [System.Net.Dns]::GetHostName(),
#        [parameter(Mandatory = $false)][int] $TestHangTimeout = 3600,
#        [parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps"
# )

# $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host "File Location = $PSScriptRoot"

$ebpfMapJsonFileName = "$PSScriptRoot\..\libs\execution_context\ebpf_maps.json"

$outputFile = "$PSScriptRoot\..\libs\execution_context\ebpf_map_macros.c"

# Read the json file
$ebpfMapJson = Get-Content $ebpfMapJsonFileName | ConvertFrom-Json

function Get-MapNamesForProperty
{
    param(
        [Parameter(Mandatory = $true)][string] $property,
        [Parameter(Mandatory = $false)][bool] $include = $true
    )

    $hashTable = [ordered]@{}

    for ($i = 0; $i -lt $ebpfMapJson.maps.Length; $i++)
    {
        $map = $ebpfMapJson.maps[$i]
        # Ignore the map of type BPF_MAP_TYPE_UNSPEC
        if ($map.type -eq "BPF_MAP_TYPE_UNSPEC")
        {
            continue
        }
        if ($include -and ($null -ne $map.$property))
        {
            if ($hashTable.Contains($map.$property))
            {
                $hashTable[$map.$property] += $map.type
            }
            else
            {
                $hashTable[$map.$property] = @($map.type)
            }
        } 
        elseif ((!$include -and ($map.$property -eq $null)))
        {
            if ($hashTable.Contains($property))
            {
                $hashTable[$property] += $map.type
            }
            else
            {
                $hashTable[$property] = @($map.type)
            }
        }
    }

    return $hashTable
}

function Generate-FindEntry()
{
    $macro = "#define FIND_ENTRY(type, map, key, flags, return_value, result) \`n"

    $propertyToNameMapping = Get-MapNamesForProperty -property "find_entry"

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        result = $property( \`n"
        $macro += "            (ebpf_map_t*)map, key, flags, return_value); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        result = EBPF_INVALID_ARGUMENT; \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n"

    return $macro
}

function Generate-FindEntrySupported()
{
    $macro = "#define FIND_ENTRY_SUPPORTED(type) \`n"
    $propertyName = "find_entry"
    $propertyToNameMapping = Get-MapNamesForProperty -property $propertyName -include $false

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        Write-Host "Property = $property"
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        return false; \`n"
    }

    $macro += "    } \`n"

    $macro += "    return true; \`n"

    $macro += "}`n"

    return $macro
}

function Generate-GetObjectFromEntry()
{
    $macro = "#define GET_OBJECT_FROM_ENTRY(type, map, key, object) \`n"

    $propertyToNameMapping = Get-MapNamesForProperty -property "get_object_from_entry"

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        object = $property( \`n"
        $macro += "            (ebpf_map_t*)map, key); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n"

    return $macro
}

# function Generate-GetObjectFromEntrySupported()
# {
#     $macro = "#define FIND_ENTRY_SUPPORTED(type) \`n"
#     $propertyName = "find_entry"
#     $propertyToNameMapping = Get-MapNamesForProperty -property $propertyName -include $false

#     $macro += "{ \`n"
#     $macro += "    switch (type) { \`n"

#     foreach ($property in $propertyToNameMapping.Keys)
#     {
#         Write-Host "Property = $property"
#         foreach ($mapType in $propertyToNameMapping[$property])
#         {
#             $macro += "    case $mapType : \`n"
#         }

#         $macro += "        return false; \`n"
#     }

#     $macro += "    } \`n"

#     $macro += "    return true; \`n"

#     $macro += "}`n"

#     return $macro
# }

function Generate-UpdateEntry()
{
    $macro = "#define UPDATE_ENTRY(type, map, key, value, option, result) \`n"
    $propertyName = "update_entry"

    $propertyToNameMapping = Get-MapNamesForProperty -property $propertyName

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        result = $property( \`n"
        $macro += "            map, key, value, option); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        result = EBPF_INVALID_ARGUMENT; \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n"

    return $macro
}

function Generate-UpdateEntryPerCpu()
{
    $macro = "#define UPDATE_ENTRY_PER_CPU(type, map, key, value, option, result) \`n"
    $propertyName = "update_entry_per_cpu"

    $propertyToNameMapping = Get-MapNamesForProperty -property $propertyName

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        result = $property( \`n"
        $macro += "            map, key, value, option); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        result = EBPF_INVALID_ARGUMENT; \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n"

    return $macro
}

# # Read the json file
# $testExecutionJson = Get-Content $TestExecutionJsonFileName | ConvertFrom-Json

Generate-FindEntry | Out-File $outputFile
Generate-FindEntrySupported | Out-File $outputFile -Append
Generate-GetObjectFromEntry | Out-File $outputFile -Append
# Generate-GetObjectFromEntrySupported | Out-File $outputFile -Append
Generate-UpdateEntry | Out-File $outputFile -Append
Generate-UpdateEntryPerCpu | Out-File $outputFile -Append