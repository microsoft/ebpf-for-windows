# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT


Write-Host "File Location = $PSScriptRoot"

$ebpfMapJsonFileName = "$PSScriptRoot\..\libs\execution_context\ebpf_maps.json"

$outputFile = "$PSScriptRoot\..\libs\execution_context\ebpf_map_macros.h"

# Read the json file
$ebpfMapJson = Get-Content $ebpfMapJsonFileName | ConvertFrom-Json

function Get-MapTypeToPropertyMapping
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
        if ($map.map_type -eq "BPF_MAP_TYPE_UNSPEC")
        {
            continue
        }
        if ($include -and ($null -ne $map.$property))
        {
            if ($hashTable.Contains($map.$property))
            {
                $hashTable[$map.$property] += $map.map_type
            }
            else
            {
                $hashTable[$map.$property] = @($map.map_type)
            }
        }
        elseif ((!$include -and ($null -eq $map.$property)))
        {
            if ($hashTable.Contains($property))
            {
                $hashTable[$property] += $map.map_type
            }
            else
            {
                $hashTable[$property] = @($map.map_type)
            }
        }
    }

    return $hashTable
}

function Get-MapTypesForProperty
{
    param(
        [Parameter(Mandatory = $true)][string] $property,
        [Parameter(Mandatory = $false)][bool] $include = $true
    )

    $mapTypesArray = @()

    for ($i = 0; $i -lt $ebpfMapJson.maps.Length; $i++)
    {
        $map = $ebpfMapJson.maps[$i]
        # Ignore the map of type BPF_MAP_TYPE_UNSPEC
        if ($map.map_type -eq "BPF_MAP_TYPE_UNSPEC")
        {
            continue
        }
        if ($include -and ($null -ne $map.$property))
        {
            $mapTypesArray += $map.map_type
        }
        elseif ((!$include -and ($null -eq $map.$property)))
        {
            $mapTypesArray += $map.map_type
        }
    }

    return $mapTypesArray
}

function Generate-FindEntry()
{
    $macro = "#define FIND_ENTRY(type, map, key, flags, return_value, result) \`n"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property "find_entry"

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

    $macro += "}`n`n"

    return $macro
}

function Generate-DeleteEntry()
{
    $macro = "#define DELETE_ENTRY(type, map, key, result) \`n"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property "delete_entry"

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        result = $property( \`n"
        $macro += "            (ebpf_map_t*)map, key); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        result = EBPF_INVALID_ARGUMENT; \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n`n"

    return $macro
}

function Generate-DeleteMap()
{
    $macro = "#define DELETE_MAP(type, map) \`n"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property "delete_map"

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        $property((ebpf_map_t*)map); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n`n"

    return $macro
}

function Get-SupportedMacro
{
    param(
        [Parameter(Mandatory = $true)][string] $propertyName,
        [Parameter(Mandatory = $true)][string] $macroPrefix
    )

    $macro = "#define " + $macroPrefix + "_SUPPORTED(type) \`n"
    $mapTypesExcluded = Get-MapTypesForProperty -property $propertyName -include $false
    $mapTypesIncluded = Get-MapTypesForProperty -property $propertyName -include $true

    $negate = $false

    $mapTypes = @()
    if ($mapTypesExcluded.Count -lt $mapTypesIncluded.Count)
    {
        $mapTypes = $mapTypesExcluded
        $negate = $true
    }
    else
    {
        $mapTypes = $mapTypesIncluded
    }

    # Generate if statement for each property
    $macro += "    ( \`n"
    foreach ($type in $mapTypes)
    {
        if ($negate)
        {
            $macro += "        (type != $type) && \`n"
        }
        else
        {
            $macro += "        (type == $type) || \`n"
        }
    }
    $macro = $macro.Substring(0, $macro.Length - 5)
    $macro += "    \`n"
    $macro += "    ) \`n`n"

    return $macro
}

function Generate-GetObjectFromEntry()
{
    $macro = "#define GET_OBJECT_FROM_ENTRY(type, map, key, object) \`n"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property "get_object_from_entry"

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

    $macro += "}`n`n"

    return $macro
}

function Generate-UpdateEntry()
{
    $macro = "#define UPDATE_ENTRY(type, map, key, value, option, result) \`n"
    $propertyName = "update_entry"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property $propertyName

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

    $macro += "}`n`n"

    return $macro
}

function Generate-UpdateEntryWithHandle()
{
    $macro = "#define UPDATE_ENTRY_WITH_HANDLE(type, map, key, value_handle, option, result) \`n"
    $propertyName = "update_entry_with_handle"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property $propertyName

    $macro += "{ \`n"
    $macro += "    switch (type) { \`n"

    foreach ($property in $propertyToNameMapping.Keys)
    {
        foreach ($mapType in $propertyToNameMapping[$property])
        {
            $macro += "    case $mapType : \`n"
        }

        $macro += "        result = $property( \`n"
        $macro += "            map, key, value_handle, option); \`n"
        $macro += "        break; \`n"
    }

    $macro += "    default: \`n"
    $macro += "        ebpf_assert(false); \`n"
    $macro += "        result = EBPF_INVALID_ARGUMENT; \`n"
    $macro += "        break; \`n"
    $macro += "    } \`n"

    $macro += "}`n`n"

    return $macro
}

function Generate-UpdateEntryPerCpu()
{
    $macro = "#define UPDATE_ENTRY_PER_CPU(type, map, key, value, option, result) \`n"
    $propertyName = "update_entry_per_cpu"

    $propertyToNameMapping = Get-MapTypeToPropertyMapping -property $propertyName

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

    $macro += "}`n`n"

    return $macro
}

function Generate-MetadataTable
{
    $macro = "const ebpf_map_metadata_table_t ebpf_map_metadata_tables[] = {`n"

    for ($i = 0; $i -lt $ebpfMapJson.maps.Length; $i++)
    {
        $map = $ebpfMapJson.maps[$i]
        $macro += "    {`n"
        foreach ($obj in $map.psobject.Properties)
        {
            if ($($obj.Value) -ne $null)
            {
                if ($($obj.Value) -eq "True")
                {
                    $macro += "        .$($obj.Name) = true,`n"
                }
                else
                {
                    $macro += "        .$($obj.Name) = $($obj.Value),`n"
                }
            }
        }
        $macro += "    },`n"
    }

    $macro += "};`n`n"

    return $macro
}

function Generate-FileHeader()
{
    $macro = "// Copyright (c) eBPF for Windows contributors`n"
    $macro += "// SPDX-License-Identifier: MIT*/`n"
    $macro += "`n"
    $macro += "/*`n"
    $macro += " * This file is generated by the script generate_ebpf_map_macros.ps1`n"
    $macro += " * Do not modify this file manually`n"
    $macro += " * `n"
    $macro += " * If there is a need to update the macros, update and run the above script`n"
    $macro += " * to regenerate this file.`n"
    $macro += " *`n"
    $macro += " * If there is a need to update the metadata table (new map type, etc.), update`n"
    $macro += " * ebpf_maps.json, and re-run the above script.`n"
    $macro += " */`n"
    $macro += "`n"
    $macro += "#pragma once`n"
    $macro += "`n"
    $macro += "#include `"ebpf_maps_structs.h`"`n"
    $macro += "`n"

    return $macro
}

function Generate-SupportedMacros
{
    $output = Get-SupportedMacro -propertyName "find_entry" -macroPrefix "FIND_ENTRY"
    $output += Get-SupportedMacro -propertyName "update_entry_per_cpu" -macroPrefix "UPDATE_ENTRY_PER_CPU"
    $output += Get-SupportedMacro -propertyName "update_entry" -macroPrefix "UPDATE_ENTRY"
    $output += Get-SupportedMacro -propertyName "delete_entry" -macroPrefix "DELETE_ENTRY"
    $output += Get-SupportedMacro -propertyName "get_object_from_entry" -macroPrefix "GET_OBJECT_FROM_ENTRY"
    $output += Get-SupportedMacro -propertyName "key_history" -macroPrefix "KEY_HISTORY"

    return $output
}

function Generate-Output
{
    $output = Generate-FileHeader

    $output += Generate-FindEntry
    $output += Generate-UpdateEntry
    $output += Generate-UpdateEntryPerCpu
    $output += Generate-UpdateEntryWithHandle
    $output += Generate-DeleteEntry
    $output += Generate-DeleteMap
    $output += Generate-GetObjectFromEntry

    $output += Generate-SupportedMacros

    $output += Generate-MetadataTable

    $output | Out-File $outputFile -Encoding utf8
    [GC]::Collect()
}

Generate-Output
