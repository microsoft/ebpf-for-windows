# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Process-File Reads $InputFile and $ConfigFile and performs replacement of strings in the content of $InputFile based
# on the Files key in the $ConfigFile.
# $ConfigFile is a json document containing the following elements:
# Array called "Files" that contains objects with properties "Symbol" and "Filename".
# Array called "EscapeCharacters" that contains objects with properties "Char" and "Escape".
#
# Each string with the value from "Symbol" is replaced with the contents from the corresponding "FileName" after
# each occurence of "Char" in the file is replaced with "Escape".

param ([Parameter(Mandatory=$True)] [string] $InputFile,
       [Parameter(Mandatory=$True)] [string] $OutputFile,
       [Parameter(Mandatory=$True)] [string] $ConfigFile)

$Config = Get-Content -Path $ConfigFile | ConvertFrom-Json
$Data = Get-Content -Path $InputFile

$Config.Files | ForEach-Object {
    $InsertString = Get-Content -Path $_.FileName
    $Config.EscapeCharacters | ForEach-Object {
        $InsertString = $InsertString.Replace($_.Char, $_.Escape)
    }

    $Data = $Data.Replace($_.Symbol, $InsertString)
}

Set-Content -Path $OutputFile -Value $Data
