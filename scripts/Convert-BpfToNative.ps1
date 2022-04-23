# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param([parameter(Mandatory=$true)] [string] $ProgramName,
[parameter(Mandatory=$false)] [string] $SolutionDir = $Pwd,
[parameter(Mandatory=$false)] [string] $Platform = "x64",
[parameter(Mandatory=$false)] [string] $Configuration = "Release",
[parameter(Mandatory=$false)] [bool] $KernelMode = $true)

Push-Location $SolutionDir
$ProjectFile = "$SolutionDir\tools\bpf2c\templates\kernel_mode_bpf2c.vcxproj"
if (!$KernelMode) {
    $ProjectFile = "$SolutionDir\tools\bpf2c\templates\user_mode_bpf2c.vcxproj"
}
msbuild /p:SolutionDir="$SolutionDir\" /p:OutDir="$SolutionDir\$Platform\$Configuration\" /p:Configuration="$Configuration" /p:Platform="$Platform" /p:ProgramName="$ProgramName" $ProjectFile
if ($LASTEXITCODE -ne 0) { throw "Build failed"}