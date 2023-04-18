# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param([Parameter(Mandatory=$True)][string]$FileName,
      [Parameter(Mandatory=$True)][string]$FilePath,
      [Parameter(Mandatory=$True)][string]$Platform,
      [Parameter(Mandatory=$True)][string]$Configuration,
      [Parameter(Mandatory=$True)][string]$KernelConfiguration,
      [Parameter(Mandatory=$True)][string]$IncludePath)

Push-Location $FilePath

$ProgramType = ""

if ($FileName -eq "bpf")
{
    $ProgramType = "xdp"
}

.\Convert-BpfToNative.ps1 -ProgramName $Filename -Type $ProgramType -IncludeDir $IncludePath -Platform $Platform -Configuration $KernelConfiguration -KernelMode $True
.\Convert-BpfToNative.ps1 -ProgramName $Filename -Type $ProgramType -IncludeDir $IncludePath -Platform $Platform -Configuration $Configuration -KernelMode $False


Pop-Location
