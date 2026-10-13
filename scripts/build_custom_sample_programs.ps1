# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param([Parameter(Mandatory=$True)][string]$FileName,
      [Parameter(Mandatory=$True)][string]$FilePath,
  [Parameter(Mandatory=$False)][string]$BinPath = $FilePath,
      [Parameter(Mandatory=$True)][string]$Platform,
      [Parameter(Mandatory=$True)][string]$Configuration,
      [Parameter(Mandatory=$True)][string]$KernelConfiguration,
      [Parameter(Mandatory=$True)][string]$IncludePath)

Push-Location $FilePath

$ProgramType = ""

if ($FileName -eq "bpf")
{
    $ProgramType = "bind"
}

& "$BinPath\Convert-BpfToNative.ps1" -FileName $Filename -Type $ProgramType -IncludeDir $IncludePath -BinDir $BinPath -Platform $Platform -Configuration $KernelConfiguration -KernelMode $True
& "$BinPath\Convert-BpfToNative.ps1" -FileName $Filename -Type $ProgramType -IncludeDir $IncludePath -BinDir $BinPath -Platform $Platform -Configuration $Configuration -KernelMode $False


Pop-Location
