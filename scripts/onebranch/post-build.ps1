# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Copy signed files from build\bin\amd64[fre|chk] to the output directory and then rebuild the nupkg and msi

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG

function CopySignedBinaries {
    param (
        [string]$Config,
        [string]$Arch
    )
    xcopy /y "build\bin\$Arch\_$Config" ".\$Arch\$Config"
    Get-ChildItem -Path "build\bin\$Arch\_$Config" -Recurse | Remove-Item -Force -Recurse
}

function CopyPackages {
    param (
        [string]$Config,
        [string]$Arch
    )
    xcopy /y ".\$Arch\$Config\*.nupkg" "build\bin\$Arch\_$Config"
    xcopy /y ".\$Arch\$Config\*.msi" "build\bin\$Arch\_$Config"
}

if ($OneBranchConfig -eq "NativeOnlyDebug" -or $OneBranchConfig -eq "NativeOnlyRelease")
{
    if ($OneBranchArch -eq "x64" -or $OneBranchArch -eq "arm64")
    {
        CopySignedBinaries -Config $OneBranchConfig -Arch $OneBranchArch
    }
    else
    {
        throw ("Architecture $OneBranchArch is not supported.")
    }
}
else
{
    throw ("Configuration $OneBranchConfig is not supported.")
}

Import-Module "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"  -DevCmdArguments "-arch=$OneBranchArch -host_arch=x64"
Set-Location $scriptPath\..\..
$SolutionDir = Get-Location
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\nuget\nuget.vcxproj
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\redist-package\redist-package.vcxproj
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\installer\ebpf-for-windows.wixproj

# After building the packages
# Copy the nupkg and msi to the output directory
if ($OneBranchConfig -eq "NativeOnlyDebug" -or $OneBranchConfig -eq "NativeOnlyRelease")
{
    if ($OneBranchArch -eq "x64" -or $OneBranchArch -eq "arm64")
    {
        CopyPackages -Config $OneBranchConfig -Arch $OneBranchArch
    }
    else
    {
        throw ("Architecture $OneBranchArch is not supported.")
    }
}
else
{
    throw ("Configuration $OneBranchConfig is not supported.")
}
