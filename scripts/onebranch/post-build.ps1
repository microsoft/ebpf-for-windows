# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Copy signed files from build\bin\amd64[fre|chk] to the output directory and then rebuild the nupkg and msi

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG

# Copy the signed binaries to the output directory
if ($OneBranchConfig -eq "NativeOnlyDebug" -and $OneBranchArch -eq "x64")
{
    xcopy /y build\bin\amd64chk .\x64\Debug
    Get-ChildItem -Path .\build\bin\amd64chk -Recurse | Remove-Item -Force -Recurse
}
elseif ($OneBranchConfig -eq "NativeOnlyRelease" -and $OneBranchArch -eq "x64")
{
    xcopy /y build\bin\amd64fre .\x64\NativeOnlyRelease
    Get-ChildItem -Path .\build\bin\amd64fre -Recurse | Remove-Item -Force -Recurse
}
else
{
    throw ("Configuration $OneBranchConfig|$OneBranchArch is not supported.")
}

Import-Module "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"  -DevCmdArguments "-arch=x64 -host_arch=x64"
Set-Location $scriptPath\..\..
$SolutionDir = Get-Location
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\nuget\nuget.vcxproj
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\redist-package\redist-package.vcxproj
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\installer\ebpf-for-windows.wixproj

# Copy the nupkg and msi to the output directory
if ($OneBranchConfig -eq "Release" -and $OneBranchArch -eq "x64")
{
    xcopy /y .\x64\Release\*.nupkg .\build\bin\amd64fre
    xcopy /y .\x64\Release\*.msi .\build\bin\amd64fre
}
elseif ($OneBranchConfig -eq "NativeOnlyRelease" -and $OneBranchArch -eq "x64")
{
    xcopy /y .\x64\NativeOnlyRelease\*.nupkg .\build\bin\amd64fre
    xcopy /y .\x64\NativeOnlyRelease\*.msi .\build\bin\amd64fre
}
else
{
    xcopy /y .\x64\Debug\*.nupkg .\build\bin\amd64chk
    xcopy /y .\x64\Debug\*.msi .\build\bin\amd64chk
}
