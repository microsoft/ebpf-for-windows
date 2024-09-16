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
    xcopy /y build\bin\x64_NativeOnlyDebug .\x64\NativeOnlyDebug
    Get-ChildItem -Path .\build\bin\x64_NativeOnlyDebug -Recurse | Remove-Item -Force -Recurse
}
elseif ($OneBranchConfig -eq "NativeOnlyRelease" -and $OneBranchArch -eq "x64")
{
    xcopy /y build\bin\x64_NativeOnlyRelease .\x64\NativeOnlyRelease
    Get-ChildItem -Path .\build\bin\x64_NativeOnlyRelease -Recurse | Remove-Item -Force -Recurse
}
elseif ($OneBranchConfig -eq "NativeOnlyDebug" -and $OneBranchArch -eq "arm64")
{
    xcopy /y build\bin\x64_NativeOnlyDebug .\x64\NativeOnlyDebug
    Get-ChildItem -Path .\build\bin\x64_NativeOnlyDebug -Recurse | Remove-Item -Force -Recurse
}
elseif ($OneBranchConfig -eq "NativeOnlyRelease" -and $OneBranchArch -eq "arm64")
{
    xcopy /y build\bin\arm64_NativeOnlyRelease .\arm64\NativeOnlyRelease
    Get-ChildItem -Path .\build\bin\arm64_NativeOnlyRelease -Recurse | Remove-Item -Force -Recurse
}
else
{
    throw ("Configuration $OneBranchConfig|$OneBranchArch is not supported.")
}

Import-Module "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"  -DevCmdArguments "-arch=$OneBranchArch -host_arch=x64"
Set-Location $scriptPath\..\..
$SolutionDir = Get-Location
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\nuget\nuget.vcxproj
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\redist-package\redist-package.vcxproj
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\installer\ebpf-for-windows.wixproj

# Copy the nupkg and msi to the output directory
if ($OneBranchConfig -eq "NativeOnlyDebug" -and $OneBranchArch -eq "x64")
{
    xcopy /y .\x64\NativeOnlyDebug\*.nupkg .\build\bin\x64_NativeOnlyDebug
    xcopy /y .\x64\NativeOnlyDebug\*.msi .\build\bin\x64_NativeOnlyDebug
}
elseif ($OneBranchConfig -eq "NativeOnlyRelease" -and $OneBranchArch -eq "x64")
{
    xcopy /y .\x64\NativeOnlyRelease\*.nupkg .\build\bin\x64_NativeOnlyRelease
    xcopy /y .\x64\NativeOnlyRelease\*.msi .\build\bin\x64_NativeOnlyRelease
}
elseif ($OneBranchConfig -eq "NativeOnlyDebug" -and $OneBranchArch -eq "arm64")
{
    xcopy /y .\arm64\NativeOnlyDebug\*.nupkg .\build\bin\arm64_NativeOnlyDebug
    xcopy /y .\arm64\NativeOnlyDebug\*.msi .\build\bin\arm64_NativeOnlyDebug
}
elseif ($OneBranchConfig -eq "NativeOnlyRelease" -and $OneBranchArch -eq "arm64")
{
    xcopy /y .\arm64\NativeOnlyRelease\*.nupkg .\build\bin\arm64_NativeOnlyRelease
    xcopy /y .\arm64\NativeOnlyRelease\*.msi .\build\bin\xarm4_NativeOnlyRelease
}
else
{
    throw ("Configuration $OneBranchConfig|$OneBranchArch is not supported.")
}