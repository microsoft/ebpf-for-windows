# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Copy signed files from build\bin\amd64[fre|chk] to the output directory and then rebuild the nupkg and msi

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG

function FormatBinDir($Config, $Arch) {
    $BinDir = "build\bin\$Arch"
    $BinDir += "_"
    $BinDir += $Config
    return $BinDir
}

function CopySignedBinaries {
    param (
        [string]$Config,
        [string]$Arch
    )
    $BinDir = FormatBinDir $Config $Arch
    xcopy /y $BinDir ".\$Arch\$Config"
    Get-ChildItem -Path $BinDir -Recurse | Remove-Item -Force -Recurse
}

# List of binaries to copy to output directory
$BinariesToCopy = @(
    "bpftool.exe",
    "bpftool.pdb",
    "ebpfapi.dll",
    "ebpfapi.lib",
    "ebpfapi.pdb",
    "ebpfcore.pdb",
    "ebpfcore.sys",
    "ebpfnetsh.dll",
    "ebpfnetsh.pdb",
    "ebpfsvc.exe",
    "ebpfsvc.pdb",
    "netebpfext.pdb",
    "netebpfext.sys",
    "api_test.exe",
    "api_test.pdb",
    "test_sample_ebpf.o",
    "test_sample_ebpf.sys",
    "bindmonitor.o",
    "bindmonitor.sys",
    "bindmonitor_ringbuf.o",
    "bindmonitor_ringbuf.sys",
    "bindmonitor_perf_event_array.o",
    "bindmonitor_perf_event_array.sys",
    "bindmonitor_tailcall.o",
    "bindmonitor_tailcall.sys",
    "tail_call_multiple.o",
    "tail_call_multiple.sys",
    "tail_call_max_exceed.o",
    "tail_call_max_exceed.sys",
    "pidtgid.o",
    "pidtgid.sys",
    "process_start_key.o",
    "process_start_key.sys",
    "thread_start_time.o",
    "thread_start_time.sys",
    "printk.o",
    "printk.sys",
    "multiple_programs.o",
    "multiple_programs.sys",
    "divide_by_zero.o",
    "printk_unsafe.o",
    "sample_ebpf_ext.sys",
    "export_program_info.exe",
    "export_program_info.pdb",
    "export_program_info_sample.exe",
    "export_program_info_sample.pdb",
    "export_program_info_test.exe",
    "export_program_info_test.pdb",
    "socket_tests.exe",
    "socket_tests.pdb"
)

function CopyPackages {
    param (
        [string]$Config,
        [string]$Arch
    )
    $BinDir = FormatBinDir $Config $Arch

    # Copy the signed packages to the output directory
    $PackagesDir = "$BinDir\packages"
    if (-not (Test-Path -Path $PackagesDir)) {
        New-Item -ItemType Directory -Path $PackagesDir
    }

    xcopy /y ".\$Arch\$Config\*.nupkg" $PackagesDir
    xcopy /y ".\$Arch\$Config\*.msi" $BinDir

    # Copy the signed binaries to the output directory
    $OutputBinDir = "$BinDir\bin"
    if (-not (Test-Path -Path $OutputBinDir)) {
        New-Item -ItemType Directory -Path $OutputBinDir
    }

    foreach ($binary in $BinariesToCopy) {
        $sourcePath = ".\$Arch\$Config\$binary"
        if (Test-Path -Path $sourcePath) {
            Copy-Item -Path $sourcePath -Destination $OutputBinDir
        } else {
            Write-Host "Warning: $sourcePath does not exist."
        }
    }

    # Copy the include files to the output directory
    $IncludeDir = "$BinDir\include"
    if (-not (Test-Path -Path $IncludeDir)) {
        New-Item -ItemType Directory -Path $IncludeDir
    }

    xcopy /y "include\*" $IncludeDir
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
