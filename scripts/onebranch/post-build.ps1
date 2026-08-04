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
    "export_program_info.exe",
    "export_program_info.pdb",
    "export_program_info_sample.exe",
    "export_program_info_sample.pdb",
    "export_program_info_test.exe",
    "export_program_info_test.pdb",
    "socket_tests.exe",
    "socket_tests.pdb",
    "connect_redirect_tests.exe",
    "connect_redirect_tests.pdb",
    "tcp_udp_listener.exe",
    "tcp_udp_listener.pdb",
    # VC debug runtime DLLs (present only for NativeOnlyDebug builds; copied
    # by tools\onebranch\onebranch.vcxproj PostBuildEvent for that config).
    # install_ebpf.psm1 copies these into System32 on the test VM so that
    # debug-built binaries (e.g. export_program_info.exe, which runs as an
    # MSI custom action) can load. Missing files are warned-and-skipped
    # below, so listing them is safe for Release configs.
    "concrt140d.dll",
    "msvcp140d.dll",
    "msvcp140d_atomic_wait.dll",
    "msvcp140d_codecvt_ids.dll",
    "msvcp140_1d.dll",
    "msvcp140_2d.dll",
    "vccorlib140d.dll",
    "vcruntime140d.dll",
    "vcruntime140_1d.dll",
    "ucrtbased.dll"
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

    # Copy all eBPF program .o and .sys files (built by sample.vcxproj via bpf2c pipeline).
    foreach ($pattern in @("*.o", "*.sys")) {
        $files = Get-ChildItem -Path ".\$Arch\$Config\$pattern" -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            if (-not (Test-Path -Path (Join-Path $OutputBinDir $file.Name))) {
                Copy-Item -Path $file.FullName -Destination $OutputBinDir
            }
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

# Resolve the Visual Studio installation via vswhere rather than hardcoding a version-specific path.
# The OneBranch build container ships whichever Visual Studio the image was built with (VS 2022 lives
# under "...\2022\Enterprise", VS 2026 under "...\18\Enterprise"), so a literal path breaks whenever
# the image is updated. This also puts msbuild on PATH for the packaging steps below.
$vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswherePath)) {
    throw "vswhere.exe not found at '$vswherePath'; unable to locate a Visual Studio installation."
}
$vsInstallPath = & $vswherePath -latest -products * -property installationPath | Select-Object -First 1
if (-not $vsInstallPath) {
    throw "Could not locate a Visual Studio installation via vswhere."
}
Write-Host "Using Visual Studio installation at '$vsInstallPath'."
Import-Module (Join-Path $vsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
Enter-VsDevShell -VsInstallPath $vsInstallPath -DevCmdArguments "-arch=$OneBranchArch -host_arch=x64"
Set-Location $scriptPath\..\..
$SolutionDir = Get-Location

# Report packaging errors. These msbuild invocations are deliberately NOT fatal: the
# nuget.vcxproj repack has been failing with MSB8013 for a long time (usersim.vcxproj, an external
# submodule, does not declare the NativeOnly* configurations; the .sln supplies a configuration
# mapping that a direct project build cannot), and the error has always been ignored here. Failing
# the build on it would break pipelines that pass today, so surface it loudly instead and leave the
# existing behavior intact.
function Invoke-PackagingBuild {
    param (
        [string]$Project,
        [string[]]$ExtraArgs = @()
    )
    msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false @ExtraArgs $Project
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "msbuild exited with code $LASTEXITCODE for $Project. Continuing (see MSB8013 note above)."
        $global:LASTEXITCODE = 0
    }
}

Invoke-PackagingBuild -Project ".\tools\nuget\nuget.vcxproj" -ExtraArgs @("/p:ForceRepack=true")
Invoke-PackagingBuild -Project ".\tools\redist-package\redist-package.vcxproj" -ExtraArgs @("/p:ForceRepack=true")
Invoke-PackagingBuild -Project ".\installer\ebpf-for-windows.wixproj"

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
