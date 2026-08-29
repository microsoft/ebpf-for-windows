# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Verifies that the `tools\driver-test` build target produces everything the driver
validation tests need at run time.

.DESCRIPTION
The internal release validation pipeline builds only the `tools\driver-test` target
instead of the full solution. Anything the driver test scripts launch at run time but
that is missing from that target's project closure is not detected at build time -- it
surfaces ~45 minutes later as an opaque test failure such as:

    This command cannot be run due to the error: The system cannot find the file specified.

This script closes that gap. It runs in two modes:

  Static  (default) Walks the transitive project closure of driver-test.vcxproj --
                    following both vcxproj <ProjectReference> items and the solution's
                    ProjectDependencies sections -- and asserts the project that
                    produces each required file is part of it. Requires no build, so it
                    is cheap enough for a lint-style CI job.

  Runtime (-BuildPath) Asserts each required file is physically present in a build
                    output directory. Runs as a post-build step of driver-test.vcxproj.

The required-file list is derived from:
  scripts\run_driver_tests.psm1     (Invoke-CICDTests, Invoke-ConnectRedirectTest,
                                     Invoke-CICDStressTests)
  scripts\vm_run_tests.psm1         (Invoke-ConnectRedirectTestHelper, Run-KernelTests)
  scripts\install_ebpf.psm1         (Install-eBPFComponents)
  scripts\execute_ebpf_cicd_tests.ps1 / setup_ebpf_cicd_tests.ps1

.PARAMETER BuildPath
Build output directory to verify (for example `x64\NativeOnlyRelease`). When omitted,
the static project-closure check runs instead.

.PARAMETER RepoRoot
Repository root. Defaults to the parent of the directory holding this script.

.EXAMPLE
.\scripts\check_driver_test_closure.ps1

.EXAMPLE
.\scripts\check_driver_test_closure.ps1 -BuildPath .\x64\NativeOnlyRelease
#>

param(
    [Parameter(Mandatory = $false)][string] $BuildPath,
    [Parameter(Mandatory = $false)][string] $RepoRoot
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

# Files the driver validation tests require at run time, mapped to the project that
# produces them. Paths are relative to the repository root and are compared against the
# transitive project closure of tools\driver-test\driver-test.vcxproj.
$RequiredFiles = [ordered]@{
    # Test executables invoked directly by the driver test harness.
    # run_driver_tests.psm1: Invoke-CICDTests / Invoke-CICDStressTests
    "api_test.exe"                     = "tests\api_test\api_test.vcxproj"
    # run_driver_tests.psm1: Invoke-CICDTests
    "bpftool_tests.exe"                = "tests\bpftool_tests\bpftool_tests.vcxproj"
    # run_driver_tests.psm1: Invoke-ConnectRedirectTest
    "connect_redirect_tests.exe"       = "tests\connect_redirect\connect_redirect_tests.vcxproj"
    # run_driver_tests.psm1: Invoke-CICDTests (Release configurations only)
    "ebpf_performance.exe"             = "tests\performance\performance.vcxproj"
    # run_driver_tests.psm1: Invoke-CICDStressTests (RestartExtension / RestartEbpfCore)
    "ebpf_restart_test_controller.exe" = "tests\stress\restart_test_controller\ebpf_restart_test_controller.vcxproj"
    # Launched by ebpf_restart_test_controller.exe
    "ebpf_restart_test_helper.exe"     = "tests\stress\restart_test_helper\ebpf_restart_test_helper.vcxproj"
    # run_driver_tests.psm1: Invoke-CICDStressTests
    "ebpf_stress_tests_km.exe"         = "tests\stress\km\ebpf_stress_tests_km.vcxproj"
    # install_ebpf.psm1: Install-eBPFComponents
    "export_program_info_sample.exe"   = "undocked\tools\export_program_info_sample\export_program_info_sample.vcxproj"
    # run_driver_tests.psm1: Invoke-CICDTests
    "sample_ext_app.exe"               = "tests\sample\ext\app\sample_ext_app.vcxproj"
    # run_driver_tests.psm1: Invoke-CICDTests
    "socket_tests.exe"                 = "tests\socket\socket_tests.vcxproj"
    # vm_run_tests.psm1: Invoke-ConnectRedirectTestHelper
    "tcp_udp_listener.exe"             = "tests\tcp_udp_listener\tcp_udp_listener.vcxproj"

    # Kernel-mode components installed by the test setup.
    # install_ebpf.psm1: Install-eBPFComponents (SampleEbpfExt).
    "sample_ebpf_ext.sys"              = "undocked\tests\sample\ext\drv\sample_ext.vcxproj"

    # Packages installed on the test machine.
    # install_ebpf.psm1: installs the eBPF runtime from the MSI
    "ebpf-for-windows.msi"             = "installer\ebpf-for-windows.wixproj"

    # Harness scripts and data files, copied to the output directory by setup_build.
    "cleanup_ebpf_cicd_tests.ps1"      = "scripts\setup_build\setup_build.vcxproj"
    "common.psm1"                      = "scripts\setup_build\setup_build.vcxproj"
    "ebpfforwindows.wprp"              = "scripts\setup_build\setup_build.vcxproj"
    "execute_ebpf_cicd_tests.ps1"      = "scripts\setup_build\setup_build.vcxproj"
    "install_ebpf.psm1"                = "scripts\setup_build\setup_build.vcxproj"
    "run_driver_tests.psm1"            = "scripts\setup_build\setup_build.vcxproj"
    "setup_ebpf_cicd_tests.ps1"        = "scripts\setup_build\setup_build.vcxproj"
    "test_execution.json"              = "scripts\setup_build\setup_build.vcxproj"
    "tracing_utils.psm1"               = "scripts\setup_build\setup_build.vcxproj"
    "vm_run_tests.psm1"                = "scripts\setup_build\setup_build.vcxproj"
}

$SolutionFile = Join-Path $RepoRoot "ebpf-for-windows.sln"
$RootProject = "tools\driver-test\driver-test.vcxproj"

function Write-Remediation {
    Write-Host ""
    Write-Host "Add the project that produces each missing file to $RootProject (and to the" -ForegroundColor Yellow
    Write-Host "driver-test ProjectDependencies section of ebpf-for-windows.sln), or update the" -ForegroundColor Yellow
    Write-Host "required-file list in scripts\check_driver_test_closure.ps1 if it is no longer needed." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Runtime mode: verify a build output directory.
# ---------------------------------------------------------------------------
if ($BuildPath) {
    if (-not (Test-Path -Path $BuildPath)) {
        throw "Build output path '$BuildPath' does not exist."
    }

    $Missing = @($RequiredFiles.Keys | Where-Object { -not (Test-Path -Path (Join-Path $BuildPath $_)) })

    if ($Missing.Count -gt 0) {
        Write-Host "Driver test closure check FAILED for '$BuildPath'." -ForegroundColor Red
        Write-Host "The following files are required by the driver validation tests but were not built:" -ForegroundColor Red
        $Missing | ForEach-Object { Write-Host "  - $_ (from $($RequiredFiles[$_]))" -ForegroundColor Red }
        Write-Remediation
        exit 1
    }

    Write-Host "Driver test closure check passed: all $($RequiredFiles.Count) required files are present in '$BuildPath'."
    exit 0
}

# ---------------------------------------------------------------------------
# Static mode: verify the project closure of the driver-test target.
# ---------------------------------------------------------------------------
if (-not (Test-Path -Path $SolutionFile)) {
    throw "Solution file '$SolutionFile' not found. Pass -RepoRoot to point at the repository root."
}

$NormalizedRepoRoot = ([System.IO.Path]::GetFullPath($RepoRoot)).TrimEnd('\') + '\'
$SolutionText = Get-Content -Path $SolutionFile -Raw

# GUID -> project path, and project path -> solution-declared dependency GUIDs.
$GuidToPath = @{}
$PathToDependencyGuids = @{}

$ProjectPattern = '(?ms)^Project\("\{[0-9A-Fa-f\-]+\}"\)\s*=\s*"[^"]*",\s*"([^"]+)",\s*"\{([0-9A-Fa-f\-]+)\}"(.*?)^EndProject'
foreach ($match in [regex]::Matches($SolutionText, $ProjectPattern)) {
    $projectPath = $match.Groups[1].Value
    $projectGuid = $match.Groups[2].Value.ToUpperInvariant()

    # Skip solution folders, which have no project file on disk.
    if (-not (Test-Path -Path (Join-Path $RepoRoot $projectPath))) {
        continue
    }

    $GuidToPath[$projectGuid] = $projectPath

    $dependencyGuids = @()
    $sectionMatch = [regex]::Match($match.Groups[3].Value, '(?ms)ProjectSection\(ProjectDependencies\)\s*=\s*postProject(.*?)EndProjectSection')
    if ($sectionMatch.Success) {
        foreach ($dependency in [regex]::Matches($sectionMatch.Groups[1].Value, '\{([0-9A-Fa-f\-]+)\}\s*=')) {
            $dependencyGuids += $dependency.Groups[1].Value.ToUpperInvariant()
        }
    }
    $PathToDependencyGuids[$projectPath] = $dependencyGuids
}

function Get-ProjectReference {
    param([string] $ProjectPath)

    $fullPath = Join-Path $RepoRoot $ProjectPath
    if (-not (Test-Path -Path $fullPath)) {
        return @()
    }

    $projectDirectory = Split-Path -Parent $fullPath
    $references = @()
    foreach ($reference in [regex]::Matches((Get-Content -Path $fullPath -Raw), '<ProjectReference\s+Include="([^"]+)"')) {
        $include = $reference.Groups[1].Value
        # Skip references that use MSBuild properties; they cannot be resolved statically.
        if ($include.Contains('$(')) {
            continue
        }
        try {
            if ([System.IO.Path]::IsPathRooted($include)) {
                $resolved = [System.IO.Path]::GetFullPath($include)
            } else {
                $resolved = [System.IO.Path]::GetFullPath((Join-Path $projectDirectory $include))
            }
        } catch {
            continue
        }
        if ($resolved.StartsWith($NormalizedRepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            # Normalize to a repo-relative path so it can be compared with solution entries.
            $references += $resolved.Substring($NormalizedRepoRoot.Length)
        }
    }
    return $references
}

# Breadth-first walk over vcxproj ProjectReferences + solution ProjectDependencies.
$Closure = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$Queue = New-Object 'System.Collections.Generic.Queue[string]'
$Queue.Enqueue($RootProject)

while ($Queue.Count -gt 0) {
    $current = $Queue.Dequeue()
    if (-not $Closure.Add($current)) {
        continue
    }

    $neighbors = @(Get-ProjectReference -ProjectPath $current)
    if ($PathToDependencyGuids.ContainsKey($current)) {
        foreach ($guid in $PathToDependencyGuids[$current]) {
            if ($GuidToPath.ContainsKey($guid)) {
                $neighbors += $GuidToPath[$guid]
            }
        }
    }

    foreach ($neighbor in $neighbors) {
        if (-not $Closure.Contains($neighbor)) {
            $Queue.Enqueue($neighbor)
        }
    }
}

$Missing = @()
foreach ($file in $RequiredFiles.Keys) {
    $producer = $RequiredFiles[$file]
    if (-not (Test-Path -Path (Join-Path $RepoRoot $producer))) {
        $Missing += "$file -> $producer (project file not found)"
    } elseif (-not $Closure.Contains($producer)) {
        $Missing += "$file -> $producer"
    }
}

if ($Missing.Count -gt 0) {
    Write-Host "Driver test closure check FAILED." -ForegroundColor Red
    Write-Host "The following files are required by the driver validation tests, but the project that" -ForegroundColor Red
    Write-Host "produces them is not in the build closure of ${RootProject}:" -ForegroundColor Red
    $Missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Remediation
    exit 1
}

Write-Host "Driver test closure check passed: all $($RequiredFiles.Count) required files are produced by the $($Closure.Count) projects in the $RootProject closure."
exit 0
