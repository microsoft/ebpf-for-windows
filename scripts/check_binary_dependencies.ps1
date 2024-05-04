# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ([Parameter(Mandatory=$true)][string] $BuildArtifact,
       [Parameter(Mandatory=$true)][string] $VsToolsPath)

Push-Location $WorkingDirectory

# Define the test cases
$testCases = @{
    "Build-x64_Debug" = @{
        "bpftool.exe" = "..\..\scripts\check_binary_dependencies_bpftool_exe_regular_debug.txt"
        "ebpfapi.dll" = "..\..\scripts\check_binary_dependencies_ebpfapi_dll_regular_debug.txt"
        "ebpfnetsh.dll" = "..\..\scripts\check_binary_dependencies_ebpfnetsh_dll_regular_debug.txt"
        "ebpfsvc.exe" = "..\..\scripts\check_binary_dependencies_ebpfsvc_exe_regular_debug.txt"
    }
    "Build-x64-native-only_NativeOnlyRelease" = @{
        "bpftool.exe" = "..\..\scripts\check_binary_dependencies_bpftool_exe_nativeonly_release.txt"
        "ebpfapi.dll" = "..\..\scripts\check_binary_dependencies_ebpfapi_dll_nativeonly_release.txt"
        "ebpfnetsh.dll" = "..\..\scripts\check_binary_dependencies_ebpfnetsh_dll_nativeonly_release.txt"
    }
}

function Test-CppBinaryDependencies {
    param (
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$TextFilePath
    )

    Write-Host "Checking binary dependencies for [$BuildArtifact - $FilePath] against [$TextFilePath]..." -ForegroundColor Green

    # Run and parse the dumpbin.exe output to extract the DLL dependencies
    $DumpbinExe = Join-Path -Path $VsToolsPath -ChildPath "bin\Hostx64\x64\dumpbin.exe"
    $Output = & "$DumpbinExe" /dependents $FilePath | Out-String

    # Parse dumpbin.exe output to get the list of DLL dependencies
    $Dependencies = $Output -split "`n" | Where-Object { $_.Trim() -ilike ("*.dll") } | ForEach-Object { $_.Trim() }
    if (-not ($FilePath -match '\.exe$' -or $FilePath -match '\.EXE$')) {
        # For DLLs only, discard the first line, which always contains the dumped file itself.
        $Dependencies = $Dependencies[1..$Dependencies.Length]
    }
    Write-Host "Dependency list for '$FilePath':" -ForegroundColor Red
    Write-Host $Dependencies

    # Read the list of expected binaries from the text file
    $ExpectedBinaries = Get-Content $TextFilePath
    Write-Host "Expected dependency list:" -ForegroundColor Red
    Write-Host $ExpectedBinaries

    # Compare dependencies with the expected binaries
    $MissingBinaries = Compare-Object -ReferenceObject $ExpectedBinaries -DifferenceObject $Dependencies -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
    $ExtraBinaries = Compare-Object -ReferenceObject $ExpectedBinaries -DifferenceObject $Dependencies | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject
    if ($MissingBinaries -or $ExtraBinaries) {
        Write-Host "Mismatch found between dependencies in the file and the list:" -ForegroundColor Red
        Write-Host "Missing Dependencies:" -ForegroundColor Red
        Write-Host $MissingBinaries
        Write-Host "Extra Dependencies:" -ForegroundColor Red
        Write-Host $ExtraBinaries
        return $false
    } else {
        Write-Host "All dependencies match the expected list." -ForegroundColor Green
        return $true
    }
}

# Iterate over all the test cases
$allTestsPassed = $true
foreach ($filePath in $testCases[$BuildArtifact].Keys) {
    $res = Test-CppBinaryDependencies -FilePath $filePath -TextFilePath $testCases[$BuildArtifact][$filePath]
    $allTestsPassed = $allTestsPassed -and $res
}

Pop-Location

if (-not $allTestsPassed) {
    Write-Host "One or more tests FAILED!" -ForegroundColor Red
    exit 1
}
exit 0
