# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Wrapper script to pass the correct parameters to the Convert-BpfToNative.ps1 script.

param(
    [parameter(Mandatory = $true)]
    [ValidateScript({
        if(-Not (Test-Path $_) ) {
            throw "File does not exist"
        }
        if(-Not ($_ -match "\.o$")) {
            throw "File must be an object file (.o extension)"
        }
        return $true
    })]
    [string] $FileName
)

$convertScript = "C:\packages\eBPF-for-Windows.x64\build\native\bin\Convert-BpfToNative.ps1"
if (-Not (Test-Path $convertScript)) {
    throw "Convert-BpfToNative.ps1 not found at expected location"
}
try {
    & $convertScript -Packages c:\packages -FileName $FileName
    if ($LASTEXITCODE -ne 0) {
        throw "Convert-BpfToNative.ps1 failed with exit code $LASTEXITCODE"
    }
} catch {
    Write-Error "Failed to convert BPF file: $_"
    exit 1
}
exit 0