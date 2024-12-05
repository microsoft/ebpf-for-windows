# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Wrapper script to pass the correct parameters to the Convert-BpfToNative.ps1 script.

param([parameter(Mandatory = $true)] [string] $FileName)

C:\packages\eBPF-for-Windows.x64\build\native\bin\Convert-BpfToNative.ps1 -Packages c:\packages -FileName $FileName