# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile)

$lines = Get-Content $InputFile

$lines = $lines | % { if ($_) { $_ = $_.Replace('\', '\\').Replace('"', '\"'); Write-output ('"' + $_ + '\n"') } else { Write-output ('"\n"') } }

$lines | Out-File $OutputFile
