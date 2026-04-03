# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    This script executes on a VM to configure it for eBPF testing.

.DESCRIPTION
    This script configures a VM for eBPF testing by enabling test signing, user-mode dumps, kernel dumps,
    and driver verifier on the eBPF platform drivers. It also enables IPv4 and IPv6 on all network adapters.
#>

########## Main Execution ##########

# Enable test signing.
bcdedit -set TESTSIGNING ON

# Enable user-mode dumps.
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "c:\dumps" -PropertyType ExpandString -ErrorAction SilentlyContinue -Force

# Enable kernel dumps.
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue

# Enable driver verifier on the eBPF platform drivers.
verifier /standard /bootmode persistent /driver ebpfcore.sys netebpfext.sys sample_ebpf_ext.sys

# Reboot the machine to apply the changes.
Restart-Computer -Force