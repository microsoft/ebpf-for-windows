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

Write-Host "=== configure_vm.ps1: Starting inner VM configuration ==="
Write-Host "  Hostname:  $env:COMPUTERNAME"
Write-Host "  OS:        $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
Write-Host "  Memory:    $([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)) MB"
Write-Host "  CPUs:      $((Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)"

# Enable test signing.
Write-Host "Enabling test signing..."
bcdedit -set TESTSIGNING ON
Write-Host "  Test signing: Enabled"

# Enable user-mode dumps.
Write-Host "Configuring user-mode dumps..."
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "c:\dumps" -PropertyType ExpandString -ErrorAction SilentlyContinue -Force | Out-Null
Write-Host "  User-mode dumps: Type=2 (Full), Folder=c:\dumps"

# Enable kernel dumps.
Write-Host "Configuring kernel dumps..."
$crashPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
New-Item -Path $crashPath -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $crashPath -Name 'CrashDumpEnabled' -Value 1 -Type DWord -Force
# Prevent Windows from auto-deleting the dump when disk space is low.
Set-ItemProperty -Path $crashPath -Name 'AlwaysKeepMemoryDump' -Value 1 -Type DWord -Force
# Allow NMI-triggered crash dumps for debugging VM hangs.
Set-ItemProperty -Path $crashPath -Name 'NMICrashDump' -Value 1 -Type DWord -Force
Write-Host "  Kernel dumps: Type=1 (Full), AlwaysKeep=1, NMICrashDump=1"

# Enable driver verifier on the eBPF platform drivers.
Write-Host "Enabling Driver Verifier (standard) on eBPF drivers..."
verifier /standard /bootmode persistent /driver ebpfcore.sys netebpfext.sys sample_ebpf_ext.sys
Write-Host "  Driver Verifier: ebpfcore.sys, netebpfext.sys, sample_ebpf_ext.sys"

# Disable Windows Search service to reduce resource contention during tests.
Set-Service WSearch -StartupType Disabled

# Disable background services that cause resource contention during stress tests.
# These services can randomly spike CPU/disk I/O and interfere with timing-sensitive tests.
$servicesToDisable = @(
    'wuauserv',   # Windows Update
    'SysMain',    # Superfetch / SysMain (disk I/O spikes)
    'DiagTrack',  # Connected User Experiences and Telemetry
    'BITS',       # Background Intelligent Transfer Service
    'dosvc'       # Delivery Optimization
)
foreach ($svc in $servicesToDisable) {
    try {
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Write-Host "  Disabled service: $svc"
    } catch {
        Write-Host "  Warning: Could not disable service ${svc}: $($_.Exception.Message)"
    }
}

# Configure pagefile large enough for full kernel memory dumps.
# Full dumps require pagefile >= physical_memory + 1MB (see CrashControl docs).
Write-Host "Configuring pagefile for full crash dumps..."
try {
    $physMemMB = [math]::Ceiling((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    $pagefileSizeMB = $physMemMB + 256   # physical + 256 MB headroom
    # Disable automatic pagefile management.
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.AutomaticManagedPagefile) {
        Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false }
    }
    # Remove any existing pagefile settings and create an explicit one.
    Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
    New-CimInstance -ClassName Win32_PageFileSetting -Property @{
        Name        = 'C:\pagefile.sys'
        InitialSize = $pagefileSizeMB
        MaximumSize = $pagefileSizeMB
    } | Out-Null
    Write-Host "  Pagefile: C:\pagefile.sys, Size=${pagefileSizeMB}MB (physMem=${physMemMB}MB + 256MB)"
} catch {
    Write-Host "  Warning: Failed to configure pagefile: $($_.Exception.Message)"
    Write-Host "  Full kernel dumps may fail if system-managed pagefile is too small."
}
Set-Service WSearch -StartupType Disabled

# Disable Windows Defender real-time monitoring and behavior monitoring to reduce
# CPU/memory pressure, especially for validating drivers such as the test bpf programs.
$defenderRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$rtpRegPath = "$defenderRegPath\Real-Time Protection"
New-Item -Path $defenderRegPath -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $rtpRegPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $defenderRegPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force
Write-Host "  Defender policy: Disabled via Group Policy registry keys (persists across reboot)"

Write-Host "=== configure_vm.ps1: Configuration complete, rebooting ==="

# Reboot the machine to apply the changes.
Restart-Computer -Force