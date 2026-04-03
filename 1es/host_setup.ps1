# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Configures the 1ES host runner for reliable Hyper-V nested virtualization.

.DESCRIPTION
    This script runs once during 1ES image baking (before Setup.ps1) and applies
    host-level configuration that requires a reboot to take effect.  It must be
    invoked as a separate customization step followed by a reboot step.

    Changes made:
      - Disables Windows Defender via Group Policy registry keys (survives
        Tamper Protection and persists across reboots).
      - Disables background services that cause I/O and CPU spikes.

.EXAMPLE
    .\host_setup.ps1
    # Then reboot the host before running Setup.ps1.
#>

$ErrorActionPreference = "Stop"

Write-Host "=== host_setup.ps1: Configuring 1ES host ==="

# ── Disable Defender via Group Policy registry keys ─────────────────
# Set-MpPreference works without reboot but can be overridden by Tamper
# Protection on newer Windows builds.  GP registry keys are authoritative
# and take effect after reboot (before the runner agent starts).
Write-Host "Disabling Defender via Group Policy registry keys..."
$defenderRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$rtpRegPath = "$defenderRegPath\Real-Time Protection"
New-Item -Path $defenderRegPath -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $rtpRegPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $defenderRegPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $rtpRegPath -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force
Write-Host "  Defender GP keys set (will take effect after reboot)."

# ── Disable background services ────────────────────────────────────
# These services cause random CPU/disk spikes on the host, which can
# starve the inner VM's vmwp.exe and wsmprovhost.exe processes.
$servicesToDisable = @(
    'WSearch',    # Windows Search (indexer)
    'SysMain',    # Superfetch (disk I/O spikes)
    'DiagTrack',  # Connected User Experiences and Telemetry
    'BITS',       # Background Intelligent Transfer Service
    'dosvc',      # Delivery Optimization
    'wuauserv'    # Windows Update
)
foreach ($svc in $servicesToDisable) {
    try {
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Write-Host "  Disabled service: $svc"
    } catch {
        Write-Host "  Warning: Could not disable ${svc}: $($_.Exception.Message)"
    }
}

Write-Host "=== host_setup.ps1: Complete (reboot required) ==="
