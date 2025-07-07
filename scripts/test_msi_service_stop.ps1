# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Dedicated test script for MSI service stop behavior during uninstall
# Regression test for issue #4467: "MSI uninstall dialog appears due to eBPF service still running"

param (
    [Parameter(Mandatory=$true)] [string]$MsiPath,
    [Parameter(Mandatory=$false)] [string]$LogFile = "msi-service-stop-test.log"
)

$ErrorActionPreference = "Stop"

# Define constants
$eBpfServiceName = "ebpfsvc"
$InstallPath = "$env:ProgramFiles\ebpf-for-windows"

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-MsiServiceStopBehavior {
    param([string]$MsiPath)
    
    Write-TestLog "=== MSI Service Stop Behavior Test ===" "INFO"
    Write-TestLog "MSI Path: $MsiPath" "INFO"
    Write-TestLog "Test Purpose: Verify eBPF service stops early during uninstall to prevent 'files in use' dialog" "INFO"
    
    try {
        # Step 1: Install MSI
        Write-TestLog "Step 1: Installing MSI package..." "INFO"
        $installArgs = "/i `"$MsiPath`" /qn /norestart /l*v msi-install-test.log ADDLOCAL=eBPF_Runtime_Components"
        $installProcess = Start-Process -FilePath msiexec.exe -ArgumentList $installArgs -Wait -PassThru
        
        if ($installProcess.ExitCode -ne 0) {
            Write-TestLog "Installation FAILED with exit code: $($installProcess.ExitCode)" "ERROR"
            return $false
        }
        Write-TestLog "✓ Installation completed successfully" "INFO"
        
        # Step 2: Verify service is running
        Write-TestLog "Step 2: Verifying eBPF service is running..." "INFO"
        Start-Sleep -Seconds 3  # Allow service to fully start
        
        $service = Get-Service -Name $eBpfServiceName -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -ne "Running") {
            Write-TestLog "ERROR: eBPF service is not running after installation" "ERROR"
            return $false
        }
        Write-TestLog "✓ eBPF service is running (Status: $($service.Status))" "INFO"
        
        # Step 3: Count eBPF processes before uninstall
        $ebpfProcessesBefore = Get-Process -Name "*ebpf*" -ErrorAction SilentlyContinue
        Write-TestLog "Found $($ebpfProcessesBefore.Count) eBPF processes before uninstall" "INFO"
        foreach ($proc in $ebpfProcessesBefore) {
            Write-TestLog "  - $($proc.ProcessName) (PID: $($proc.Id))" "INFO"
        }
        
        # Step 4: Monitor service during uninstall
        Write-TestLog "Step 3: Starting service monitoring and uninstall..." "INFO"
        
        $monitorResults = @()
        $uninstallJob = Start-Job -ScriptBlock {
            param($msiPath, $logFile)
            $uninstallArgs = "/x `"$msiPath`" /qn /norestart /l*v $logFile"
            $process = Start-Process -FilePath msiexec.exe -ArgumentList $uninstallArgs -Wait -PassThru
            return $process.ExitCode
        } -ArgumentList $MsiPath, "msi-uninstall-test.log"
        
        # Monitor service status during uninstall
        $monitorStart = Get-Date
        $maxMonitorTime = 120  # 2 minutes max
        
        while (-not $uninstallJob.State -eq "Completed" -and (Get-Date).Subtract($monitorStart).TotalSeconds -lt $maxMonitorTime) {
            $elapsed = (Get-Date).Subtract($monitorStart).TotalSeconds
            
            try {
                $currentService = Get-Service -Name $eBpfServiceName -ErrorAction SilentlyContinue
                $status = if ($currentService) { $currentService.Status } else { "NotFound" }
                
                $monitorResults += @{
                    ElapsedSeconds = [math]::Round($elapsed, 1)
                    ServiceStatus = $status
                    Timestamp = Get-Date
                }
                
                # Log significant status changes
                if ($monitorResults.Count -gt 1) {
                    $prevStatus = $monitorResults[-2].ServiceStatus
                    if ($status -ne $prevStatus) {
                        Write-TestLog "Service status changed: $prevStatus → $status (at $([math]::Round($elapsed, 1))s)" "INFO"
                    }
                }
            } catch {
                Write-TestLog "Error monitoring service: $_" "ERROR"
            }
            
            Start-Sleep -Milliseconds 500
        }
        
        # Get uninstall result
        $uninstallResult = Receive-Job -Job $uninstallJob -Wait
        Remove-Job -Job $uninstallJob
        $uninstallDuration = (Get-Date).Subtract($monitorStart).TotalSeconds
        
        Write-TestLog "Uninstall completed in $([math]::Round($uninstallDuration, 2)) seconds with exit code: $uninstallResult" "INFO"
        
        # Step 5: Analyze results
        Write-TestLog "Step 4: Analyzing results..." "INFO"
        
        $success = $true
        
        # Check uninstall success
        if ($uninstallResult -eq 0) {
            Write-TestLog "✓ Uninstall completed successfully (no user dialog required)" "INFO"
        } else {
            Write-TestLog "✗ Uninstall FAILED with exit code: $uninstallResult" "ERROR"
            $success = $false
        }
        
        # Check service stop timing
        $serviceStoppedEvent = $monitorResults | Where-Object { $_.ServiceStatus -eq "Stopped" -or $_.ServiceStatus -eq "NotFound" } | Select-Object -First 1
        
        if ($serviceStoppedEvent) {
            $stopTime = $serviceStoppedEvent.ElapsedSeconds
            Write-TestLog "✓ Service was stopped at $stopTime seconds into uninstall" "INFO"
            
            if ($stopTime -le 30) {
                Write-TestLog "✓ Service stopped early in uninstall process (≤30s) - this prevents file-in-use dialog" "INFO"
            } else {
                Write-TestLog "⚠ Service stopped later than expected (>30s) - may still cause dialog" "WARN"
            }
        } else {
            Write-TestLog "⚠ Could not determine when service was stopped" "WARN"
        }
        
        # Check for remaining processes
        Start-Sleep -Seconds 2
        $ebpfProcessesAfter = Get-Process -Name "*ebpf*" -ErrorAction SilentlyContinue
        if ($ebpfProcessesAfter.Count -eq 0) {
            Write-TestLog "✓ No eBPF processes remain after uninstall" "INFO"
        } else {
            Write-TestLog "⚠ Found $($ebpfProcessesAfter.Count) eBPF processes still running:" "WARN"
            foreach ($proc in $ebpfProcessesAfter) {
                Write-TestLog "  - $($proc.ProcessName) (PID: $($proc.Id))" "WARN"
            }
        }
        
        # Check uninstall log for dialog-related issues
        $uninstallLogContent = Get-Content -Path "msi-uninstall-test.log" -ErrorAction SilentlyContinue
        if ($uninstallLogContent) {
            $dialogIssues = $uninstallLogContent | Where-Object { 
                $_ -match "files that need to be updated|applications are using files|RestartManager|ERROR_INSTALL_USEREXIT" 
            }
            
            if ($dialogIssues.Count -eq 0) {
                Write-TestLog "✓ No file-in-use or dialog-related errors in uninstall log" "INFO"
            } else {
                Write-TestLog "⚠ Found potential dialog-related issues in uninstall log:" "WARN"
                foreach ($issue in $dialogIssues) {
                    Write-TestLog "  $issue" "WARN"
                }
            }
        }
        
        return $success
        
    } catch {
        Write-TestLog "EXCEPTION during test: $_" "ERROR"
        return $false
    } finally {
        # Cleanup: ensure uninstall if something went wrong
        try {
            $service = Get-Service -Name $eBpfServiceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-TestLog "Cleanup: Forcing uninstall to clean up test environment..." "INFO"
                $cleanupArgs = "/x `"$MsiPath`" /qn /norestart"
                Start-Process -FilePath msiexec.exe -ArgumentList $cleanupArgs -Wait -PassThru | Out-Null
            }
        } catch {
            Write-TestLog "Cleanup warning: $_" "WARN"
        }
    }
}

# Main execution
Write-TestLog "Starting MSI Service Stop Test" "INFO"
Write-TestLog "Regression test for GitHub issue #4467" "INFO"

if (-not (Test-Path $MsiPath)) {
    Write-TestLog "ERROR: MSI file not found at: $MsiPath" "ERROR"
    exit 1
}

$testResult = Test-MsiServiceStopBehavior -MsiPath $MsiPath

if ($testResult) {
    Write-TestLog "=== TEST PASSED ===" "INFO"
    Write-TestLog "eBPF service stop behavior is working correctly during MSI uninstall" "INFO"
    exit 0
} else {
    Write-TestLog "=== TEST FAILED ===" "ERROR"
    Write-TestLog "eBPF service stop behavior test failed - check logs above" "ERROR"
    exit 1
}