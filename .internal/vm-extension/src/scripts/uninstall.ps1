# Dot source the utility script
. .\utilities.ps1

function Uninstall-Driver {
    param (
        [string]$serviceName
    )

    Write-Log -level $LogLevelInfo -message "Uninstalling $serviceName"
    
    # Attempt to stop the driver service (which will stop dependent services as well)
    net stop $serviceName

    # Delete the driver service
    $scDeleteOutput = & "sc.exe" delete $serviceName

    # Check the exit code to determine the result
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$serviceName uninstalled successfully."
        return $LASTEXITCODE
    } else {
        Write-Log -level $LogLevelError -message "Failed to uninstall $serviceName."
        Write-Log -level $LogLevelError -message "Error message: $scDeleteOutput"
        return $LASTEXITCODE
    }
}

function Uninstall-eBPF {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Uninstalling eBPF for Windows"

    # Uninstall the eBPF services and use the results to generate the status file
    $uninstallResult1 = Uninstall-Driver -serviceName "eBPFCore"
    $uninstallResult2 = Uninstall-Driver -serviceName "NetEbpfExt"

    # Determine the overall status and status message
    if ($uninstallResult1 -eq 0 -and $uninstallResult2 -eq 0) {
        $overallStatus = $StatusSuccess
        $overallStatusCode = 0
        $statusMessage = "eBPF for Windows uninstalled successfully."
    } else {
        $overallStatus = $StatusError
        $overallStatusCode = 1
        $failedServices = @()
        
        if ($uninstallResult1 -ne 0) {
            $failedServices += "eBPFCore"
        }
        if ($uninstallResult2 -ne 0) {
            $failedServices += "NetEbpfExt"
        }

        $failedServicesString = $failedServices -join ", "
        $statusMessage = "Failed to uninstall service(s): $failedServicesString."
    }

    # Delete the eBPF files
    if (Test-Path $installDirectory) {
        try {
            Remove-Item -Path $installDirectory -Recurse -Force
            $logMessage = "Directory '$installDirectory' deleted successfully."
            Write-Log -level $LogLevelInfo -message $logMessage
        } catch {
            $errorMessage = "Failed to delete directory '$installDirectory'. Error: $_"
            Write-Log -level $LogLevelError -message $errorMessage
        }
    } else {
        $logMessage = "Directory '$installDirectory' does not exist."
        Write-Log -level $LogLevelWarning -message $logMessage
    }

    # TBD: Unregister trace providers

    # Generate the status file
    Generate-StatusFile -handlerWorkloadName "eBPFforWindows" -operationName "uninstall" -status $overallStatus -statusCode $overallStatusCode -statusMessage $statusMessage
}

# Uninstall eBPF from the default installation directory
Uninstall-eBPF [Environment]::GetFolderPath("ProgramFiles") + "\eBPF"