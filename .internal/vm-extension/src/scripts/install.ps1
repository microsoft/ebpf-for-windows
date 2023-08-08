# Dot source the utility script
. .\utilities.ps1

function Install-Driver {
    param (
        [string]$serviceName,
        [string]$servicePath
    )

    Write-Log "Installing service $serviceName"

    # Combine the destination path and filename for copying
    $BinaryPath = Join-Path -Path $servicePath -ChildPath $serviceName
    
    # Create the service using sc.exe (you'll need to replace this with the actual command)
    $scCreateOutput = & "sc.exe" create $serviceName type=kernel start=demand binPath="$BinaryPath.sys"

    # Check the exit code to determine the result
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$serviceName installed successfully."
        return $LASTEXITCODE
    } else {
        Write-Log -level $LogLevelError -message "Failed to install $serviceName."
        Write-Log -level $LogLevelError -message "Error message: $scCreateOutput"
        return $LASTEXITCODE
    }
}

function Install-eBPF {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "Installing eBPF for Windows"

    # Create the destination directory if it doesn't exist
    if (-not (Test-Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory
    }

    # Recursively copy all files from source to destination
    $copyResult = $null
    try {
        $copyResult = Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Log -level $LogLevelError -message "Error while copying files: $_"      
        exit 1
    }
    Write-Log -level $LogLevelError -message "Files copied from '$sourcePath' to '$destinationPath'."

    # Install the eBPF services and use the results to generate the status file
    $installResult1 = Install-Driver -serviceName "eBPFCore"
    $installResult2 = Install-Driver -serviceName "NetEbpfExt"

    # Determine the overall status and status message
    if ($installResult1 -eq 0 -and $installResult2 -eq 0) {
        $overallStatus = $StatusSuccess
        $overallStatusCode = 0
        $statusMessage = "eBPF for Windows installed successfully."
    } else {
        $overallStatus = $StatusError
        $overallStatusCode = 1
        $failedServices = @()
        
        if ($installResult1 -ne 0) {
            $failedServices += "eBPFCore"
        }
        if ($installResult2 -ne 0) {
            $failedServices += "NetEbpfExt"
        }

        $failedServicesString = $failedServices -join ", "
        $statusMessage = "Failed to install service(s): $failedServicesString."
    }

    # TBD: Register trace providers

    # TBD: confirm if Install does not need to generate a status file
    Generate-StatusFile -handlerWorkloadName "eBPFforWindows" -operationName "install" -status $overallStatus -statusCode $overallStatusCode -statusMessage $statusMessage
}


# Install eBPF from the artifact package within the extension ZIP file
Install-eBPF ".\package", [Environment]::GetFolderPath("ProgramFiles") + "\eBPF"