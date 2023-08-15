#######################################################
# Global Variables
#######################################################
# Define eBPF Handler Environment variables
Set-Variable -Name "runTests" -Value $true -Option Constant
Set-Variable -Name "EbpfPackagePath" -Value ".\package" -Option Constant
Set-Variable -Name "EbpfDefaultInstallPath" -Value [Environment]::GetFolderPath("ProgramFiles") + "\ebpf-for-windows" -Option Constant
Set-Variable -Name "EbpfCoreDriverName" -Value "eBPFCore" -Option Constant
Set-Variable -Name "NetEbpfExtDriverName" -Value "NetEbpfExt" -Option Constant
Set-Variable -Name "NetshExtensionName" -Value "ebpfnetsh.dll" -Option Constant
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
}

# Define the VM extension's Status file constants
Set-Variable -Name "HandlerWorkloadName" -Value "eBPFforWindows" -Option Constant
Set-Variable -Name "OperationNameEnable" -Value "enable" -Option Constant
Set-Variable -Name "OperationNameDisable" -Value "disable" -Option Constant
Set-Variable -Name "OperationNameInstall" -Value "install" -Option Constant
Set-Variable -Name "OperationNameUninstall" -Value "uninstall" -Option Constant
Set-Variable -Name "OperationNameUpdate" -Value "update" -Option Constant
Set-Variable -Name "StatusTransitioning" -Value "transitioning" -Option Constant
Set-Variable -Name "StatusError" -Value "error" -Option Constant
Set-Variable -Name "StatusSuccess" -Value "success" -Option Constant
Set-Variable -Name "StatusWarning" -Value "warning" -Option Constant


#######################################################
# Logging Functions
#######################################################

# Define constants for log levels
$LogLevelInfo = "INFO"
$LogLevelWarning = "WARNING"
$LogLevelError = "ERROR"
function Write-Log {
    param (
        [string]$level,
        [string]$message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp]-[$level] - $message"

    # Append the log entry to the log file, and also write it to the console
    $logEntry | Out-File -Append -FilePath $($handlerEnvironmentObject.handlerEnvironment.logFolder) + "ebpf.log"
    Write-Host $logEntry
}

#######################################################
# Utility Functions
#######################################################


function Get-HandlerEnvironment {
    param (
        # The HandlerEnvironment.json file is always located in the root of where the ZIP package is extracted
        [string]$handlerEnvironmentFullPath = ".\HandlerEnvironment.json"
    )
   
    if (Test-Path $filePhandlerEnvironmentFullPathath) {
        $jsonContent = Get-Content -Path $handlerEnvironmentFullPath -Raw | ConvertFrom-Json
        return $jsonContent
    } else {
        Write-Log -level $LogLevelError -message "HandlerEnvironment.json file not found."
        return $null
    }
}

function Create-StatusFile {
    param (
        [string]$handlerWorkloadName,
        [string]$operationName,
        [string]$status,
        [int]$statusCode,
        [string]$statusMessage
    )

    # Get the SequenceNumber from the name of the latest created .settings file
    $lastSequenceNumber = Get-ChildItem -Path "$($env:eBPFHandlerEnv.handlerEnvironment.configFolder)" -Filter "*.settings" | Sort-Object CreationTime -Descending | Select-Object -First 1
    if ($null -eq $lastSequenceNumber) {
        Write-Log -level $LogLevelError -message "No '.settings' file found."
        return
    }

    # Construct the status JSON object
    $statusObject = @{
        version = "1.0"
        timestampUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = @{
            name = $handlerWorkloadName
            operation = $operationName
            configurationAppliedTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            status = $status
            code = $statusCode
            message = @{
                id = "localized_resource_id"
                params = @("MyParam0", "MyParam1")
            }
            formattedMessage = @{
                lang = "en-US"
                message = $statusMessage
            }
        }
    }
    
    # Convert the status object to JSON
    $statusJson = ConvertTo-Json $statusObject -Depth 5

    # Write the JSON to the .status file with the name of the latest .settings file
    $statusFileName = [System.IO.Path]::ChangeExtension($lastSequenceNumber.Name, ".status")
    $statusFilePath = Join-Path "$($env:eBPFHandlerEnv.handlerEnvironment.statusFolder)" $statusFileName
    $statusJson | Set-Content -Path $statusFilePath

    Write-Log -level $LogLevelInfo -message "Status file generated: $statusFilePath"
}

function Get-FullDiskPathFromService {
    param (
        [string]$serviceName
    )

    $queryOutput = sc qc $serviceName

    # Search for the BINARY_PATH_NAME line using regex
    $binaryPathLine = $queryOutput -split "`n" | Where-Object { $_ -match "BINARY_PATH_NAME\s+:\s+(.*)" }

    if ($binaryPathLine) {
        $binaryPath = $matches[1]

        # Extract the full disk path using regex
        $fullDiskPath = [regex]::Match($binaryPath, '(?<=\\)\w:.+')

        if ($fullDiskPath.Success) {
            return $fullDiskPath.Value
        } else {
            return $null
        }
    } else {
        return $null
    }
}

function Get-ProductVersionFromFile {
    param (
        [string]$filePath
    )

    if (Test-Path -Path $filePath -PathType Leaf) {
        $fileVersionInfo = Get-ItemProperty -Path $filePath -Name VersionInfo
        $productVersion = $fileVersionInfo.VersionInfo.ProductVersion

        if ($productVersion) {
            return $productVersion
        } else {
            return $null
        }
    } else {
        return $null
    }
}

function Compare-VersionNumbers {
    param (
        [string]$version1,
        [string]$version2
    )

    $version1Digits = $version1 -split '\.'
    $version2Digits = $version2 -split '\.'

    $maxDigits = [Math]::Max($version1Digits.Length, $version2Digits.Length)

    for ($i = 0; $i -lt $maxDigits; $i++) {
        $digit1 = if ($i -lt $version1Digits.Length) { [int]$version1Digits[$i] } else { 0 }
        $digit2 = if ($i -lt $version2Digits.Length) { [int]$version2Digits[$i] } else { 0 }

        if ($digit1 -lt $digit2) {
            return -1
        } elseif ($digit1 -gt $digit2) {
            return 1
        }
    }

    return 0
}

function Add-DirectoryToSystemPath {
    param (
        [string]$directoryPath
    )

    $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)

    if ($currentPath -split ";" -contains $directoryPath) {
        Write-Log -level $LogLevelInfo -message "The directory is already in the system PATH."
    } else {
        $newPath = "$currentPath;$directoryPath"
        [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Log -level $LogLevelInfo -message "Directory added to the system PATH."
    }
}

function Remove-DirectoryFromSystemPath {
    param (
        [string]$directoryPath
    )

    $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)

    if ($currentPath -split ";" -contains $directoryPath) {
        $newPath = ($currentPath -split ";" | Where-Object { $_ -ne $directoryPath }) -join ";"
        [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Log -level $LogLevelInfo -message "Directory removed from the system PATH."
    } else {
        Write-Log -level $LogLevelInfo -message "The directory is not found in the system PATH."
    }
}

function Register-NetshExtension{

    # Add the eBPF netsh helper.
    Push-Location -Path $EbpfDefaultInstallPath
    $installResult = & "netsh.exe" add helper $NetshExtensionName

    # Check the exit code to determine the result
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$serviceName registered successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to register $NetshExtensionName. Error message: $installResult"
    }

    Pop-Location
    return $LASTEXITCODE
}

function Unregister-NetshExtension{

    # Add the eBPF netsh helper.
    Push-Location -Path $EbpfDefaultInstallPath
    $installResult = & "netsh.exe" delete helper $NetshExtensionName

    # Check the exit code to determine the result
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$serviceName unregistered successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to unregister $NetshExtensionName. Error message: $installResult"
    }

    Pop-Location
    return $LASTEXITCODE
}

function CheckDriverInstalled {
    param (
        [string]$driverName
    )
    
    $colServices = Get-WmiObject -Query "Select * from Win32_BaseService where Name='$driverName'"
    
    if ($colServices.Count -gt 0) {
        return $true
    } else {
        return $false
    }
}

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
    } else {
        Write-Log -level $LogLevelError -message "Failed to install $serviceName. Error message: $scCreateOutput"
    }

    return $LASTEXITCODE
}

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
    } else {
        Write-Log -level $LogLevelError -message "Failed to uninstall $serviceName. Error message: $scDeleteOutput"      
    }
    return $LASTEXITCODE
}

function Stop-eBPFDrivers {
    $EbpfDrivers | ForEach-Object {
        $driverName = $_.Name
        Stop-Service -Name $driverName -ErrorAction SilentlyContinue
        if ($?) {
            Write-Log -level $LogLevelInfo -message "Stopped driver: $driverName"
        } else {
            Write-Log -level $LogLevelError -message "Failed to stop driver: $driverName"
        }
    }
}

function Copy-EbpFiles {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    # Create the destination directory, if it doesn't exist.
    if (-not (Test-Path $destinationPath)) {
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop
        } catch {
            Write-Log -Level $LogLevelError -Message "Failed to create destination directory '$destinationPath': $_"
            return $false
        }
    }

    # Recursively copy all files from source to destination.
    try {
        Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse -Force -ErrorAction Stop
        Write-Log -Level $LogLevelInfo -Message "Files copied from '$sourcePath' to '$destinationPath'."
        return $true
    } catch {
        Write-Log -Level $LogLevelError -Message "Error while copying files: $_"
        return $false
    }
}

function Delete-EbpfFiles {
    param (
        [string]$destinationPath
    )

    if (Test-Path $destinationPath) {
        try {
            Remove-Item -Path $destinationPath -Recurse -Force -ErrorAction Stop
            Write-Log -Level $LogLevelInfo -Message "Directory '$destinationPath' deleted successfully."
            return $true
        } catch {
            Write-Log -Level $LogLevelError -Message "Failed to delete directory '$destinationPath'. Error: $_"
            return $false
        }
    } else {
        Write-Log -Level $LogLevelWarning -Message "Directory '$destinationPath' does not exist."
        return $false
    }
}

function Enable-Tracing {

    # TBD: Register trace providers
}

function Disable-Tracing {
    
    # TBD: Unregister trace providers 
}


#######################################################
# VM Extension Handler Functions
#######################################################

function Reset-eBPF {
    # NOP for this current implementation
    # TBD: confirm if Reset does not need to generate a status file
}

function Enable-eBPF {
    # This is where any checks for prerequisites should be performed

    # Generate the status file
    Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameEnable -status $StatusSuccess -statusCode 0 -statusMessage "eBPF enabled"
}

function Disable-eBPF {
    Stop-eBPFDrivers
    # TBD: confirm if Disable does not need to generate a status file
    Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameDisable -status $StatusSuccess -statusCode 0 -statusMessage "eBPF disabled"
}

function Install-eBPF {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "Installing eBPF for Windows"
    $statusCode = 0

    # Copy the eBPF files to the destination folder
    $copyResult = Copy-EbpFiles -sourcePath $sourcePath -destinationPath $destinationPath
    if ($copyResult) {
        # Install the eBPF services and use the results to generate the status file
        $installResult1 = Install-Driver -serviceName $EbpfCoreDriverName
        $installResult2 = Install-Driver -serviceName $NetEbpfExtDriverName

        # Determine the overall status and status message
        if ($installResult1 -eq 0 -and $installResult2 -eq 0) {
            
            # Add the eBPF installation directory to the system PATH
            Add-DirectoryToSystemPath -directoryPath $installDirectory
            
            # Register the trace providers
            Enable-Tracing

            Write-Log -level $LogLogLevelInfoLevelError -message "eBPF for Windows installed successfully."
        } else {
            $statusCode = 1
            $failedServices = @()            
            if ($installResult1 -ne 0) {
                $failedServices += $EbpfCoreDriverName
            }
            if ($installResult2 -ne 0) {
                $failedServices += $NetEbpfExtDriverName
            }
            $failedServicesString = $failedServices -join ", "
            Write-Log -level $LogLevelError -message "Failed to install service(s): $failedServicesString."
        }
    } else {
        $statusCode = 1
        Write-Log -level $LogLevelError -message "Failed to copy eBPF files to the destination folder."
    }

    return $statusCode
}

function Uninstall-eBPF {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Uninstalling eBPF for Windows"
    $statusCode = 0

    # Stop all eBPF drivers (which will stop all the services which have a dependency on them).
    Stop-eBPFDrivers

    # Uninstall the eBPF services and use the results to generate the status file
    $uninstallResult1 = Uninstall-Driver -serviceName $EbpfCoreDriverName
    $uninstallResult2 = Uninstall-Driver -serviceName $NetEbpfExtDriverName

    # Determine the overall status and status message
    if ($uninstallResult1 -eq 0 -and $uninstallResult2 -eq 0) {

        Write-Log -level $LogLevelInfo -message "eBPF for Windows uninstalled successfully."
    } else {
        $statusCode = 1
        $failedServices = @()        
        if ($uninstallResult1 -ne 0) {
            $failedServices += $EbpfCoreDriverName
        }
        if ($uninstallResult2 -ne 0) {
            $failedServices += $NetEbpfExtDriverName
        }
        $failedServicesString = $failedServices -join ", "
        Write-Log -level $LogLevelError -message "Failed to uninstall service(s): $failedServicesString."
    }

    # Remove the eBPF installation directory from the system PATH
    Remove-DirectoryFromSystemPath -directoryPath $installDirectory

    # Delete the eBPF files
    Delete-EbpfFiles -destinationPath $installDirectory

    # Unregister the trace providers
    Disable-Tracing   

    return $statusCode
}

function InstallOrUpdate-eBPF {
    param (
        [string]$vmAgentOperationName,
        [string]$sourcePath,
        [string]$destinationPath
    )

    $statusCode = 0
    $statusString = $StatusSuccess
    $statusMessage = ""

    # Set the default product version to 0.0.0 (i.e. not installed)
    $productVersion = "0.0.0"

    # Retrieve the product version of the driver in the extension package
    $filePath = Join-Path -Path $EbpfPackagePath -ChildPath "$EbpfCoreDriverName.sys"
    $newProductVersion = Get-ProductVersionFromFile -filePath "$filePath"
    
    # Firstly, check if eBPFCore is installed and registered.
    $fullDiskPath = Get-FullDiskPathFromService -serviceName $EbpfCoreDriverName
    if ($fullDiskPath) {

        # TBD: check if the driver is registered in the default folder, if not, log an error --> what to do??
        if ($fullDiskPath -ne $EbpfDefaultInstallPath) {
            Write-Log -level $LogLevelWarning -message "'$EbpfCoreDriverName' driver registered from a non-default folder: $fullDiskPath"
        }

        Write-Log -level $LogLevelInfo -message "eBPF driver installed and registered from: $fullDiskPath"

        # Check the product version of the installed driver
        $filePath = Join-Path -Path $EbpfDefaultInstallPath -ChildPath "drivers\$EbpfCoreDriverName.sys"
        $productVersion = Get-ProductVersionFromFile -filePath "$filePath"

    } else {
        Write-Log -level $LogLevelWarning -message "'$EbpfCoreDriverName' driver not registered on this machine, checking installation in the default folder..."

        # Check the product version of the installed driver
        $filePath = Join-Path -Path $EbpfDefaultInstallPath -ChildPath "drivers\$EbpfCoreDriverName.sys"
        $productVersion = Get-ProductVersionFromFile -filePath "$filePath"        
    }
    
    # If there's a product version, then a version of eBPF is installed, let's check if it needs to be updated.
    if ($productVersion) {
        Write-Log -level $LogLevelInfo -message "eBPF v$productVersion is already installed."

        # If the product version is less than the version distributed with the VM extension, then upgrade it. Otherwise, no update is needed.
        $comparison = Compare-VersionNumbers -version1 $productVersion -version2 $newProductVersion       
        if ($comparison -lt 0) {

            Write-Log -level $LogLevelInfo -message "Upgrading eBPF to v$newProductVersion..."
            
            # For the moment, we just uninstall and Install
            $res = Uninstall-eBPF -serviceName $EbpfCoreDriverName
            if ($res -ne 0) {
                $statusString = $StatusError
                $statusCode = 1
                $statusMessage = "eBPF $vmAgentOperationName FAILED (Uninstall failed)."
                Write-Log -level $LogLevelError -message $statusMessage
            } else {
                Write-Log -level $LogLevelInfo -message "eBPF v$productVersion uninstalled successfully."
                $res = Install-eBPF $EbpfPackagePath, $EbpfDefaultInstallPath
                if ($res -ne 0) {
                    $statusString = $StatusError
                    $statusCode = 1
                    $statusMessage = "eBPF $vmAgentOperationName FAILED (Install failed)."
                    Write-Log -level $LogLevelError -message $statusMessage
                } else {
                    $statusString = $StatusSuccess
                    $statusCode = 0
                    $statusMessage = "eBPF $vmAgentOperationName succeeded."
                    Write-Log -level $LogLevelError -message $statusMessage
                }
            }
        } elseif ($comparison -gt 0) {
            $statusString = $StatusSuccess
            $statusCode = 0
            $statusMessage = "The installed eBPF version (v$productVersion) is newer than the one in the extension package (v$newProductVersion)"
            Write-Log -level $LogLevelWarning -message $statusMessage
        } else {
            $statusString = $StatusSuccess
            $statusCode = 0
            $statusMessage = "eBPF version is up to date (v$productVersion)."
            Write-Log -level $LogLevelInfo -message $statusMessage
        }
    } else {
        Write-Log -level $LogLevelInfo -message "No eBPF installation found in [$destinationPath]: installing (v$newProductVersion)."
        
        # Proceed with a new installation from the artifact package within the extension ZIP file
        $res = Install-eBPF $EbpfPackagePath, $EbpfDefaultInstallPath
        if ($res -ne 0) {
            $statusString = $StatusError
            $statusCode = 1
            $statusMessage = "eBPF $vmAgentOperationName FAILED (Clean install failed)."
            Write-Log -level $LogLevelError -message $statusMessage
        } else {            
            $statusString = $StatusSuccess
            $statusCode = 0
            $statusMessage = "eBPF v$newProductVersion installed successfully."
            Write-Log -level $LogLevelInfo -message $statusMessage
        }
    }

    # TBD: confirm if Install does not need to generate a status file
    if ($vmAgentOperationName -ne $OperationNameInstall) {

        Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $vmAgentOperationName -status $statusString -statusCode $statusCode -statusMessage $statusMessage
    }
    
    # Extra step for IMDS (this is not accounted as a result of the eBPF VM Extension, as it is not part of the eBPF VM Extension package)
    $serviceName = "GuestProxyAgent"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log -level $LogLevelInfo -message "$serviceName does not exist -> skipping start."
    } else {
        $res = Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $res) {
            Write-Log -level $LogLevelError -message "Failed to start $serviceName. Error code: $res"
        }
    }
}


#######################################################
# Main entry point
#######################################################
# Call the Get-HandlerEnvironment function, capture the output and set the global environment variable.
$handlerEnvironmentObject = Get-HandlerEnvironment
$env:eBPFHandlerEnv = $handlerEnvironmentObject
if ($handlerEnvironmentObject -ne $null) {
    Write-Host "Log Folder: $($handlerEnvironmentObject.handlerEnvironment.logFolder)"
    Write-Host "Config Folder: $($handlerEnvironmentObject.handlerEnvironment.configFolder)"
    Write-Host "Status Folder: $($handlerEnvironmentObject.handlerEnvironment.statusFolder)"
    Write-Host "Heartbeat File: $($handlerEnvironmentObject.handlerEnvironment.heartbeatFile)"
    Write-Host "Deployment ID: $($handlerEnvironmentObject.handlerEnvironment.deploymentid)"
    Write-Host "Role Name: $($handlerEnvironmentObject.handlerEnvironment.rolename)"
    Write-Host "Instance Name: $($handlerEnvironmentObject.handlerEnvironment.instance)"
    Write-Host "Host Resolver Address: $($handlerEnvironmentObject.handlerEnvironment.hostResolverAddress)"
    Write-Host "Events Folder: $($handlerEnvironmentObject.handlerEnvironment.eventsFolder)"
} else {
    Write-Host ".\HandlerEnvironment.json file not found."
    return
}

#######################################################
# Tests
#######################################################
if ($runTests -eq $true) {

    #Load test-environment (current working folder is the root folder in which the entire ZIP in unzipped).
    $handlerEnvironmentObject = Get-HandlerEnvironment -handlerEnvironmentFullPath ".\HandlerEnvironment-test.json" 

    # Install
    InstallOrUpdate-eBPF $OperationNameInstall $EbpfPackagePath, $EbpfDefaultInstallPath

    # Update
    Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
    InstallOrUpdate-eBPF $OperationNameUpdate, $EbpfPackagePath, $EbpfDefaultInstallPath

    # Uninstall
    $statusString = $StatusSuccess
    $statusCode = 0
    $statusMessage = ""
    $res = Uninstall-eBPF $EbpfDefaultInstallPath
    if ($res -eq $true) {    
        $statusMessage = "eBPF for Windows was successfully uninstalled"
    }
    else {
        $statusString = $StatusError
        $statusCode = 1
        $statusMessage = "eBPF for Windows was not uninstalled"
    }
    Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUninstall -status $statusString -statusCode $statusCode -statusMessage $statusMessage
}