#######################################################
# Global Variables
#######################################################
# Define eBPF Handler Environment variables
Set-Variable -Name "runTests" -Value $true
Set-Variable -Name "EbpfPackagePath" -Value ".\package"
Set-Variable -Name "EbpfDefaultInstallPath" -Value "$env:ProgramFiles\ebpf-for-windows"
Set-Variable -Name "AksRegistryKeyPath" -Value "HKLM:\Software\AKS\Key" #TBD: change to the actual registry key
Set-Variable -Name "AksRegistryKeyValue" -Value 1 #TBD: change to the actual registry value
Set-Variable -Name "EbpfCoreDriverName" -Value "eBPFCore"
Set-Variable -Name "NetEbpfExtDriverName" -Value "NetEbpfExt"
Set-Variable -Name "NetshExtensionName" -Value "ebpfnetsh.dll"
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
}

# Define the VM extension's generic and Status file constants
Set-Variable -Name "DefaultHandlerEnvironmentPath" -Value ".\HandlerEnvironment.json"
Set-Variable -Name "HandlerWorkloadName" -Value "eBPFforWindows"
Set-Variable -Name "OperationNameEnable" -Value "enable"
Set-Variable -Name "OperationNameDisable" -Value "disable"
Set-Variable -Name "OperationNameInstall" -Value "install"
Set-Variable -Name "OperationNameUninstall" -Value "uninstall"
Set-Variable -Name "OperationNameUpdate" -Value "update"
Set-Variable -Name "StatusTransitioning" -Value "transitioning"
Set-Variable -Name "StatusError" -Value "error"
Set-Variable -Name "StatusSuccess" -Value "success"
Set-Variable -Name "StatusWarning" -Value "warning"


#######################################################
# Logging Functions
#######################################################
# Define constants for log levels
$LogLevelInfo = "INFO"
$LogLevelWarning = "WARNING"
$LogLevelError = "ERROR"
Set-Variable -Name "LogFileName" -Value "ebpf_handler.log"
Set-Variable -Name "LogFilePath" -Value ".\$LogFileName"

function Write-Log {
    param (
        [string]$level,
        [string]$message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp]-[$level] - $message"
    
    # Always write to host
    Write-Host $logEntry

    # Append the log entry to the log file, and also write it to the console
    $logEntry | Out-File -Append -FilePath $LogFilePath  
}

#######################################################
# Utility Functions
#######################################################
function Get-HandlerEnvironment {
    param (
        # The HandlerEnvironment.json file is always located in the root of where the ZIP package is extracted
        [string]$handlerEnvironmentFullPath = "$DefaultHandlerEnvironmentPath"
    )

    if (Test-Path $handlerEnvironmentFullPath -PathType Leaf) {
        $jsonContent = Get-Content -Path $handlerEnvironmentFullPath -Raw
        $jsonContent = $jsonContent | ConvertFrom-Json
        $global:eBPFHandlerEnvObj = $jsonContent[0]
        if ($null -ne $global:eBPFHandlerEnvObj) {
            $global:LogFilePath = Join-Path -Path $($global:eBPFHandlerEnvObj.handlerEnvironment.logFolder) -ChildPath $LogFileName
            Write-Log -level $LogLevelInfo -message "Log Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.logFolder)"
            Write-Log -level $LogLevelInfo -message "Log File Path: $LogFilePath"
            Write-Log -level $LogLevelInfo -message "Config Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.configFolder)"
            Write-Log -level $LogLevelInfo -message "Status Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)"
            Write-Log -level $LogLevelInfo -message "Heartbeat File: $($global:eBPFHandlerEnvObj.handlerEnvironment.heartbeatFile)"
            Write-Log -level $LogLevelInfo -message "Deployment ID: $($global:eBPFHandlerEnvObj.handlerEnvironment.deploymentid)"
            Write-Log -level $LogLevelInfo -message "Role Name: $($global:eBPFHandlerEnvObj.handlerEnvironment.rolename)"
            Write-Log -level $LogLevelInfo -message "Instance Name: $($global:eBPFHandlerEnvObj.handlerEnvironment.instance)"
            Write-Log -level $LogLevelInfo -message "Host Resolver Address: $($global:eBPFHandlerEnvObj.handlerEnvironment.hostResolverAddress)"
            Write-Log -level $LogLevelInfo -message "Events Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.eventsFolder)"
        } else {
            Write-Log -level $LogLevelInfo -message "$handlerEnvironmentFullPath does not contain a valid object."
            return $false
        }
        return $true
    } else {
        Write-Log -level $LogLevelError -message "$handlerEnvironmentFullPath file not found."
        return $false
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
    $lastSequenceNumber = Get-ChildItem -Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.configFolder)" -Filter "*.settings" | Sort-Object CreationTime -Descending | Select-Object -First 1
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
    $statusFilePath = Join-Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)" $statusFileName
    $statusJson | Set-Content -Path $statusFilePath

    Write-Log -level $LogLevelInfo -message "Status file generated: $statusFilePath"
}

function Is-AKS-Environment {

    $key = Get-Item -Path $AksRegistryKeyPath -ErrorAction SilentlyContinue

    if ($null -ne $key) {
        $value = $key.GetValue($AksRegistryKeyValue)
        if ($null -ne $value) {
            return $true
        } else {
            Write-Log -level $LogLevelInfo -message "Value '$AksRegistryKeyValue' not found in registry key '$AksRegistryKeyPath'."
        }
    } else {
        Write-Log -level $LogLevelInfo -message "Registry key '$AksRegistryKeyPath' not found."
    }

    return $false
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
        Write-Log -level $LogLevelInfo -message "'$directoryPath' is already in the system PATH -> no action taken."
    } else {
        $newPath = "$currentPath;$directoryPath"
        [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Log -level $LogLevelInfo -message "'$directoryPath' added to the system PATH."
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
        Write-Log -level $LogLevelInfo -message "'$directoryPath' removed from the system PATH."
    } else {
        Write-Log -level $LogLevelInfo -message "'$directoryPath' is not found in the system PATH -> no action taken."
    }
}

function Register-NetshExtension{
    param (
        [string]$installDirectory
    )

    Push-Location -Path $installDirectory

    # Add the eBPF netsh helper.
    $installResult = & "netsh.exe" add helper $NetshExtensionName

    # Check the exit code to determine the result
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$NetshExtensionName registered successfully."
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
        Write-Log -level $LogLevelInfo -message "$NetshExtensionName unregistered successfully."
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

    Write-Log -level $LogLevelInfo -message "Installing service $serviceName"

    # Create the service using sc.exe (you'll need to replace this with the actual command)
    $BinaryPath = Join-Path -Path $servicePath -ChildPath $serviceName
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
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key
        Stop-Service -Name $driverName -ErrorAction SilentlyContinue
        if ($?) {
            Write-Log -Level $LogLevelInfo -Message "Stopped driver: $driverName"
        } else {
            Write-Log -Level $LogLevelError -Message "Failed to stop driver: $driverName"
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
        Copy-Item -Path ($sourcePath + "\*") -Destination $destinationPath -Recurse -Force -ErrorAction Stop
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

    # Copy the eBPF files to the destination folder
    $copyResult = Copy-EbpFiles -sourcePath $sourcePath -destinationPath $destinationPath
    if ($copyResult -eq $true) {
        # Install the eBPF services and use the results to generate the status file
        $installResult1 = Install-Driver -serviceName $EbpfCoreDriverName -servicePath "$destinationPath\drivers"
        $installResult2 = Install-Driver -serviceName $NetEbpfExtDriverName -servicePath "$destinationPath\drivers"

        # Determine the overall status and status message
        if ($installResult1 -eq 0 -and $installResult2 -eq 0) {

            # Add the eBPF installation directory to the system PATH
            Add-DirectoryToSystemPath -directoryPath $destinationPath | Out-Null 

            # Register the netsh extension
            Register-NetshExtension -installDirectory $destinationinstallDirectory | Out-Null 
               
            # Register the trace providers
            Enable-Tracing | Out-Null 

            $statusCode = 0
            Write-Log -level $LogLevelInfo -message "eBPF for Windows installed successfully."
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

    return [int]$statusCode
}

function Uninstall-eBPF {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Uninstalling eBPF for Windows"
    
    # Stop all eBPF drivers (which will stop all the services which have a dependency on them).
    Stop-eBPFDrivers | Out-Null 

    # De-register the netsh extension
    Unregister-NetshExtension | Out-Null 

    # Uninstall the eBPF services and use the results to generate the status file
    $uninstallResult1 = Uninstall-Driver -serviceName $EbpfCoreDriverName
    $uninstallResult2 = Uninstall-Driver -serviceName $NetEbpfExtDriverName

    # Determine the overall status and status message
    if ($uninstallResult1 -eq 0 -and $uninstallResult2 -eq 0) {
        $statusCode = 0
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
    Remove-DirectoryFromSystemPath -directoryPath $installDirectory | Out-Null 

    # Delete the eBPF files
    Delete-EbpfFiles -destinationPath $installDirectory | Out-Null 

    # Unregister the trace providers
    Disable-Tracing | Out-Null 

    return [int]$statusCode
}

function Upgrade-eBPF {
    param (
        [string]$vmAgentOperationName,
        [string]$currProductVersion,
        [string]$newProductVersion,
        [string]$installDirectory
    )
    
    Write-Log -level $LogLevelInfo -message "Upgrading eBPF from v$currProductVersion to v$newProductVersion..."

    if (Is-AKS-Environment -eq $true) {
        $statusCode = 1
        Write-Log -level $LogLevelError -message "eBPF $vmAgentOperationName not allowed in an AKS environment."
    } else {
        Write-Log -level $LogLevelInfo -message "eBPF $vmAgentOperationName in non-AKS environment."

        # For the moment, we just uninstall and install to the current installation folder
        $statusCode = Uninstall-eBPF "$installDirectory"
        if ($statusCode -ne 0) {
            $statusMessage = "eBPF $vmAgentOperationName FAILED (Uninstall failed)."
            Write-Log -level $LogLevelError -message $statusMessage
        } else {
            Write-Log -level $LogLevelInfo -message "eBPF v$currProductVersion uninstalled successfully."
            $statusCode = Install-eBPF -sourcePath "$EbpfPackagePath" -destinationPath "$installDirectory"
            if ($statusCode -ne 0) {
                $statusMessage = "eBPF $vmAgentOperationName FAILED (Install failed)."
                Write-Log -level $LogLevelError -message $statusMessage
            } else {
                $statusMessage = "eBPF $vmAgentOperationName succeeded."
                Write-Log -level $LogLevelError -message $statusMessage
            }
        }
    }

    return [int]$statusCode
}

function InstallOrUpdate-eBPF {
    param (
        [string]$vmAgentOperationName,
        [string]$sourcePath,
        [string]$destinationPath
    )

    # Set the default product version to NULL (i.e. not installed)
    $currProductVersion = $null

    # This function is flexible to uninstall/install/upgrade to a different path than the iven one, for those scenarios where the driver is registered from a different folder.
    $currInstallPath = $destinationPath

    # Retrieve the product version of the driver in the extension package
    $newProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path $EbpfPackagePath -ChildPath "drivers\$EbpfCoreDriverName.sys")
    
    # Firstly, check if eBPFCore is installed and registered (as a test for eBPF to be installed).
    $currDriverPath = Get-FullDiskPathFromService -serviceName $EbpfCoreDriverName
    if ($currDriverPath) {
        Write-Log -level $LogLevelInfo -message "eBPF driver installed and registered from: '$currDriverPath"

        # TBD: check if the driver is registered in the default folder, if not, log an error --> what to do??
        # Currently, we just log a warning and proceed with the installation in the current folder.
        $currInstallPath = Split-Path -Path $currDriverPath -Parent
        if ($currDriverPath -ne $EbpfDefaultInstallPath) {
            Write-Log -level $LogLevelWarning -message "'$EbpfCoreDriverName' driver registered from a non-default folder: $currDriverPath"
        }

        # Retrieve the product version of the installed driver
        $currProductVersion = Get-ProductVersionFromFile -filePath "$currDriverPath"

    } else {
        Write-Log -level $LogLevelWarning -message "'$EbpfCoreDriverName' driver not registered on this machine, checking installation in the default folder..."

        # Check if there's a driver in the default installation folder, and get its product version
        $currProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path $EbpfDefaultInstallPath -ChildPath "drivers\$EbpfCoreDriverName.sys")
    }
    
    # If there's a $currProductVersion has a value, then a version of eBPF is already installed, let's check if it needs to be updated.
    if ($null -ne $currProductVersion) {
        Write-Log -level $LogLevelInfo -message "eBPF v$currProductVersion is already installed."

        # If the product version is less than the version distributed with the VM extension, then upgrade it. Otherwise, no update is needed.
        $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion       
        if ($comparison -lt 0) {
            [int]$statusCode = Upgrade-eBPF -vmAgentOperationName $vmAgentOperationName -currProductVersion $currProductVersion -newProductVersion $newProductVersion -installDirectory "$currInstallPath"
        } elseif ($comparison -gt 0) {
            $statusCode = 0
            $statusMessage = "The installed eBPF version (v$currProductVersion) is newer than the one in the extension package (v$newProductVersion)"
            Write-Log -level $LogLevelWarning -message $statusMessage
        } else {
            $statusCode = 0
            $statusMessage = "eBPF version is up to date (v$currProductVersion)."
            Write-Log -level $LogLevelInfo -message $statusMessage
        }
    } else {
        Write-Log -level $LogLevelInfo -message "No eBPF installation found in [$destinationPath]: installing (v$newProductVersion)."
        
        # Proceed with a new installation from the artifact package within the extension ZIP file
        $statusCode = Install-eBPF -sourcePath "$EbpfPackagePath" -destinationPath "$currInstallPath"
        if ($statusCode -ne 0) {
            Write-Log -level $LogLevelError -message "Failed to install eBPF v$newProductVersion."
            Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $vmAgentOperationName -status $StatusError -statusCode 1 -statusMessage "eBPF $vmAgentOperationName FAILED (Clean install failed)."
        } else {
            Write-Log -level $LogLevelInfo -message "eBPF v$newProductVersion installed successfully."
            # TBD: confirm if Install does not need to generate a status file
            Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $vmAgentOperationName -status $StatusSuccess -statusCode 0 -statusMessage "eBPF $vmAgentOperationName succeeded."
        }
    }

    return [int]$statusCode
}


#######################################################
# Main entry point
#######################################################
# Change the working directory to the root of the test environment, so to simulate the actual env that will be set up by the VM Agent.
Push-Location -Path 'C:\_ebpf\vm_ext'
if ($runTests -eq $true) {

    #Load test-environment (current working folder is the root folder in which the entire ZIP in unzipped).
    if (Get-HandlerEnvironment -handlerEnvironmentFullPath ".\HandlerEnvironment-test.json" -eq $true) {

        # Test cases
        Write-Log -level $LogLevelInfo -message "= Cleaning up environment =================================================================================================="
        # Quick & dirty cleanup
        $null = net stop eBPFCore 2>&1
        $null = sc.exe delete eBPFCore 2>&1
        $null = net stop NetEbpfExt 2>&1
        $null = sc.exe delete NetEbpfExt 2>&1
        $null = netsh delete helper ebpfnetsh.dll 2>&1
        $null = Remove-DirectoryFromSystemPath "$EbpfDefaultInstallPath" 2>&1
        $null = Remove-Item -Path "$EbpfDefaultInstallPath" -Recurse -Force 2>&1
        Remove-Item -Path "$global:LogFilePath" -Recurse -Force 2>&1 | Out-Null    
 
        # Install an old version
        Write-Log -level $LogLevelInfo -message "= Install an old version =================================================================================================="
        Delete-EbpfFiles -destinationPath "$EbpfPackagePath"
        Copy-EbpFiles -sourcePath ".\_redist-package_v0.7.0" -destinationPath "$EbpfPackagePath"
        InstallOrUpdate-eBPF -vmAgentOperationName $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"

        # Update to newer version
        Write-Log -level $LogLevelInfo -message "= Update to newer version =================================================================================================="
        Delete-EbpfFiles -destinationPath "$EbpfPackagePath"
        Copy-EbpFiles -sourcePath ".\_redist-package_v0.10.0" -destinationPath "$EbpfPackagePath"
        Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
        InstallOrUpdate-eBPF -vmAgentOperationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
        
        # Update to older version
        Write-Log -level $LogLevelInfo -message "= Update to older version =================================================================================================="
        Delete-EbpfFiles -destinationPath "$EbpfPackagePath"
        Copy-EbpFiles -sourcePath ".\_redist-package_v0.7.0" -destinationPath "$EbpfPackagePath"
        Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
        InstallOrUpdate-eBPF -vmAgentOperationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"

        # Uninstall
        Write-Log -level $LogLevelInfo -message "= Uninstall =================================================================================================="
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
    } else {
        Write-Log -level $LogLevelError -message "Failed to load .\HandlerEnvironment-test.json."
        exit
    }
} else
{
    # Call the Get-HandlerEnvironment function, capture the output and set the global environment variable.
    if (Get-HandlerEnvironment -ne $true) {
        Write-Log -level $LogLevelError -message "Failed to load '$DefaultHandlerEnvironmentPath'."
        exit       
    }
}

Pop-Location