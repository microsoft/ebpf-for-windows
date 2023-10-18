#######################################################
# Global Variables
#######################################################
# Define eBPF Handler Environment variables.
Set-Variable -Name "EbpfExtensionName" -Value "EbpfForWindows"
Set-Variable -Name "EbpfPackagePath" -Value ".\"
Set-Variable -Name "EbpfDefaultInstallPath" -Value "$env:ProgramFiles\ebpf-for-windows"
Set-Variable -Name "EbpfNetshExtensionName" -Value "ebpfnetsh.dll"
Set-Variable -Name "EbpfTracingStartupTaskName" -Value "eBpfTracingStartupTask"
Set-Variable -Name "EbpfTracingStartupTaskFilename" -Value "ebpf_tracing_startup_task.xml"
Set-Variable -Name "EbpfTracingPeriodicTaskName" -Value "eBpfTracingPeriodicTask"
Set-Variable -Name "EbpfTracingPeriodicTaskFilename" -Value "ebpf_tracing_periodic_task.xml"
Set-Variable -Name "EbpfTracingTaskCmd" -Value "ebpf_tracing.cmd"
Set-Variable -Name "EbpfTracingPath" -Value "$env:SystemRoot\Logs\eBPF"
Set-Variable -Name "EbpfStartTimeoutSeconds" -Value 60
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
}

# VM Agent-generated environment variables.
Set-Variable -Name "VmAgentEnvVar_SEQUENCE_NO" -Value "ConfigSequenceNumber"

# Define the VM extension's generic and Status file constants.
Set-Variable -Name "DefaultHandlerEnvironmentFilePath" -Value ".\HandlerEnvironment.json"
Set-Variable -Name "StatusName" -Value $EbpfExtensionName
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
$LogLevelInfo = 1
$LogLevelWarning = 2
$LogLevelError = 3
$LoggingLevel = $LogLevelInfo
Set-Variable -Name "LogFileName" -Value "ebpf_handler.log"
Set-Variable -Name "LogFilePath" -Value ".\$LogFileName"

function Write-Log {
    param (
        [int]$level,
        [string]$message
    )

    # Construct the log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    switch ($level) {
        $LogLevelInfo { 
            $levelString = "INFO"
        }
        $LogLevelWarning { 
            $levelString = "WARNING"
        }
        $LogLevelError { 
            $levelString = "ERROR"
        }
        Default {
            $levelString = "*"
        }
    }
    $logEntry = "[$timestamp]-[$levelString] - $message"
    
    # Always write to host
    Write-Host $logEntry

    # Append the log entry to the log file, if the log level is greater than or equal to the logging level.
    if ($level -ge $LoggingLevel) {        
        $logEntry | Out-File -Append -FilePath $global:LogFilePath
    }    
}

#######################################################
# Utility Functions
#######################################################
function Set-EnvironmentVariable {
    param (
        [string]$variableName,
        [string]$variableValue
    )

    Write-Log -level $LogLevelInfo -message "Set-EnvironmentVariable($variableName, $variableValue)"
    
    try {
        [Environment]::SetEnvironmentVariable($variableName, $variableValue, [System.EnvironmentVariableTarget]::Process)
        Write-Log -level $LogLevelInfo -message "Environment variable '$variableName' set successfully."
    }
    catch {
        Write-Log -level $LogLevelError -message "Failed to set environment variable '$variableName'. Error: $_"
        return 1
    }
    
    return 0
}

function Get-EnvironmentVariable {
    param (
        [string]$variableName
    )

    Write-Log -level $LogLevelInfo -message "Get-EnvironmentVariable($variableName)"

    $variableValue = [Environment]::GetEnvironmentVariable($variableName, [System.EnvironmentVariableTarget]::Process)
    if ([string]::IsNullOrWhiteSpace($variableValue)) {
        Write-Log -level $LogLevelError -message "Environment variable '$variableName' is not set or has an empty value."
    } else {
        Write-Log -level $LogLevelInfo -message "Environment variable '$variableName' has value '$variableValue'."
    }
    
    return $variableValue
}

function Is-Upgrade-Supported {
    # This function will return true if the upgrade is allowed in the current environment, false otherwise.
    # Currently, it is a placeholder for future requirements.

    Write-Log -level $LogLevelInfo -message "Is-Upgrade-Supported()"
    return $true
}

function Get-FullDiskPathFromService {
    param (
        [string]$serviceName
    )

    Write-Log -level $LogLevelInfo -message "Get-FullDiskPathFromService($serviceName)"

    $scQueryOutput = & "sc.exe" qc $serviceName

    # Search for the BINARY_PATH_NAME line using regex.
    $binaryPathLine = $scQueryOutput -split "`n" | Where-Object { $_ -match "BINARY_PATH_NAME\s+:\s+(.*)" }

    if ($binaryPathLine) {

        # Extract the full disk path using regex.
        $binaryPath = $matches[1]
        $fullDiskPath = [regex]::Match($binaryPath, '(?<=\\)\w:.+')

        if ($fullDiskPath.Success) {
            return $fullDiskPath.Value
        }
    }
    
    return $null
}

function Get-ProductVersionFromFile {
    param (
        [string]$filePath
    )

    Write-Log -level $LogLevelInfo -message "Get-ProductVersionFromFile($filePath)"

    if (Test-Path -Path $filePath -PathType Leaf) {
        $fileVersionInfo = Get-ItemProperty -Path $filePath -Name VersionInfo
        $productVersion = $fileVersionInfo.VersionInfo.ProductVersion
        if ($productVersion) {
            return $productVersion
        }
    }

    return $null
}

function Compare-VersionNumbers {
    param (
        [string]$version1,
        [string]$version2
    )

    Write-Log -level $LogLevelInfo -message "Compare-VersionNumbers($version1, $version2)"

    $version1Digits = $version1 -split '\.'
    $version2Digits = $version2 -split '\.'

    $maxDigits = [Math]::Max($version1Digits.Length, $version2Digits.Length)
    for ($i = 0; $i -lt $maxDigits; $i++) {
        $digit1 = if ($i -lt $version1Digits.Length) { [int]$version1Digits[$i] } else { 0 }
        $digit2 = if ($i -lt $version2Digits.Length) { [int]$version2Digits[$i] } else { 0 }

        if ($i -eq 3) {
            # If we reached the 4th digit, then we're comparing the handler version, so let's return a distiguished result.
            # This way, eBPF will not be updated, as this is just a handler update.
            return 2
        }
        
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
    
    Write-Log -level $LogLevelInfo -message "Add-DirectoryToSystemPath($directoryPath)"

    try {
        $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
        if ($currentPath -split ";" -contains $directoryPath) {
            Write-Log -level $LogLevelInfo -message "'$directoryPath' is already in the system PATH -> no action taken."
        } else {
            $newPath = "$currentPath;$directoryPath"
            [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
            Write-Log -level $LogLevelInfo -message "'$directoryPath' added to the system PATH."
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while adding '$directoryPath' to the system PATH: $_"
        return 1
    }

    return 0
}

function Remove-DirectoryFromSystemPath {
    param (
        [string]$directoryPath
    )

    Write-Log -level $LogLevelInfo -message "Remove-DirectoryFromSystemPath($directoryPath)"

    try {
        $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
        if ($currentPath -split ";" -contains $directoryPath) {
            $newPath = ($currentPath -split ";" | Where-Object { $_ -ne $directoryPath }) -join ";"
            [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
            Write-Log -level $LogLevelInfo -message "'$directoryPath' removed from the system PATH."
        } else {
            Write-Log -level $LogLevelInfo -message "'$directoryPath' is not found in the system PATH -> no action taken."
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while removing '$directoryPath' from the system PATH: $_"
        return 1
    }

    return 0
}

function Install-Driver {
    param (
        [string]$serviceName,
        [string]$servicePath
    )

    Write-Log -level $LogLevelInfo -message "Install-Driver($serviceName, $servicePath)"

    try {
        # Create the service using sc.exe (you'll need to replace this with the actual command).
        $scCreateOutput = & "sc.exe" create $serviceName type=kernel start=auto binPath="$servicePath"

        # Check the exit code to determine the result.
        if ($LASTEXITCODE -eq 0) {
            Write-Log -level $LogLevelInfo -message "'$serviceName' installed successfully."
        } else {
            Write-Log -level $LogLevelError -message "Failed to install '$serviceName'. Error message: $scCreateOutput"
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while installing '$serviceName': $_"
    }

    return $LASTEXITCODE
}

function Uninstall-Driver {
    param (
        [string]$serviceName
    )
    try {
        Write-Log -level $LogLevelInfo -message "Uninstall-Driver($serviceName)"
    
        # Delete the driver service
        $scDeleteOutput = & "sc.exe" delete $serviceName

        # Check the exit code to determine the result.
        if ($LASTEXITCODE -eq 0) {
            Write-Log -level $LogLevelInfo -message "'$serviceName' uninstalled successfully."
        } else {
            Write-Log -level $LogLevelError -message "Failed to uninstall '$serviceName'. Error message: $scDeleteOutput"      
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while installing '$serviceName': $_"
    }

    return $LASTEXITCODE
}

function Copy-Directory {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "Copy-Directory($sourcePath, $destinationPath)"

    $res = 0
    # Create the destination directory, if it doesn't exist.
    if (-not (Test-Path $destinationPath)) {
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop | Out-Null
        } catch {
            Write-Log -level $LogLevelError -message "Failed to create destination directory '$destinationPath': $_"
            $res = 1
        }
    }

    # Recursively copy all files from source to destination.
    try {
        Copy-Item -Path ($sourcePath + "\*") -Destination $destinationPath -Recurse -Force -ErrorAction Stop | Out-Null
        Write-Log -level $LogLevelInfo -message "Files copied from '$sourcePath' to '$destinationPath'."
    } catch {
        Write-Log -level $LogLevelError -message "Error while copying files: $_"
        $res = 1
    }
    
    return $res
}

function Delete-Directory {
    param (
        [string]$destinationPath
    )
    
    Write-Log -level $LogLevelInfo -message "Delete-Directory($destinationPath)"
    
    $res = 0
    if (Test-Path $destinationPath) {
        try {
            Remove-Item -Path $destinationPath -Recurse -Force -ErrorAction Stop
            Write-Log -level $LogLevelInfo -message "Directory '$destinationPath' deleted successfully."            
        } catch {
            Write-Log -level $LogLevelError -message "Failed to delete directory '$destinationPath'. Error: $_"
            $res = 1
        }
    } else {
        Write-Log -level $LogLevelWarning -message "Directory '$destinationPath' does not exist."
        $res = 1
    }

    return $res
}

function Create-Scheduled-Task {
    param (
        [string]$installDirectory,
        [string]$taskName,
        [string]$taskFile
    )

    Write-Log -level $LogLevelInfo -message "Create-Scheduled-Task($installDirectory, $taskName, $taskFile)"

    try {
        $xmlPath = Join-Path $installDirectory $taskFile
        Register-ScheduledTask -Xml (Get-Content -Path $xmlPath -Raw) -TaskName $taskName | Out-Null
        Write-Log -level $LogLevelInfo -message "SUCCESS setting up the '$taskName' task."
    } catch {        
        Write-Log -level $LogLevelError -message "FAILED setting up the '$taskName' task.  Error message: $($_.Exception.Message)"
        return $_.Exception.HResult
    }

    return 0
}

#######################################################
# VM Extension Handler Internal Helper Functions
#######################################################
function Get-HandlerEnvironment {
    param (
        # The HandlerEnvironment.json file is always located in the root of where the ZIP package is extracted.
        [string]$handlerEnvironmentFullPath = "$DefaultHandlerEnvironmentFilePath"
    )

    $res = 0
    if (Test-Path $handlerEnvironmentFullPath -PathType Leaf) {
        $jsonContent = Get-Content -Path $handlerEnvironmentFullPath -Raw
        $jsonContent = $jsonContent | ConvertFrom-Json
        $global:eBPFHandlerEnvObj = $jsonContent[0]
        if ($null -ne $global:eBPFHandlerEnvObj) {
            # Set the global log file path.
            $global:LogFilePath = Join-Path -Path $($global:eBPFHandlerEnvObj.handlerEnvironment.logFolder) -ChildPath $LogFileName

            # Only write to log when we have a valid object, including the log file path.
            Write-Log -level $LogLevelInfo -message "Get-HandlerEnvironment($handlerEnvironmentFullPath)"
            Write-Log -level $LogLevelInfo -message "Log Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.logFolder)"
            Write-Log -level $LogLevelInfo -message "Log File Path: $($global:LogFilePath)"
            Write-Log -level $LogLevelInfo -message "Config Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.configFolder)"
            Write-Log -level $LogLevelInfo -message "Status Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)"
            Write-Log -level $LogLevelInfo -message "Heartbeat File: $($global:eBPFHandlerEnvObj.handlerEnvironment.heartbeatFile)"
            Write-Log -level $LogLevelInfo -message "Deployment ID: $($global:eBPFHandlerEnvObj.handlerEnvironment.deploymentid)"
            Write-Log -level $LogLevelInfo -message "Role Name: $($global:eBPFHandlerEnvObj.handlerEnvironment.rolename)"
            Write-Log -level $LogLevelInfo -message "Instance Name: $($global:eBPFHandlerEnvObj.handlerEnvironment.instance)"
            Write-Log -level $LogLevelInfo -message "Host Resolver Address: $($global:eBPFHandlerEnvObj.handlerEnvironment.hostResolverAddress)"
            Write-Log -level $LogLevelInfo -message "Events Folder: $($global:eBPFHandlerEnvObj.handlerEnvironment.eventsFolder)"
        } else {
            Write-Error "$handlerEnvironmentFullPath does not contain a valid object."
            $res = 1
        }
    } else {
        Write-Error "$handlerEnvironmentFullPath file not found."
        $res = 1
    }

    return $res
}

function Report-Status {
    param (
        [string]$name,
        [string]$operation,
        [string]$status,
        [int]$statusCode,
        [string]$statusMessage
    )

    Write-Log -level $LogLevelInfo -message "Report-Status($name, $operation, $status, $statusCode, $statusMessage)"

    # Retrieve the SequenceNumber from the process' environment variable.
	$lastSequenceNumber = Get-EnvironmentVariable($VmAgentEnvVar_SEQUENCE_NO)

    # Construct the status JSON object
    $statusObject = @(@{
        version = "1.0"
        timestampUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = @{
            name = $name
            operation = $operation
            status = $status
            code = $statusCode
            formattedMessage = @{
                lang = "en-US"
                message = $statusMessage
            }
        }
    })
    
    # Convert the status object to JSON
    $statusJson = ConvertTo-Json $statusObject -Depth 5

    # Write the JSON to the .status file with the name of the latest .settings file.
    $statusFileName = [System.IO.Path]::ChangeExtension($lastSequenceNumber, ".status")
    $statusFilePath = Join-Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)" $statusFileName
    $statusJson | Set-Content -Path $statusFilePath

    Write-Log -level $LogLevelInfo -message "Status file generated: $statusFilePath"
}

function Delete-Ebpf-Tracing-Tasks {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Delete-Ebpf-Tracing-Tasks($installDirectory)"

    # Firstly, lets stop the tracing providers
    $scriptPath = Join-Path $installDirectory $EbpfTracingTaskCmd
    if (Test-Path $scriptPath -PathType Leaf) {
        $output = & "$scriptPath" stop /trace_path "$EbpfTracingPath"
        if ($LASTEXITCODE -ne 0) {
            Write-Log -level $LogLevelWarning -message "FAILED stopping tracing. Error message: $output"
        } else {
            Write-Log -level $LogLevelInfo -message "SUCCESS stopping tracing."
        }
    } else {
        Write-Log -level $LogLevelError -message "Tracing script not found '$scriptPath'."
        return -1
    }

    # Lastly, lets delete the scheduled tasks
    $tasks = $EbpfTracingStartupTaskName, $EbpfTracingPeriodicTaskName
    foreach ($task in $tasks) {
        try {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Log -level $LogLevelInfo -message "SUCCESS deleting the '$task' task."
        } catch {
            Write-Log -level $LogLevelWarning -message "eBPF tracing task '$task' may not exist, no action taken. Error message: $($_.Exception.Message)"
        }
    }

    return 0
}

function Create-Ebpf-Tracing-Tasks {
    param (
        [string]$installDirectory
    )
    Write-Log -level $LogLevelInfo -message "Create-Ebpf-Tracing-Tasks($installDirectory)"

    Delete-Ebpf-Tracing-Tasks -installDirectory $installDirectory | Out-Null

    $res = Create-Scheduled-Task -installDirectory $installDirectory -taskName $EbpfTracingStartupTaskName -taskFile $EbpfTracingStartupTaskFilename
    if ($res -eq 0) {
        $res = Create-Scheduled-Task -installDirectory $installDirectory -taskName $EbpfTracingPeriodicTaskName -taskFile $EbpfTracingPeriodicTaskFilename
    } else {
        Delete-Ebpf-Tracing-Tasks -installDirectory $installDirectory | Out-Null
    }

    return $res
}

function Enable-EbpfTracing {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Enable-EbpfTracing($installDirectory)"
    return Create-Ebpf-Tracing-Tasks -installDirectory $installDirectory
}

function Disable-EbpfTracing {    
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Disable-EbpfTracing($installDirectory)"

    Delete-Ebpf-Tracing-Tasks -installDirectory $installDirectory | Out-Null
}

function Register-EbpfNetshExtension{
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Register-EbpfNetshExtension($installDirectory)"
    Push-Location -Path $installDirectory

    # Add the eBPF netsh helper.
    $installResult = & "netsh.exe" add helper $EbpfNetshExtensionName

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "'$EbpfNetshExtensionName' registered successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to register '$EbpfNetshExtensionName'. Error message: $installResult"
    }

    Pop-Location
    return $LASTEXITCODE
}

function Unregister-EbpfNetshExtension{

    Write-Log -level $LogLevelInfo -message "Unregister-EbpfNetshExtension"
    Push-Location -Path $EbpfDefaultInstallPath

    # Add the eBPF netsh helper.
    $installResult = & "netsh.exe" delete helper $EbpfNetshExtensionName

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "'$EbpfNetshExtensionName' unregistered successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to unregister '$EbpfNetshExtensionName'. Error message: $installResult"
    }

    Pop-Location
    return $LASTEXITCODE
}

function Stop-eBPFDrivers {

    Write-Log -level $LogLevelInfo -message "Stop-eBPFDrivers()"

    $statusCode = 0
    $originalStartupType = @{} # Store original startup types

    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key

        # Store the original startup type.
        $originalStartupType[$driverName] = (Get-WmiObject -Class Win32_BaseService -Filter "Name='$driverName'").StartMode

        # First, disable the driver, so that it doesn't eventually get restarted again after we stop it (i.e triggered by a service having a dependency).
        Set-Service -Name $driverName -StartupType Disabled -ErrorAction SilentlyContinue
        if ($?) {
            Write-Log -level $LogLevelInfo -message "Disabled driver: $driverName"
        
            # Then, stop the driver.
            Stop-Service -Name $driverName -Force -ErrorAction SilentlyContinue
            if ($?) {
                Write-Log -level $LogLevelInfo -message "Stopped driver: $driverName"
            } else {
                Write-Log -level $LogLevelError -message "Failed to stop driver: $driverName"
                $statusCode = 1;
            }
        } else {
            # If disabling failed, attempt to revert to the original startup type.
            Set-Service -Name $driverName -StartupType $originalStartupType[$driverName] -ErrorAction SilentlyContinue
            Write-Log -level $LogLevelError -message "Failed to disable driver: $driverName"
            $statusCode = 1;
        }
    }

    return [int]$statusCode
}


function Install-eBPF {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "Install-eBPF($sourcePath, $destinationPath)"

    # Copy the eBPF files to the destination folder.
    $copyResult = Copy-Directory -sourcePath "$sourcePath\bin" -destinationPath $destinationPath
    if ($copyResult -eq 0) {

        # Install the eBPF services and use the results to generate the status file  .      
        $failedServices = @() 
        $EbpfDrivers.GetEnumerator() | ForEach-Object {
            $driverName = $_.Key
            $installResult = Install-Driver -serviceName $driverName -servicePath "$destinationPath\drivers\$driverName.sys"
            if ($installResult -ne 0) {
                $failedServices += $driverName
            }
        }

        # Determine the overall installation status.
        if ($failedServices.Length -eq 0) {

            # Add the eBPF installation directory to the system PATH.
            Add-DirectoryToSystemPath -directoryPath $destinationPath | Out-Null 

            # Register the netsh extension.
            Register-EbpfNetshExtension -installDirectory $destinationPath | Out-Null 
               
            # Register the trace providers.
            Enable-EbpfTracing -installDirectory $destinationPath | Out-Null 

            $statusCode = 0
            Write-Log -level $LogLevelInfo -message "eBPF for Windows installed successfully."
        } else {
            $statusCode = 1
            $failedServicesString = $failedServices -join ", "
            Write-Log -level $LogLevelError -message "Failed to install service(s): $failedServicesString -> reverting registration for the ones that succeded."

            # Uninstall any eBPF drivers.
            $EbpfDrivers.GetEnumerator() | ForEach-Object {
                Uninstall-Driver -serviceName $_.Key | Out-Null
            }
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

    Write-Log -level $LogLevelInfo -message "Uninstall-eBPF($installDirectory)"
    
    # Stop all eBPF drivers (which will stop all the services which have a dependency on them).
    Stop-eBPFDrivers | Out-Null 

    # De-register the netsh extension
    Unregister-EbpfNetshExtension | Out-Null 

    # Uninstall the eBPF services and use the results to generate the log message.
    $failedServices = @() 
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key
        $uninstallResult = Uninstall-Driver -serviceName $driverName
        if ($uninstallResult -ne 0) {
            $failedServices += $driverName
        }
    }

    # Determine the overall installation status
    if ($failedServices.Length -eq 0) {
        $statusCode = 0
        Write-Log -level $LogLevelInfo -message "eBPF for Windows uninstalled successfully."
    } else {
        $statusCode = 1
        $failedServicesString = $failedServices -join ", "
        Write-Log -level $LogLevelError -message "Failed to uninstall service(s): $failedServicesString."
    }
    
    # Unregister the trace providers
    Disable-EbpfTracing -installDirectory $installDirectory | Out-Null 

    # Remove the eBPF installation directory from the system PATH
    Remove-DirectoryFromSystemPath -directoryPath $installDirectory | Out-Null 

    # Delete the eBPF files
    Delete-Directory -destinationPath $installDirectory | Out-Null

    return [int]$statusCode
}

function Upgrade-eBPF {
    param (
        [string]$operationName,
        [string]$currProductVersion,
        [string]$newProductVersion,
        [string]$installDirectory
    )
    
    Write-Log -level $LogLevelInfo -message "Upgrade-eBPF($operationName, $currProductVersion, $newProductVersion, $installDirectory)"

    if (Is-Upgrade-Supported) {
        Write-Log -level $LogLevelInfo -message "Performing eBPF [$operationName]."

        # For the moment, we just uninstall and install from/to the given installation folder.
        $statusCode = Uninstall-eBPF-Handler -installDirectory "$installDirectory" -createStatusFile $false
        if ($statusCode -ne 0) {
            $statusMessage = "eBPF $operationName FAILED (Uninstall failed)."
            Write-Log -level $LogLevelError -message $statusMessage
        } else {
            Write-Log -level $LogLevelInfo -message "eBPF v$currProductVersion uninstalled successfully."
            $statusCode = Install-eBPF -sourcePath "$EbpfPackagePath" -destinationPath "$installDirectory"
            if ($statusCode -ne 0) {
                $statusMessage = "eBPF $operationName FAILED (Install failed)."
                Write-Log -level $LogLevelError -message $statusMessage
            } else {
                $statusMessage = "eBPF $operationName succeeded."
                Write-Log -level $LogLevelInfo -message $statusMessage
            }
        } 
    } else {       
        $statusCode = 1
        Write-Log -level $LogLevelError -message "eBPF [$operationName] not allowed in the current environment."
    }

    return [int]$statusCode
}

function InstallOrUpdate-eBPF {
    param (
        [string]$operationName,
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "InstallOrUpdate-eBPF($operationName, $sourcePath, $destinationPath)"

    # Set the default product version to NULL (i.e. not installed).
    $currProductVersion = $null

    # This function is flexible to uninstall/install/upgrade to a different path than the iven one, for those scenarios where the driver is registered from a different folder.
    $currInstallPath = $destinationPath

    # Retrieve the product version of the driver in the extension package (anyone will do, as they should all have the same product version, so we don't have to hardcode a specific driver name)
    # Note: the "install" command is always run on the *new* version of the handler, so we can retrieve the target product version of the driver in the extension package.
    $EbpfDriverName = ($EbpfDrivers.GetEnumerator() | Select-Object -First 1).Key
    $newProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path "$sourcePath\bin" -ChildPath "drivers\$EbpfDriverName.sys")
    
    # Firstly, check if the eBPF driver is installed and registered (as a test for eBPF to be installed).
    $currDriverPath = Get-FullDiskPathFromService -serviceName $EbpfDriverName
    if ($currDriverPath) {
        Write-Log -level $LogLevelInfo -message "Found eBPF driver installed and registered from: '$currDriverPath'"

        # TBC: check if the driver is registered in the default folder, if not, log a warning and proceed with the installation in the current folder.
        $currInstallPath = Split-Path -Path $currDriverPath -Parent | Split-Path -Parent
        if ($currInstallPath -ne $EbpfDefaultInstallPath) {
            Write-Log -level $LogLevelWarning -message "'$EbpfDriverName' driver registered from a non-default folder: [$currInstallPath] instead of [$EbpfDefaultInstallPath]"
        }

        # Retrieve the product version of the installed driver.
        $currProductVersion = Get-ProductVersionFromFile -filePath "$currDriverPath"

    } else {
        Write-Log -level $LogLevelWarning -message "'$EbpfDriverName' driver not registered on this machine, checking installation in the default folder..."

        # Check if there's a driver in the default installation folder, and get its product version.
        $currProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path $EbpfDefaultInstallPath -ChildPath "drivers\$EbpfDriverName.sys")
    }
    
    # If $currProductVersion has a value, then a version of eBPF is already installed, let's check if it needs to be updated.
    if ($null -ne $currProductVersion) {
        Write-Log -level $LogLevelInfo -message "Found eBPF v$currProductVersion already installed."

        $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
        if ($comparison -eq 2) {
            # If the product version is the same as the version distributed with the VM extension package, then we return a success code, as if the operation was successful.
            # This because it's a handler-only update, so we don't need to do anything to the current eBPF installation.
            $statusCode = 0
            $statusMessage = "This is a handler-only update to v($updateToVersion) -> no action taken."
            Write-Log -level $LogLevelInfo -message $statusMessage
        } else {

            # Depending on the version comparison, we either install/upgrade, downgrade or do nothing if the version is the same.
            $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
            if ($comparison -ne 0) {
                # If the product version is lower than the version distributed with the VM extension, then upgrade it.
                if ($comparison -gt 0) {
                    # If the product version is greater than the version distributed with the VM extension, then just issue a warning, but allow th downgrade.
                    $statusMessage = "WARNING: The installed eBPF version (v$currProductVersion) is newer than the one in the VM Extension package (v$newProductVersion) -> eBPF will be downgraded to (v$newProductVersion)!."
                    Write-Log -level $LogLevelWarning -message $statusMessage
                }
                [int]$statusCode = Upgrade-eBPF -operationName $operationName -currProductVersion $currProductVersion -newProductVersion $newProductVersion -installDirectory "$currInstallPath"
            } else {                
                # If eBPF is already installed with the same version, then we return a success code, as if the operation was successful.
                $statusCode = 0
                $statusMessage = "eBPF version is up to date (v$currProductVersion)."
                Write-Log -level $LogLevelInfo -message $statusMessage
            }
        }
    } else {
        Write-Log -level $LogLevelInfo -message "No eBPF installation found in [$destinationPath]: installing (v$newProductVersion)."
        
        # Proceed with a new installation from the artifact package within the extension ZIP file.
        $statusCode = Install-eBPF -sourcePath "$sourcePath" -destinationPath "$currInstallPath"
        if ($statusCode -ne 0) {
            Write-Log -level $LogLevelError -message "Failed to install eBPF v$newProductVersion."
            Report-Status -name $StatusName -operation $operationName -status $StatusError -statusCode 1 -statusMessage "eBPF $operationName FAILED (Clean install failed)."
        } else {
            Write-Log -level $LogLevelInfo -message "eBPF v$newProductVersion installed successfully."
            # If this was an 'Install' operation, the VM Agent will then call 'Enable' on the handler.
        }
    }

    return [int]$statusCode
}

function Restart-GuestProxyAgent-Service {

    Write-Log -level $LogLevelInfo -message "Restart-GuestProxyAgent-Service()"

    $res = 0
    $GuestProxyAgentServiceName = "GuestProxyAgent"
    try {
        $service = Get-Service -Name $GuestProxyAgentServiceName -ErrorAction Stop

        if ($null -eq $service) {
            Write-Log -level $LogLevelWarning -message "Service '$GuestProxyAgentServiceName' is not installed -> no action taken."
        } else {
            Write-Log -level $LogLevelInfo -message "Restarting service '$GuestProxyAgentServiceName'..."
            
            # Start the service in a background job
            $job = Start-Job -ScriptBlock {
                param($serviceName)
                Restart-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            } -ArgumentList $GuestProxyAgentServiceName

            # Wait for the service to start, or timeout.
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            while ((Get-Service -Name $GuestProxyAgentServiceName).Status -ne 'Running') {
                if ($stopwatch.Elapsed.TotalSeconds -ge $EbpfStartTimeoutSeconds) {
                    Write-Log -level $LogLevelError -message "Timeout while restarting [$GuestProxyAgentServiceName] (> $EbpfStartTimeoutSeconds seconds)"
                    Stop-Job -Job $job
                    Remove-Job -Job $job
                    $res = 1
                    break
                }
                Start-Sleep -MilliSeconds 100 # releaf the CPU
            }
            $stopwatch.Stop()

            if ($res -eq 0) {
                Write-Log -level $LogLevelInfo -message "Service '$GuestProxyAgentServiceName' was successfully restarted."
            }
        }
    }
    catch {
        $res = 1
        Write-Log -level $LogLevelError -message "An error occurred while restarting service '$GuestProxyAgentServiceName': $_"
    }

    return [int]$res
}

#######################################################
# VM Extension Handler Functions
#######################################################
function Reset-eBPF-Handler {
    Write-Log -level $LogLevelInfo -message "Reset-eBPF-Handler() -> NOP"
    
    # NOP for this current implementation.
    # Reset does not need to generate a status file.
    return 0
}

function Enable-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Enable-eBPF-Handler()"

    $statusInfo = [PSCustomObject]@{
        StatusCode = 0
        StatusString = $StatusSuccess
    }

    try {
        # Check if the eBPF drivers are registered correctly, and start them.
        $EbpfDrivers.GetEnumerator() | ForEach-Object {
            $driverName = $_.Key
            $currDriverPath = Get-FullDiskPathFromService -serviceName $driverName
            if ($currDriverPath) {
                if ($?) {
                    Write-Log -level $LogLevelInfo -message "[$driverName] is registered correctly, starting the driver service..."
                    
                    # Start the service in a background job
                    $job = Start-Job -ScriptBlock {
                        param($driverName)
                        Start-Service -Name $driverName -ErrorAction SilentlyContinue
                    } -ArgumentList $driverName

                    # Wait for the service to start, or timeout.                
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    while ((Get-Service -Name $driverName).Status -ne 'Running') {
                        if ($stopwatch.Elapsed.TotalSeconds -ge $EbpfStartTimeoutSeconds) {
                            Write-Log -level $LogLevelError -message "Timeout while starting driver [$driverName] (> $EbpfStartTimeoutSeconds seconds)"
                            Stop-Job -Job $job
                            Remove-Job -Job $job
                            $statusInfo.StatusCode = 1
                            $statusInfo.StatusString = $StatusError
                            break
                        }
                        Start-Sleep -MilliSeconds 100 # releaf the CPU
                    }
                    $stopwatch.Stop()

                    if ($statusInfo.StatusCode -eq 0) {
                        Write-Log -level $LogLevelInfo -message "Started driver [$driverName]"
                    }
                } else {
                    Write-Log -level $LogLevelError -message "[$driverName] is NOT registered correctly!"
                    $statusInfo.StatusCode = 1
                    $statusInfo.StatusString = $StatusError
                }
            }
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while starting the eBPF drivers: $_"
        $statusInfo.StatusCode = 1
        $statusInfo.StatusString = $StatusError
    }

    # Check if the eBPF drivers were started correctly, otherwise stop them and return an error.
    if ($statusInfo.StatusCode -eq 0) {
        # If the eBPF drivers are started successfully, we need to restart the GuestProxyAgent service.
        $res = Restart-GuestProxyAgent-Service
        if ($res -ne 0) {            
            Write-Log -level $LogLevelError -message "eBPF was successfully installed, but restarting the GuestProxyAgent service FAILED -> Failing the overall operation."
            $statusInfo.StatusCode = 2
            $statusInfo.StatusString = $StatusError
        }
    } else {
        Stop-eBPFDrivers | Out-Null
        $statusInfo.StatusCode = 1
        $statusInfo.StatusString = $StatusError
    }

    # Generate the status file
    Report-Status -name $StatusName -operation $OperationNameEnable -status $statusInfo.StatusString -statusCode $statusInfo.StatusCode -statusMessage "eBPF enabled"

    return [int]$statusInfo.StatusCode
}

function Disable-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Disable-eBPF-Handler()"

    # Disable does not need to generate a status file.
    $statusCode = Stop-eBPFDrivers
   
    return [int]$statusCode
}

function Uninstall-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Uninstall-eBPF-Handler()"

    $statusCode = Uninstall-eBPF -installDirectory "$EbpfDefaultInstallPath"
   
    return [int]$statusCode
}

function Install-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Install-eBPF-Handler()"

    # Install or Update eBPF for Windows.
    # NOTE: The install operation does not generate a status file, since the VM Agent will afterwards call the enable operation.
    return InstallOrUpdate-eBPF -operationName $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
}

function Update-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Update-eBPF-Handler() -> NOP"

    # NOP for this current implementation.
    # Update does not need to generate a status file.
    return 0
}

#######################################################
# Main entry point
#######################################################
# Call the Get-HandlerEnvironment function, capture the output and set the global environment variable.
Get-HandlerEnvironment -handlerEnvironmentFullPath "$DefaultHandlerEnvironmentFilePath" | Out-Null
