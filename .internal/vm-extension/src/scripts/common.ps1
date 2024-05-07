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
Set-Variable -Name "EbpfBackupPath" -Value "$env:TEMP\ebpf_backup"
Set-Variable -Name "EbpfRegistryPath" -Value "HKLM:\Software\eBPF"
Set-Variable -Name "EbpfDisableRuntimeUpdateRegistryKey" -Value "EbpfDisableRuntimeUpdate"
Set-Variable -Name "EbpfStartTimeoutSeconds" -Value 60
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
}

# Define the eBPF Handler registry key for handling VM Agent's stateless calls on Auto-Update.
Set-Variable -Name "WindowsAzureRegistryPath" -Value "HKLM:\SOFTWARE\Microsoft\Windows Azure"
Set-Variable -Name "WindowsAzureEbpfUpgradingRegistryKey" -Value "EbpfUpgrading"

# eBPF Handler return codes (any non-zero value will be treated as an error by the VM Agent).
Set-Variable -Name "EbpfStatusCode_SUCCESS" -Value 0
Set-Variable -Name "EbpfStatusCode_ERROR" -Value 1001
Set-Variable -Name "EbpfStatusCode_BAD_ENV_FILE" -Value 1002
Set-Variable -Name "EbpfStatusCode_ENV_FILE_NOT_FOUND" -Value 1003
Set-Variable -Name "EbpfStatusCode_INSTALLATION_DOWNGRADE_UNALLOWED" -Value 1005
Set-Variable -Name "EbpfStatusCode_INSTALLATION_UNALLOWED" -Value 1006
Set-Variable -Name "EbpfStatusCode_COPY_FAILED" -Value 1007
Set-Variable -Name "EbpfStatusCode_DELETE_DIR_FAILED" -Value 1008
Set-Variable -Name "EbpfStatusCode_CREATE_DIR_FAILED" -Value 1009
Set-Variable -Name "EbpfStatusCode_FIND_DIR_FAILED" -Value 1010
Set-Variable -Name "EbpfStatusCode_CREATE_TASK_FAILED" -Value 1011
Set-Variable -Name "EbpfStatusCode_DELETE_TASK_FAILED" -Value 1012
Set-Variable -Name "EbpfStatusCode_STARTING_DRIVER_FAILED" -Value 1013
Set-Variable -Name "EbpfStatusCode_STOPPING_DRIVER_FAILED" -Value 1014
Set-Variable -Name "EbpfStatusCode_DISABLING_DRIVER_FAILED" -Value 1015
Set-Variable -Name "EbpfStatusCode_INSTALLING_DRIVER_FAILED" -Value 1016
Set-Variable -Name "EbpfStatusCode_UNINSTALLING_DRIVER_FAILED" -Value 1017
Set-Variable -Name "EbpfStatusCode_REGISTERING_NETSH_EXTENSION_FAILED" -Value 1018
Set-Variable -Name "EbpfStatusCode_UNREGISTERING_NETSH_EXTENSION_FAILED" -Value 1019
Set-Variable -Name "EbpfStatusCode_RESTARTING_SERVICE_FAILED" -Value 1020
Set-Variable -Name "EbpfStatusCode_COMPONENTS_IN_USE" -Value 1021

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
        return $EbpfStatusCode_ERROR
    }
    
    return $EbpfStatusCode_SUCCESS
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

function Get-FullDiskPathFromService {
    param (
        [string]$serviceName
    )

    Write-Log -level $LogLevelInfo -message "Get-FullDiskPathFromService($serviceName)"

    try {
        # Define the registry path
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        
        # Check if the registry key exists
        if (Test-Path $registryPath) {
            # Retrieve the BINARY_PATH_NAME value from the registry
            $binaryPath = Get-ItemProperty -Path $registryPath -Name ImagePath | Select-Object -ExpandProperty ImagePath
            if ($binaryPath -match '(?<=\\)\w:.+') {
                return $matches[0]
            }
        } else {
            Write-Log -level $LogLevelWarning -message "Service '$serviceName' is not installed -> no action taken."
        }
    }  catch {
        Write-Log -level $LogLevelError-message "An error occurred while retrieving the registry key for service '$serviceName': $_"
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

# Compare-VersionNumbers compares two version numbers in the format "major.minor.patch.hotfix" and returns:
#    0 - if version1 == version2
#   -1 - if version1 < version2
#    1 - if version1 > version2
#    2 - if version1 and version2 are equal up to the 3rd digit (i.e. the patch number)
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
        return $EbpfStatusCode_ERROR
    }

    return $EbpfStatusCode_SUCCESS
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
        return $EbpfStatusCode_ERROR
    }

    return $EbpfStatusCode_SUCCESS
}

function Install-Driver {
    param (
        [string]$serviceName,
        [string]$servicePath
    )

    Write-Log -level $LogLevelInfo -message "Install-Driver($serviceName, $servicePath)"
    $res = $EbpfStatusCode_SUCCESS

    try {
        # Create the service using sc.exe (you'll need to replace this with the actual command).
        $scCreateOutput = & "sc.exe" create $serviceName type=kernel start=auto binPath="$servicePath"

        # Check the exit code to determine the result.
        if ($LASTEXITCODE -eq 0) {            
            Write-Log -level $LogLevelInfo -message "'$serviceName' installed successfully."
        } else {
            $res = $EbpfStatusCode_INSTALLING_DRIVER_FAILED
            Write-Log -level $LogLevelError -message "Failed to install '$serviceName'. ErrorCode: $LASTEXITCODE, Error message: $scCreateOutput"
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while installing '$serviceName': $_"
    }

    return $res
}

function Uninstall-Driver {
    param (
        [string]$serviceName
    )

    Write-Log -level $LogLevelInfo -message "Uninstall-Driver($serviceName)"
    $res = $EbpfStatusCode_SUCCESS

    try {
        Write-Log -level $LogLevelInfo -message "Uninstall-Driver($serviceName)"
    
        # Delete the driver service
        $scDeleteOutput = & "sc.exe" delete $serviceName

        # Check the exit code to determine the result.
        if ($LASTEXITCODE -eq 0) {
            Write-Log -level $LogLevelInfo -message "'$serviceName' uninstalled successfully."
        } else {
            $res = $EbpfStatusCode_UNINSTALLING_DRIVER_FAILED
            Write-Log -level $LogLevelError -message "Failed to uninstall '$serviceName'. ErrorCode: $LASTEXITCODE, Error message: $scDeleteOutput"      
        }
    }
    catch {
        Write-Log -level $LogLevelError -message "An error occurred while installing '$serviceName': $_"
    }

    return $res
}

function Restart-Service-Retry {
    param (
        [string]$ServiceName
    )

    Write-Log -level $LogLevelInfo -message "Restart-Service-Retry($ServiceName)"

    $res = $EbpfStatusCode_SUCCESS
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($null -eq $service) {
            $res = $EbpfStatusCode_NOT_FOUND
            Write-Log -level $LogLevelWarning -message "Service '$ServiceName' is not installed -> no action taken."
        } else {
            Write-Log -level $LogLevelInfo -message "Restarting service '$ServiceName'..."
            
            # Start the service in a background job
            $job = Start-Job -ScriptBlock {
                param($serviceName)
                Restart-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            } -ArgumentList $ServiceName

            # Wait for the service to start, or timeout.            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            while ((Get-Service -Name $ServiceName).Status -ne 'Running') {
                if ($stopwatch.Elapsed.TotalSeconds -ge $EbpfStartTimeoutSeconds) {
                    Write-Log -level $LogLevelError -message "Timeout while restarting [$ServiceName] (> $EbpfStartTimeoutSeconds seconds)"
                    Stop-Job -Job $job
                    Remove-Job -Job $job
                    $res = $EbpfStatusCode_RESTARTING_SERVICE_FAILED
                    break
                }
                Start-Sleep -MilliSeconds 100 # releaf the CPU
            }
            $stopwatch.Stop()

            if ($res -eq $EbpfStatusCode_SUCCESS) {
                Write-Log -level $LogLevelInfo -message "Service '$ServiceName' was successfully restarted."
            }
        }
    }
    catch {
        $res = $EbpfStatusCode_RESTARTING_SERVICE_FAILED
        Write-Log -level $LogLevelError -message "An error occurred while restarting service '$ServiceName': $_"
    }

    return [int]$res
}

function Copy-Directory {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "Copy-Directory($sourcePath, $destinationPath)"
    $res = $EbpfStatusCode_SUCCESS

    # Create the destination directory, if it doesn't exist.
    if (-not (Test-Path $destinationPath)) {
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop | Out-Null
        } catch {
            Write-Log -level $LogLevelError -message "Failed to create destination directory '$destinationPath': $_"
            $res = $EbpfStatusCode_CREATE_DIR_FAILED
        }
    }

    # Recursively copy all files from source to destination.
    try {
        Copy-Item -Path ($sourcePath + "\*") -Destination $destinationPath -Recurse -Force -ErrorAction Stop | Out-Null
        Write-Log -level $LogLevelInfo -message "Files copied from '$sourcePath' to '$destinationPath'."
    } catch {
        Write-Log -level $LogLevelError -message "Error while copying files: $_"
        $res = $EbpfStatusCode_COPY_FAILED
    }
    
    return $res
}

function Delete-Directory {
    param (
        [string]$destinationPath
    )
    
    Write-Log -level $LogLevelInfo -message "Delete-Directory($destinationPath)"
    $res = $EbpfStatusCode_SUCCESS

    if (Test-Path $destinationPath) {
        try {
            Remove-Item -Path $destinationPath -Recurse -Force -ErrorAction Stop
            Write-Log -level $LogLevelInfo -message "Directory '$destinationPath' deleted successfully."            
        } catch {
            Write-Log -level $LogLevelError -message "Failed to delete directory '$destinationPath'. Error: $_"
            $res = $EbpfStatusCode_DELETE_DIR_FAILED
        }
    } else {
        Write-Log -level $LogLevelWarning -message "Directory '$destinationPath' does not exist."
        $res = $EbpfStatusCode_FIND_DIR_FAILED
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
        Write-Log -level $LogLevelError -message "FAILED setting up the '$taskName' task. Error Code: $($_.Exception.HResult) Error message: $($_.Exception.Message)"
        return $EbpfStatusCode_CREATE_TASK_FAILED
    }

    return $EbpfStatusCode_SUCCESS
}

#######################################################
# VM Extension Handler Internal Helper Functions
#######################################################
function Get-HandlerEnvironment {
    param (
        # The HandlerEnvironment.json file is always located in the root of where the ZIP package is extracted.
        [string]$handlerEnvironmentFullPath = "$DefaultHandlerEnvironmentFilePath"
    )

    $res = $EbpfStatusCode_SUCCESS
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
            $res = $EbpfStatusCode_BAD_ENV_FILE
        }
    } else {
        Write-Error "$handlerEnvironmentFullPath file not found."
        $res = $EbpfStatusCode_ENV_FILE_NOT_FOUND
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

function Is-InstallOrUpdate-Supported {
    # This function will return true if the upgrade is allowed in the current environment, false otherwise.
    # Currently, it is a placeholder for future requirements.

    Write-Log -level $LogLevelInfo -message "Is-InstallOrUpdate-Supported()"

    # Retrieve the registry key value
    $keyValue = (Get-ItemProperty -Path $EbpfRegistryPath -Name $EbpfDisableRuntimeUpdateRegistryKey).EbpfDisableRuntimeUpdate
    If ($null -eq $keyValue) {
        Write-Log -level $LogLevelWarning -message "The registry key '$EbpfDisableRuntimeUpdateRegistryKey' does not exist -> Install or Update are allowed by default."
    } else {
        if ($keyValue -ne 0) {
            Write-Log -level $LogLevelError -message "The registry key '$EbpfDisableRuntimeUpdateRegistryKey' is set to '$keyValue' (non-zero) -> Install or Update are NOT allowed."
            return $false
        }
        Write-Log -level $LogLevelInfo -message "Install or Update are allowed in the current environment."
    }

    return $true
}

function eBPF-Components-In-Use {
    # This function will return true if the eBPF components are in use, false otherwise.

    Write-Log -level $LogLevelInfo -message "eBPF-Components-In-Use()"

    # TBD: Check if the eBPF components are in use
    # - Check if there are any programs or maps loaded (i.e. via 'netsh ebpf')
    # - Stop eBPF drivers, so that no new programs or maps can be loaded
    # - Check if there are any handles to EbpfApi.dll (i.e. UM applications using the eBPF API)
    #   - If there are, restart the drivers and return $true
    # - If there are no handles to the EbpfApi.dll, then we can update the eBPF components, return $false
    #   - If there are, return $true

    return $false
}

function Set-EbpfUpdatingFlag {
    param (
        [switch]$SetFlag,
        [switch]$ResetFlag
    )

    try {
        if ($SetFlag) {
            # Create or update the registry key
            New-Item -Path $WindowsAzureRegistryPath -Name $WindowsAzureEbpfUpgradingRegistryKey -Force | Out-Null
            Write-Log -Level $LogLevelInfo -Message "$WindowsAzureEbpfUpgradingRegistryKey flag set successfully."
            return $EbpfStatusCode_SUCCESS
        }
        elseif ($ResetFlag) {
            # Remove the registry key
            $fullRegistryPath = Join-Path $WindowsAzureRegistryPath $WindowsAzureEbpfUpgradingRegistryKey
            Remove-Item -Path $fullRegistryPath -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Level $LogLevelInfo -Message "$WindowsAzureEbpfUpgradingRegistryKey flag reset successfully."
            return $EbpfStatusCode_SUCCESS
        }
        else {
            Write-Log -Level $LogLevelError -Message "Please specify either -SetFlag or -ResetFlag switch."
        }
    }
    catch {
        Write-Log -Level $LogLevelError -Message "Error: $_"
    }

    return $EbpfStatusCode_ERROR
}

function Get-EbpfUpdatingFlag {
    $fullRegistryPath = Join-Path $WindowsAzureRegistryPath $WindowsAzureEbpfUpgradingRegistryKey

    # Check if the registry key exists
    $flagSet = Test-Path $fullRegistryPath

    return $flagSet
}

function Get-EbpfVersionInfo {
    param (
        
        [string]$sourcePath,
        [string]$destinationPath
    )

    # Define a version info object.
    $versionInfo = [PSCustomObject]@{
        currInstallPath = $destinationPath
        currDriverPath = $null
        currProductVersion = $null
        newProductVersion = $null
        comparison = -1
    }

    # Retrieve the product version of the driver in the extension package (anyone will do, as they should all have the same product version, so we don't have to hardcode a specific driver name)
    # Note: the "install" command is always run on the *new* version of the handler, so we can retrieve the target product version of the driver in the extension package.
    $EbpfDriverName = ($EbpfDrivers.GetEnumerator() | Select-Object -First 1).Key
    $versionInfo.newProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path "$sourcePath" -ChildPath "drivers\$EbpfDriverName.sys")

    # Firstly, check if the eBPF driver is installed and registered (as a test for eBPF to be installed).
    $versionInfo.currDriverPath = Get-FullDiskPathFromService -serviceName $EbpfDriverName
    if ($null -ne $currDriverPath) {
        # Check if the driver is registered in the default folder, if not, log a warning and proceed with the installation in the current folder.
        $versionInfo.currInstallPath = Split-Path -Path $versionInfo.currDriverPath -Parent | Split-Path -Parent
        if ($versionInfo.currInstallPath -ne $EbpfDefaultInstallPath) {
            Write-Log -level $LogLevelWarning -message "'$EbpfDriverName' driver registered from a non-default folder: '$($versionInfo.currInstallPath)' instead of [$EbpfDefaultInstallPath]"
        }

        # Retrieve the product version of the installed driver.
        $versionInfo.currProductVersion = Get-ProductVersionFromFile -filePath "$($versionInfo.currDriverPath)"
        Write-Log -level $LogLevelInfo -message "Found eBPF '$EbpfDriverName' driver v$($versionInfo.currProductVersion) installed and registered from: '$($versionInfo.currDriverPath)'."
    } else {
        # If no eBPF driver is registered, before proceeding with a new installation from the artifact package within the extension's ZIP file,
        # we check if there's a previous installation in the default installation folder, and if so, we use that as the current installation path.
        Write-Log -level $LogLevelInfo -message "No '$EbpfDriverName' driver registered on this machine. Checking if there's a driver in the default installation folder: '$EbpfDefaultInstallPath'..."
        $versionInfo.currProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path $EbpfDefaultInstallPath -ChildPath "drivers\$EbpfDriverName.sys")
        if ($versionInfo.currProductVersion) {
            Write-Log -level $LogLevelInfo -message "Found eBPF '$EbpfDriverName' driver v$($versionInfo.currProductVersion) installed in the default installation folder: '$EbpfDefaultInstallPath'."
            $versionInfo.currInstallPath = $EbpfDefaultInstallPath
        } else {
            Write-Log -level $LogLevelInfo -message "No '$EbpfDriverName' driver found in the default installation folder: '$EbpfDefaultInstallPath'."
        }
    }

    # If there's a version of eBPF installed, compare the product version of the installed driver with the one in the extension package.
    if ($null -ne $versionInfo.currProductVersion) {
        $versionInfo.comparison = Compare-VersionNumbers -version1 $versionInfo.currProductVersion -version2 $versionInfo.newProductVersion
    }

    return $versionInfo
}

function Delete-EbpfTracingTasks {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Delete-EbpfTracingTasks($installDirectory)"

    # In accounting that files & tasks could be manually deleted, we go through all the steps and just log any errors.
    $res = $EbpfStatusCode_SUCCESS

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

    return $res
}

function Create-EbpfTracingTasks {
    param (
        [string]$installDirectory
    )
    Write-Log -level $LogLevelInfo -message "Create-EbpfTracingTasks($installDirectory)"

    Delete-EbpfTracingTasks -installDirectory $installDirectory | Out-Null

    $res = Create-Scheduled-Task -installDirectory $installDirectory -taskName $EbpfTracingStartupTaskName -taskFile $EbpfTracingStartupTaskFilename
    if ($res -eq  $EbpfStatusCode_SUCCESS) {
        $res = Create-Scheduled-Task -installDirectory $installDirectory -taskName $EbpfTracingPeriodicTaskName -taskFile $EbpfTracingPeriodicTaskFilename
    } else {
        Delete-EbpfTracingTasks -installDirectory $installDirectory | Out-Null
    }

    return $res
}

function Enable-EbpfTracing {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Enable-EbpfTracing($installDirectory)"
    return Create-EbpfTracingTasks -installDirectory $installDirectory
}

function Disable-EbpfTracing {    
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Disable-EbpfTracing($installDirectory)"
    return Delete-EbpfTracingTasks -installDirectory $installDirectory
}

function Register-EbpfNetshExtension{
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Register-EbpfNetshExtension($installDirectory)"
    $res = $EbpfStatusCode_SUCCESS

    Push-Location -Path $installDirectory

    # Add the eBPF netsh helper.
    $installResult = & "netsh.exe" add helper $EbpfNetshExtensionName

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "'$EbpfNetshExtensionName' registered successfully."
    } else {
        $res = $EbpfStatusCode_REGISTERING_NETSH_EXTENSION_FAILED
        Write-Log -level $LogLevelError -message "Failed to register '$EbpfNetshExtensionName'. Error message: $installResult"
    }

    Pop-Location
    return $res
}

function Unregister-EbpfNetshExtension{

    Write-Log -level $LogLevelInfo -message "Unregister-EbpfNetshExtension"
    $res = $EbpfStatusCode_SUCCESS
    Push-Location -Path $EbpfDefaultInstallPath

    # Add the eBPF netsh helper.
    $installResult = & "netsh.exe" delete helper $EbpfNetshExtensionName

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "'$EbpfNetshExtensionName' unregistered successfully."
    } else {
        $res = $EbpfStatusCode_UNREGISTERING_NETSH_EXTENSION_FAILED
        Write-Log -level $LogLevelError -message "Failed to unregister '$EbpfNetshExtensionName'. Error message: $installResult"
    }

    Pop-Location
    return $res
}

function Restart-GuestProxyAgent {

    Write-Log -level $LogLevelInfo -message "Restart-GuestProxyAgent()"

    $serviceName = "GuestProxyAgent"
    $res = Restart-Service-Retry -ServiceName $serviceName

    # If the service is not found, we return success.
    if ($res -eq $EbpfStatusCode_SERVICE_NOT_FOUND) {
        $res = $EbpfStatusCode_SUCCESS
    }

    return [int]$res
}

function Start-EbpfDrivers {
    param(
        [bool]$restartGuestProxyAgentService = $false
    )

    Write-Log -level $LogLevelInfo -message "Start-EbpfDrivers($restartGuestProxyAgentService)"

    $statusInfo = [PSCustomObject]@{
        StatusCode = $EbpfStatusCode_SUCCESS
        StatusString = $StatusSuccess
        StatusMessage = "eBPF enabled"
    }

    try {
        # Check if the eBPF drivers are registered correctly, and start them.
        $EbpfDrivers.GetEnumerator() | ForEach-Object {
            $driverName = $_.Key
            $currDriverPath = Get-FullDiskPathFromService -serviceName $driverName
            if ($currDriverPath) {
                if ($?) {
                    Write-Log -level $LogLevelInfo -message "[$driverName] is registered correctly, starting the driver service..."

                    # Set the startup type to automatic.
                    Set-Service -Name $driverName -StartupType Automatic -ErrorAction SilentlyContinue
                    
                    # Start the service in a background job
                    $job = Start-Job -ScriptBlock {
                        param($driverName)
                        Start-Service -Name $driverName -ErrorAction SilentlyContinue
                    } -ArgumentList $driverName

                    # Wait for the service to start, or timeout.                
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    while ((Get-Service -Name $driverName).Status -ne 'Running') {
                        if ($stopwatch.Elapsed.TotalSeconds -ge $EbpfStartTimeoutSeconds) {
                            Stop-Job -Job $job
                            Remove-Job -Job $job
                            $statusInfo.StatusCode = $EbpfStatusCode_STARTING_DRIVER_FAILED
                            $statusInfo.StatusString = $StatusError
                            $statusInfo.StatusMessage = "Timeout while starting driver [$driverName] (> $EbpfStartTimeoutSeconds seconds)"
                            Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
                            break
                        }
                        Start-Sleep -MilliSeconds 100 # releaf the CPU
                    }
                    $stopwatch.Stop()

                    if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {
                        Write-Log -level $LogLevelInfo -message "Started driver [$driverName]"
                    }
                } else {
                    $statusInfo.StatusCode = $EbpfStatusCode_STARTING_DRIVER_FAILED
                    $statusInfo.StatusString = $StatusError
                    $statusInfo.StatusMessage = "[$driverName] is NOT registered correctly!"
                    Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
                }
            }
        }

        # If all drivers were started successfully, attempt to start the Guest Proxy Agent service.
        # Note: although restarting the GuestProxyAgent service is an extended operation that is not part of the eBPF VM Extension's scope,
        # it has a dependency on the eBPF drivers, so we need to make sure to start the Guest Proxy Agent service to ensure the VM's connectivity.
        # Therefore, we account success/failure of this operation in the overall result, so that the platform will stop rolling out updates to Azure VMs.
        if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {
            Write-Log -level $LogLevelInfo -message "eBPF drivers started successfully."
            if ($restartGuestProxyAgentService) {
                Write-Log -level $LogLevelInfo -message "Attempting to start the Guest Proxy Agent service..."
                $statusInfo.StatusCode = Restart-GuestProxyAgent
                if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {
                    $statusInfo.StatusString = $StatusSuccess
                    $statusInfo.StatusMessage = "Guest Proxy Agent service started successfully."
                    Write-Log -level $LogLevelInfo -message $statusInfo.StatusMessage
                } else {
                    $statusInfo.StatusString = $StatusError
                    $statusInfo.StatusMessage = "FAILED to start Guest Proxy Agent service."
                    Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
                }
            }
        } else {
            $statusInfo.StatusString = $StatusError
            $statusInfo.StatusMessage = "FAILED to start eBPF drivers."
            Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
        }
    }
    catch {
        $statusInfo.StatusCode = $EbpfStatusCode_STARTING_DRIVER_FAILED
        $statusInfo.StatusString = $StatusError
        $statusInfo.StatusMessage = "An error occurred while starting the eBPF drivers: $_"
        Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
    }

    return $statusInfo
}

function Stop-EbpfDrivers {

    Write-Log -level $LogLevelInfo -message "Stop-EbpfDrivers()"

    $statusCode = $EbpfStatusCode_SUCCESS
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
                $statusCode = $EbpfStatusCode_STOPPING_DRIVER_FAILED;
            }
        } else {
            # If disabling failed, attempt to revert to the original startup type.
            Set-Service -Name $driverName -StartupType $originalStartupType[$driverName] -ErrorAction SilentlyContinue
            Write-Log -level $LogLevelError -message "Failed to disable driver: $driverName"
            $statusCode = $EbpfStatusCode_DISABLING_DRIVER_FAILED;
        }
    }

    return [int]$statusCode
}

function Install-EbpfDrivers {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Install-EbpfDrivers($installDirectory)"

    $statusCode = $EbpfStatusCode_SUCCESS

    # Install the eBPF drivers and use the results to generate the log message.
    $failedServices = @() 
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key
        $installResult = Install-Driver -serviceName $driverName -servicePath "$installDirectory\drivers\$($_.Value)"
        if ($installResult -ne $EbpfStatusCode_SUCCESS) {
            $failedServices += $driverName
        }
    }
    if ($failedServices.Length -eq 0) {
        $statusCode = $EbpfStatusCode_SUCCESS
        Write-Log -level $LogLevelInfo -message "eBPF drivers installed successfully."
    } else {
        $statusCode = $EbpfStatusCode_INSTALLING_DRIVER_FAILED
        $failedServicesString = $failedServices -join ", "
        Write-Log -level $LogLevelError -message "Failed to install service(s): $failedServicesString."

        # If any of the drivers failed to install, attempt to uinstall the drivers that were successfully uninstalled.
        $failedServices | ForEach-Object {
            $driverName = $_
            $uninstallResult = Uninstall-Driver -serviceName $driverName
            if ($uninstallResult -ne 0) {
                Write-Log -level $LogLevelError -message "Failed to uninstall service: $driverName."
                $statusCode = $EbpfStatusCode_UNINSTALLING_DRIVER_FAILED
            }
        }
    }

    return [int]$statusCode
}

function Uninstall-EbpfDrivers {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Uninstall-EbpfDrivers($installDirectory)"

    # First, stop the drivers
    $statusCode = Stop-EbpfDrivers
    if ($statusCode -ne $EbpfStatusCode_SUCCESS) {
        Write-Log -level $LogLevelError -message "Failed to stop eBPF drivers."
        return [int]$statusCode
    }

    # Uninstall the eBPF drivers and use the results to generate the log message.
    $failedServices = @() 
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key
        $uninstallResult = Uninstall-Driver -serviceName $driverName
        if ($uninstallResult -ne 0) {
            $failedServices += $driverName
        }
    }
    if ($failedServices.Length -eq 0) {
        $statusCode = $EbpfStatusCode_SUCCESS
        Write-Log -level $LogLevelInfo -message "eBPF drivers uninstalled successfully."
    } else {
        $statusCode = $EbpfStatusCode_UNINSTALLING_DRIVER_FAILED
        $failedServicesString = $failedServices -join ", "
        Write-Log -level $LogLevelError -message "Failed to uninstall service(s): $failedServicesString."

        # If any of the drivers failed to uninstall, attempt to re-install the drivers that were successfully uninstalled.
        $failedServices | ForEach-Object {
            $driverName = $_
            $installResult = Install-Driver -serviceName $driverName -servicePath "$installDirectory\drivers\$($_.Value)"
            if ($installResult -ne $EbpfStatusCode_SUCCESS) {
                Write-Log -level $LogLevelError -message "Failed to re-install service: $driverName."
                $statusCode = $EbpfStatusCode_INSTALLING_DRIVER_FAILED
            }
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
    $statusCode = Copy-Directory -sourcePath "$sourcePath" -destinationPath $destinationPath
    if ($statusCode -eq $EbpfStatusCode_SUCCESS) {

        # Install the eBPF services and use the results to generate the status file.
        $statusCode = Install-EbpfDrivers -installDirectory $destinationPath      
        if ($statusCode -eq $EbpfStatusCode_SUCCESS) {

            # Accounting for any error on the following operations is not worth the risk of leaving the system in a bad state, 
            # i.e. if this is called during a rollback, we cannot fail a potential succesful system functionality restoration
            # because of accessory operations, being just the drivers the essential part for having the data path active.
            # Therefore, we just log any errors and proceed with the installation of the rest of the components.

            # Add the eBPF installation directory to the system PATH.
            Add-DirectoryToSystemPath -directoryPath $destinationPath | Out-Null 

            # Register the netsh extension.
            Register-EbpfNetshExtension -installDirectory $destinationPath | Out-Null 

            # Register the trace providers.
            Enable-EbpfTracing -installDirectory $destinationPath | Out-Null 

            Write-Log -level $LogLevelInfo -message "eBPF for Windows installed successfully."
        } else {
            $statusCode = $EbpfStatusCode_INSTALLING_DRIVER_FAILED
            $failedServicesString = $failedServices -join ", "
            Write-Log -level $LogLevelError -message "Failed to install service(s): $failedServicesString -> reverting registration for the ones that succeded."
        }
    } else {
        Write-Log -level $LogLevelError -message "Failed to copy eBPF files to the destination folder."
    }

    return [int]$statusCode
}

function Uninstall-eBPF {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Uninstall-eBPF($installDirectory)"

    if (eBPF-Components-In-Use) {
        Write-Log -level $LogLevelError -message "eBPF components are in use, cannot uninstall."
        $statusCode = $EbpfStatusCode_COMPONENTS_IN_USE
    } else {    
        # Uninstall the eBPF drivers and use the results to generate the log message.
        $statusCode = Uninstall-EbpfDrivers -installDirectory $installDirectory
        if ($statusCode -eq $EbpfStatusCode_SUCCESS) {
            # If all drivers were successfully uninstalled, then we can proceed with the rest of the uninstallation.
            
            # Accounting for any error on the following operations is not worth the risk of leaving the system in a bad state, 
            # i.e. if this is called during a rollback, we cannot fail a potential succesful system functionality restoration
            # because of accessory operations, being just the drivers the essential part for having the data path active.
            # Therefore, we just log any errors and proceed with the installation of the rest of the components.

            # Unregister the trace providers
            Disable-EbpfTracing -installDirectory $installDirectory | Out-Null

            # De-register the netsh extension
            Unregister-EbpfNetshExtension | Out-Null 

            # Remove the eBPF installation directory from the system PATH
            Remove-DirectoryFromSystemPath -directoryPath $installDirectory | Out-Null 

            # Delete the eBPF files
            Delete-Directory -destinationPath $installDirectory | Out-Null
        }
    }

    return [int]$statusCode
}

function Update-eBPF {
    param (
        [string]$operationName,
        [string]$currProductVersion,
        [string]$newProductVersion,
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Update-eBPF($operationName, $currProductVersion, $newProductVersion, $installDirectory)"
    
    Write-Log -level $LogLevelInfo -message "Performing eBPF [$operationName]."

    # For the moment, we just uninstall and install from/to the given installation folder.
    $statusCode = Uninstall-eBPF -installDirectory "$installDirectory" -createStatusFile $false
    if ($statusCode -ne $EbpfStatusCode_SUCCESS) {
        $statusMessage = "eBPF $operationName FAILED (Uninstall failed)."
        Write-Log -level $LogLevelError -message $statusMessage
    } else {
        Write-Log -level $LogLevelInfo -message "eBPF v$currProductVersion uninstalled successfully."
        $statusCode = Install-eBPF -sourcePath "$EbpfPackagePath" -destinationPath "$installDirectory"
        if ($statusCode -ne $EbpfStatusCode_SUCCESS) {
            $statusMessage = "eBPF $operationName FAILED (Install failed)."
            Write-Log -level $LogLevelError -message $statusMessage
        } else {
            $statusMessage = "eBPF $operationName succeeded."
            Write-Log -level $LogLevelInfo -message $statusMessage
        }
    }

    return [int]$statusCode
}

# This function is designed to handle the installation or update of an eBPF. It supports operations such as installation, upgrade, and rollback.
# The function assesses the existing installation, compares versions, and takes appropriate actions based on the specified parameters.
# This function is flexible to uninstall/install/upgrade to a different path than the given one, for those scenarios where the driver is registered from a different folder.
function InstallOrUpdate-eBPF {
    param (
        [string]$operationName,
        [string]$sourcePath,
        [string]$destinationPath,
        [bool]$allowDowngrade
    )

    Write-Log -level $LogLevelInfo -message "InstallOrUpdate-eBPF($operationName, $sourcePath, $destinationPath, $allowDowngrade)"

    # Define a status info object.
    $statusInfo = [PSCustomObject]@{
        StatusCode = $EbpfStatusCode_ERROR
        StatusString = $StatusError
        StatusMessage = "<none>"
    }
    # Define a version info object.
    $versionInfo = [PSCustomObject]@{
        currInstallPath = $destinationPath
        currDriverPath = $null
        currProductVersion = $null
        newProductVersion = $null
        comparison = -1
    }

    # Check if the operation is allowed in the current environment.
    if (-not (Is-InstallOrUpdate-Supported)) {
        $statusInfo.StatusCode = $EbpfStatusCode_INSTALLATION_UNALLOWED
        $statusInfo.StatusMessage = "eBPF [$operationName] not allowed in the current environment."
        Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
        
        return $statusInfo
    }

    try {
        # By default, no rollback is needed.
        $rollback = $false

        # Retrieve the current installation version info.        
        $versionInfo = Get-EbpfVersionInfo -sourcePath $sourcePath -destinationPath $destinationPath

        # If $currProductVersion has a value, then a version of eBPF is already installed, let's check if it needs to (or can) be updated.
        if ($null -ne $versionInfo.currProductVersion) {
            Write-Log -level $LogLevelInfo -message "Found eBPF v$($versionInfo.currProductVersion) already installed."

            # Compare the product version of the installed driver with the one in the extension package.
            if ($versionInfo.comparison -eq 2) {
                # If the product version is the same as the version distributed with the VM extension package up to the 3rd digit (comparison == 2),
                # then it's a handler-only update, and we don't need to do anything to the current eBPF installation.
                $statusInfo.StatusCode = $EbpfStatusCode_SUCCESS
                Write-Log -level $LogLevelInfo -message "This is a handler-only update to v($($versionInfo.currProductVersion)) -> no action taken."
            } else {
                # Depending on the version comparison, we either install, upgrade/downgrade or do nothing if the version is the same.
                if ($versionInfo.comparison -eq 0) {
                    # If the product version is the same as the version distributed with the VM extension, then we return a success code, as if the operation was successful.
                    $statusInfo.StatusCode = $EbpfStatusCode_SUCCESS
                    Write-Log -level $LogLevelInfo -message "eBPF version is up to date v($($versionInfo.currProductVersion))."
                } elseif ($versionInfo.comparison -gt 0 -and -not $allowDowngrade) {
                    # If the product version is greater than the version distributed with the VM extension and downgrade is NOT allowed, then return an error.
                    $rollback = $false # Rollback is not required in this case.
                    $statusInfo.StatusCode = $EbpfStatusCode_INSTALLATION_DOWNGRADE_UNALLOWED
                    Write-Log -level $LogLevelError -message "The installed eBPF version v($($versionInfo.currProductVersion)) is newer than the one in the VM Extension package v($($versionInfo.newProductVersion)) -> eBPF downgrades are not allowed!"
                } else {
                    # Updgrade or Downgrade the current eBPF installation.
                    if ($null -ne $versionInfo.currDriverPath) {
                        # If the eBPF drivers are registered (i.e., not just present in the default installation folder), stop them.
                        $statusInfo.StatusCode = Stop-EbpfDrivers
                    } else {
                        $statusInfo.StatusCode = $EbpfStatusCode_SUCCESS
                    }
                    if ($statusInfo.StatusCode -ne $EbpfStatusCode_SUCCESS) {
                        # If stopping the eBPF drivers failed, then we attempt to restart them in best-effort and return an error.
                        Start-EbpfDrivers -restartGuestProxyAgentService $true | Out-Null
                        $statusInfo.StatusString = $StatusError
                        $statusInfo.StatusMessage = "eBPF $operationName FAILED (Stopping eBPF drivers failed) -> Nothing changed in the system."
                        Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
                        return $statusInfo
                    } else {
                        # Backup the current installation (e.g. an existing installation from WinPA may be present).        
                        $statusInfo.StatusCode = Backup-EbpfDeployment -installDirectory "$($versionInfo.currInstallPath)"
                        if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {
                            Write-Log -level $LogLevelInfo -message "Backup of the current eBPF installation succeeded."

                            # Since there is an existing installation, we may need to rollback to the backed up version in case of failure.
                            $rollback = $true

                            # Log differently if Upgrade or Downgrade the current eBPF installation.
                            if ($versionInfo.comparison -gt 0 -and $allowDowngrade) {
                                # If the product version is greater than the version distributed with the VM extension, but downgrate is allowed, then just issue a warning.
                                Write-Log -level $LogLevelWarning -message "The installed eBPF version (v$($versionInfo.currProductVersion) is newer than the one in the VM Extension package (v$($versionInfo.newProductVersion)) -> eBPF will be downgraded to (v$($versionInfo.newProductVersion))."
                            } else {
                                # If the product version is lower than the version distributed with the VM extension, then upgrade it.
                                Write-Log -level $LogLevelInfo -message "The installed eBPF version (v$($versionInfo.currProductVersion)) is older than the one in the VM Extension package (v$($versionInfo.newProductVersion)) -> eBPF will be upgraded to (v$($versionInfo.newProductVersion))."
                            }
                            $statusInfo.StatusCode = Update-eBPF -operationName $operationName -currProductVersion $versionInfo.currProductVersion -newProductVersion $versionInfo.newProductVersion -installDirectory "$($versionInfo.currInstallPath)"
                        } else {
                            $statusInfo.StatusString = $StatusError
                            $statusInfo.StatusMessage = "eBPF $operationName FAILED (Backing up the current installation failed) -> Nothing changed in the system."
                            Write-Log -level $LogLevelError -message            
                        }
                    }
                }
            }
        } else {
            # If no eBPF version is installed, proceed with a new installation from the artifact package within the extension's ZIP file.
            Write-Log -level $LogLevelInfo -message "No eBPF installation found in [$destinationPath]: installing (v$($versionInfo.newProductVersion))."            
            $statusInfo.StatusCode = Install-eBPF -sourcePath "$sourcePath" -destinationPath "$($versionInfo.currInstallPath)"
            if ($statusInfo.StatusCode -ne $EbpfStatusCode_SUCCESS) {
                Write-Log -level $LogLevelError -message "Failed to install eBPF v$($versionInfo.newProductVersion) (new installation)."
            } else {
                Write-Log -level $LogLevelInfo -message "eBPF v$($versionInfo.newProductVersion) installed successfully."
            }
        }

        # If the installation was successful, attempt to start the eBPF drivers and restart the GuestProxyAgent service.    
        if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {        
            # Attempt to start the eBPF drivers and restart the GuestProxyAgent service (i.e. what would be done in the Enable command).
            $statusInfo = Start-EbpfDrivers -restartGuestProxyAgentService $true
            if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {                                                 
                $rollback = $false
                $statusInfo.StatusString = $StatusSuccess
                $statusInfo.StatusMessage = "eBPF $operationName succeeded."
                Write-Log -level $LogLevelInfo -message $statusInfo.StatusMessage
            } else {
                # Restore the error so to return it to the caller and rollback the installation below.            
                $statusInfo.StatusString = $StatusError
                $statusInfo.StatusMessage = "eBPF $operationName FAILED -> attempting rollback." 
                Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
            }
        }
        
        # If anything failed, attempt to rollback the installation, if there was a previous installation.
        if ($rollback) {
            # Save the current error code that caused the installation failure, so that we can return it to the caller.
            $prevStatusCode = $statusInfo.StatusCode

            # Uninstall eBPF: we are in a faling path, so we don't account for any error during the uninstallation of what's on the system,
            # and attempt scraping out anything we can, and re-installing the previous version.
            Uninstall-eBPF -installDirectory "$($versionInfo.currInstallPath)" | Out-Null

            # Attempt to rinstall the previous version of eBPF tht was backed up.
            $statusInfo.StatusCode = Install-eBPF -sourcePath "$EbpfBackupPath" -destinationPath "$($versionInfo.currInstallPath)"
            if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {                   
                # Enable eBPF (attempt to start the eBPF drivers and restart the GuestProxyAgent service).                    
                $statusInfo = Start-EbpfDrivers -restartGuestProxyAgentService $true                    
                if ($statusInfo.StatusCode -eq $EbpfStatusCode_SUCCESS) {
                    $statusInfo.StatusString = $StatusError
                    $statusInfo.StatusMessage = "eBPF $operationName FAILED, but rollback succeeded."
                } else {
                    $statusInfo.StatusString = $StatusError
                    $statusInfo.StatusMessage = "CATASTROPHIC FAILURE: eBPF $operationName FAILED and rollback FAILED."
                }
            } else {
                $statusInfo.StatusMessage = "CATASTROPHIC FAILURE: eBPF $operationName FAILED and rollback FAILED."
            }
            Write-Log -level $LogLevelError -message $statusInfo.StatusMessage

            # Return the original error code that caused the rollback.
            $statusInfo.StatusCode = $prevStatusCode
        }
    } catch {
        $statusInfo.StatusString = $StatusError
        $statusInfo.StatusMessage = "An error occurred during the '$operationName' operation eBPF: $_"
        Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
    } finally {
        # Remove the backup directory.
        Remove-EbpfDeploymentBackup | Out-Null
    }

    return $statusInfo
}

function Backup-EbpfDeployment {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Backup-EbpfDeployment($installDirectory)"

    try {
        # Check if the installation path exists
        if (Test-Path -Path $installDirectory -PathType Container) {
            # Create or clear the backup directory
            if (Test-Path $EbpfBackupPath -PathType Container) {
                Remove-Item -Recurse -Force -Path $EbpfBackupPath
            }
            New-Item -ItemType Directory -Force -Path $EbpfBackupPath | Out-Null

            # Copy installation files to the backup directory
            Copy-Item -Recurse -Path $installDirectory\* -Destination $EbpfBackupPath -Force

            # Log success
            $logMessage = "Backup completed successfully. Backup directory: $EbpfBackupPath"
            Write-Log -Level $LogLevelInfo -Message $logMessage

            return $EbpfStatusCode_SUCCESS
        } else {
            # Log error if installation path not found
            $logMessage = "Error: Installation path not found at $EbpfDefaultInstallPath"
            Write-Log -Level $LogLevelError -Message $logMessage

            return $EbpfStatusCode_FIND_DIR_FAILED
        }
    } catch {
        # Log error during backup
        $logMessage = "Error during backup: $_"
        Write-Log -Level $LogLevelError -Message $logMessage

        return $EbpfStatusCode_ERROR
    }
}

function Restore-EbpfDeployment {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Restore-EbpfDeployment($installDirectory)"

    try {
        # Check if a valid backup directory is found
        if (Test-Path $EbpfBackupPath -PathType Container) {
            # Remove existing installation directory
            Remove-Item -Recurse -Force -Path $installDirectory -ErrorAction SilentlyContinue

            # Copy files from backup to the installation directory
            Copy-Item -Recurse -Path $EbpfBackupPath -Destination $installDirectory -Force

            # Log success
            $logMessage = "Restoration completed successfully from backup: $EbpfBackupPath"
            Write-Log -Level $LogLevelInfo -Message $logMessage

            # Delete the backup directory after successful restoration
            Remove-EbpfDeploymentBackup | Out-Null

            return $EbpfStatusCode_SUCCESS
        } else {
            # Log error if no valid backup directory found
            $logMessage = "Error: No valid backup directory found at $EbpfBackupPath"
            Write-Log -Level $LogLevelError -Message $logMessage

            return $EbpfStatusCode_FIND_DIR_FAILED
        }
    } catch {
        # Log error during restoration
        $logMessage = "Error during restoration: $_"
        Write-Log -Level $LogLevelError -Message $logMessage

        return $EbpfStatusCode_ERROR
    }
}

function Remove-EbpfDeploymentBackup {

    Write-Log -level $LogLevelInfo -message "Remove-EbpfDeploymentBackup()"

    try {

        # Check if the backup directory exists
        if (Test-Path $EbpfBackupPath -PathType Container) {
            # Remove the backup directory
            Remove-Item -Recurse -Force -Path $EbpfBackupPath

            # Log success
            $logMessage = "Backup directory removed successfully: $EbpfBackupPath"
            Write-Log -Level $LogLevelInfo -Message $logMessage

            return $EbpfStatusCode_SUCCESS
        } else {
            # Log message if the backup directory does not exist
            $logMessage = "Backup directory not found: $EbpfBackupPath"
            Write-Log -Level $LogLevelWarning -Message $logMessage

            return $EbpfStatusCode_FIND_DIR_FAILED
        }
    } catch {
        # Log error during removal
        $logMessage = "Error during removal of backup directory: $_"
        Write-Log -Level $LogLevelError -Message $logMessage

        return $EbpfStatusCode_ERROR
    }
}

#######################################################
# VM Extension Handler Functions
#######################################################
function Reset-eBPF-Handler {
    Write-Log -level $LogLevelInfo -message "Reset-eBPF-Handler() -> NOP"
    
    # NOP for this current implementation.
    return $EbpfStatusCode_SUCCESS
}

function Enable-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Enable-eBPF-Handler()"

    $statusInfo = [PSCustomObject]@{
        StatusCode = $EbpfStatusCode_SUCCESS
        StatusString = $StatusSuccess
        StatusMessage = "eBPF enabled"
    }

    # Check if the handler is being invoked from the VM Agent within the context of and Update Operation.
    if (Get-EbpfUpdatingFlag) {

        # If we are here, it means that the Update commans did NOT return an error (otherwise the VM Agent would have aborted the Update operation).
        # Therefore, being the Enable command the last command of the Update operation sequence: reset the "updating" persistent flag.
        Set-EbpfUpdatingFlag -ResetFlag | Out-Null

        # If the handler is being invoked from the VM Agent within the Update Operation, we don't need to do anything,
        # as all the operations have been already performed by the Update command.
        $statusInfo.StatusMessage = "Enable-eBPF-Handler() invoked from the VM Agent within the Update Operation -> NOP."
        Write-Log -level $LogLevelInfo -message $statusInfo.StatusMessage
    } else {
        # Attempt to start the eBPF drivers.
        $statusInfo = Start-EbpfDrivers -restartGuestProxyAgentService $true
        
        # Generate the status file
        Report-Status -name $StatusName -operation $OperationNameEnable -status $statusInfo.StatusString -statusCode $statusInfo.StatusCode -statusMessage $statusInfo.StatusMessage
    }

    return [int]$statusInfo.StatusCode
}

function Disable-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Disable-eBPF-Handler()"

    # Attempt to stop the eBPF drivers (and GuestProxyAgent service).
    $statusCode = Stop-EbpfDrivers
    if ($statusCode -ne $EbpfStatusCode_SUCCESS) {
        Write-Log -level $LogLevelError -message "Failed to stop eBPF drivers, attempting to restart them with the GuestProxyAgent service."
        Start-EbpfDrivers -restartGuestProxyAgentService $true | Out-Null
    }

    return [int]$statusCode
}

function Uninstall-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Uninstall-eBPF-Handler()"

    # Check if the handler is being invoked from the VM Agent within the context of and Update Operation.
    if (Get-EbpfUpdatingFlag) {
        Write-Log -level $LogLevelInfo -message "Uninstall-eBPF-Handler() invoked from the VM Agent within the Update Operation -> NOP."
        return $EbpfStatusCode_SUCCESS
    }

    $statusCode = Uninstall-eBPF -installDirectory "$EbpfDefaultInstallPath"
   
    return [int]$statusCode
}

function Install-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Install-eBPF-Handler()"

    # Define a status info object.
    $statusInfo = [PSCustomObject]@{
        StatusCode = $EbpfStatusCode_ERROR
        StatusString = $StatusError
        StatusMessage = "<none>"
    }

    try {
        # Install (or Update eBPF in case of existing WinPA installation).
        $statusInfo = InstallOrUpdate-eBPF -operationName $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath" -allowDowngrade $false
    } catch {
        $statusInfo.StatusString = $StatusError
        $statusInfo.StatusMessage = "An error occurred during the '$OperationNameInstall' operation eBPF: $_"
        Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
    }

    return [int]$statusInfo.StatusCode
}

function Update-eBPF-Handler {

    Write-Log -level $LogLevelInfo -message "Update-eBPF-Handler()"

    # IMPLEMENTATION NOTE:
    # Due to the current implementation of the VM Extrnsion Platform and Auto-Update requirements, toghether with the dependency taken by the GuestProxy agent,
    # the Update operation has to forcily implement ALL the command sequence invoked within the Update opertion (i.e. Disable, Uninstall, Update, Install and Enable).
    # This is because the VM Agent may invoke the Update operation in a disconnected state, in case the GuestProxyAgent fails to restart.
    # Therefore, a global persistent flag is used by all of the commands within the Update operation, to determine they are being invoked from the VM Agent
    # within the Update operation scope, and if so, do NOP.
    
    # Define a status info object.
    $statusInfo = [PSCustomObject]@{
        StatusCode = $EbpfStatusCode_ERROR
        StatusString = $StatusError
        StatusMessage = "<none>"
    }

    try {
        # BEFORE setting the "EbpfUpdatingFlag" persistent flag, detect if the handler is being invoked for the first time,
        # so that InstallOrUpdate-eBPF can be invoked to allow or not downgrades.
        $allowDowngrade = Get-EbpfUpdatingFlag

        # Set the "EbpfUpdatingFlag" persistent flag.
        $statusInfo.StatusCode = Set-EbpfUpdatingFlag -SetFlag
        if ($statusInfo.StatusCode -ne $EbpfStatusCode_SUCCESS) {
            $statusInfo.StatusMessage = "eBPF $OperationNameUpdate FAILED (Set-EbpfUpdatingFlag failed) -> Operation aborted."
            Write-Log -level $LogLevelError -message $statusMessage
        } else {
            # Install (or Update eBPF in case of existing WinPA installation).
            $statusInfo = InstallOrUpdate-eBPF -operationName $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath" -allowDowngrade $allowDowngrade
        }
    } catch {
        $statusInfo.StatusString = $StatusError
        $statusInfo.StatusMessage = "An error occurred durint the '$OperationNameUpdate' operation eBPF: $_"
        Write-Log -level $LogLevelError -message $statusInfo.StatusMessage
    } finally {

        # If the Update command failed, reset the "updating" persistent flag as the Enable command will not be invoked.
        if ($statusInfo.StatusCode -ne $EbpfStatusCode_SUCCESS) {
            Set-EbpfUpdatingFlag -ResetFlag | Out-Null
        }

        # Update does not need to generate a status file, but in order to support Auto-Upate in a disconnected state, it will in place of the Enable command (which will not be invoked in case of failure).
        Report-Status -name $StatusName -operation $OperationNameUpdate -status $statusInfo.StatusString -statusCode $statusInfo.StatusCode -statusMessage $statusInfo.StatusMessage
    }
    
    return [int]$statusInfo.StatusCode
}

#######################################################
# Main entry point
#######################################################
# Call the Get-HandlerEnvironment function, capture the output and set the global environment variable.
Get-HandlerEnvironment -handlerEnvironmentFullPath "$DefaultHandlerEnvironmentFilePath" | Out-Null
