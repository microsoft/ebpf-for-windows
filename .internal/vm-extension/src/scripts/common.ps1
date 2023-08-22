#######################################################
# Global Variables
#######################################################
# Define eBPF Handler Environment variables.
Set-Variable -Name "runTests" -Value $true
Set-Variable -Name "testRootFolder" -Value "C:\_ebpf\vm_ext"
Set-Variable -Name "AksRegistryKeyPath" -Value "HKLM:\Software\AKS\Key" # TBD: change to the actual registry key
Set-Variable -Name "AksRegistryKeyValue" -Value 1 # TBD: change to the actual registry value
Set-Variable -Name "EbpfExtensionName" -Value "eBPFforWindows"
Set-Variable -Name "EbpfPackagePath" -Value ".\package"
Set-Variable -Name "EbpfDefaultInstallPath" -Value "$env:ProgramFiles\ebpf-for-windows"
Set-Variable -Name "EbpfNetshExtensionName" -Value "ebpfnetsh.dll"
Set-Variable -Name "EbpfTracingStartupTaskName" -Value "eBpfTracingStartupTask"
Set-Variable -Name "EbpfTracingStartupTaskFilename" -Value "ebpf_tracing_startup_task.xml"
Set-Variable -Name "EbpfTracingPeriodicTaskName" -Value "eBpfTracingPeriodicTask"
Set-Variable -Name "EbpfTracingPeriodicTaskFilename" -Value "ebpf_tracing_periodic_task.xml"
Set-Variable -Name "EbpfTracingTaskCmd" -Value "ebpf_tracing.cmd"
Set-Variable -Name "EbpfTracingPath" -Value "$env:SystemRoot\Logs\eBPF"
$EbpfDrivers =
@{
    "EbpfCore" = "ebpfcore.sys";
    "NetEbpfExt" = "netebpfext.sys";
}

# VM Agent-generated environment variables.
Set-Variable -Name "VmAgentEnvVar_VERSION" -Value "VERSION"

# Define the VM extension's generic and Status file constants.
Set-Variable -Name "DefaultHandlerEnvironmentPath" -Value ".\HandlerEnvironment.json"
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

    # Append the log entry to the log file, and also write it to the console.
    $logEntry | Out-File -Append -FilePath $LogFilePath  
}

#######################################################
# Utility Functions
#######################################################
function Get-EnvironmentVariable {
    param (
        [string]$variableName
    )
    
    $value = (Get-Item "Env:$variableName").Value
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Environment variable '$variableName' is not set."
    }
    
    return $value
}

function Get-HandlerEnvironment {
    param (
        # The HandlerEnvironment.json file is always located in the root of where the ZIP package is extracted.
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
        [string]$name,
        [string]$operation,
        [string]$status,
        [int]$statusCode,
        [string]$statusMessage
    )

    # Get the SequenceNumber from the name of the latest *modified* .settings file.
    $settingsFiles = Get-ChildItem -Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.configFolder)" -Include "$EbpfExtensionName.*.settings" -Recurse | Sort-Object LastWriteTime -Descending
    $lastSequenceNumber = $settingsFiles[0].Name

    # Construct the status JSON object
    $statusObject = @{
        version = "1.0"
        timestampUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = @{
            name = $name
            operation = $operation
            configurationAppliedTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            status = $status
            code = $statusCode
            # message = @{
            #     id = "localized_resource_id"
            #     params = @("MyParam0", "MyParam1")
            # }
            formattedMessage = @{
                lang = "en-US"
                message = $statusMessage
            }
        }
    }
    
    # Convert the status object to JSON
    $statusJson = ConvertTo-Json $statusObject -Depth 5

    # Write the JSON to the .status file with the name of the latest .settings file.
    $statusFileName = [System.IO.Path]::ChangeExtension($lastSequenceNumber, ".status")
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

    $scQueryOutput = & "sc.exe" qc $serviceName

    # Search for the BINARY_PATH_NAME line using regex.
    $binaryPathLine = $scQueryOutput -split "`n" | Where-Object { $_ -match "BINARY_PATH_NAME\s+:\s+(.*)" }

    if ($binaryPathLine) {
        $binaryPath = $matches[1]

        # Extract the full disk path using regex.
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

function Install-Driver {
    param (
        [string]$serviceName,
        [string]$servicePath
    )

    Write-Log -level $LogLevelInfo -message "Installing service $serviceName"

    # Create the service using sc.exe (you'll need to replace this with the actual command).
    $scCreateOutput = & "sc.exe" create $serviceName type=kernel start=demand binPath="$servicePath"

    # Check the exit code to determine the result.
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

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$serviceName uninstalled successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to uninstall $serviceName. Error message: $scDeleteOutput"      
    }
    return $LASTEXITCODE
}

function Copy-Directory {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    # Create the destination directory, if it doesn't exist.
    if (-not (Test-Path $destinationPath)) {
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop
        } catch {
            Write-Log -level $LogLevelError -message "Failed to create destination directory '$destinationPath': $_"
            return $false
        }
    }

    # Recursively copy all files from source to destination.
    try {
        Copy-Item -Path ($sourcePath + "\*") -Destination $destinationPath -Recurse -Force -ErrorAction Stop
        Write-Log -level $LogLevelInfo -message "Files copied from '$sourcePath' to '$destinationPath'."
        return $true
    } catch {
        Write-Log -level $LogLevelError -message "Error while copying files: $_"
        return $false
    }
}

function Delete-Directory {
    param (
        [string]$destinationPath
    )

    if (Test-Path $destinationPath) {
        try {
            Remove-Item -Path $destinationPath -Recurse -Force -ErrorAction Stop
            Write-Log -level $LogLevelInfo -message "Directory '$destinationPath' deleted successfully."
            return $true
        } catch {
            Write-Log -level $LogLevelError -message "Failed to delete directory '$destinationPath'. Error: $_"
            return $false
        }
    } else {
        Write-Log -level $LogLevelWarning -message "Directory '$destinationPath' does not exist."
        return $false
    }
}

# Function to create a scheduled task
function Create-Scheduled-Task {
    param (
        [string]$installDirectory,
        [string]$taskName,
        [string]$taskFile
    )

    Write-Log -level $LogLevelInfo -message "Creating scheduled task '$taskName' from '$taskFile'..."

    try {
        $xmlPath = Join-Path $installDirectory $taskFile
        Register-ScheduledTask -Xml (Get-Content -Path $xmlPath -Raw) -TaskName $taskName
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

function DownloadAndUnpackEbpfRedistPackage {
    param (
        [string]$packageVersion,
        [string]$targetDirectory
    )

    # Download the eBPF redist package from the MS CodeHub feed, and unpack just the eBPF package to the target directory
    Start-Process nuget.exe  -ArgumentList "install eBPF-for-Windows-Redist -version $packageVersion -Source https://mscodehub.pkgs.visualstudio.com/eBPFForWindows/_packaging/eBPFForWindows/nuget/v3/index.json -OutputDirectory $targetDirectory" -Wait
    Rename-Item -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\eBPF-for-Windows-Redist.$packageVersion.nupkg" -NewName "eBPF-for-Windows-Redist.$packageVersion.nupkg.zip"
    Expand-Archive -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\eBPF-for-Windows-Redist.$packageVersion.nupkg.zip" -DestinationPath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\temp"
    Copy-Directory -sourcePath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\temp\package\bin" -destinationPath "$targetDirectory\v$packageVersion"
    Delete-Directory -destinationPath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion"
}

# This function deletes the tasks to start eBPF tracing at boot, and execute periodic rundowns,
# and deletes the EbpfTracingPath directory and its contents
function Delete-Ebpf-Tracing-Tasks {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Delete-Ebpf-Tracing-Tasks..."

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
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop
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
    Write-Log -level $LogLevelInfo -message "Create-Ebpf-Tracing-Tasks..."

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

    return Create-Ebpf-Tracing-Tasks -installDirectory $installDirectory
}

function Disable-EbpfTracing {    
    param (
        [string]$installDirectory
    )

    Delete-Ebpf-Tracing-Tasks -installDirectory $installDirectory | Out-Null
}

function Register-EbpfNetshExtension{
    param (
        [string]$installDirectory
    )

    Push-Location -Path $installDirectory

    # Add the eBPF netsh helper.
    $installResult = & "netsh.exe" add helper $EbpfNetshExtensionName

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$EbpfNetshExtensionName registered successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to register $EbpfNetshExtensionName. Error message: $installResult"
    }

    Pop-Location
    return $LASTEXITCODE
}

function Unregister-EbpfNetshExtension{

    # Add the eBPF netsh helper.
    Push-Location -Path $EbpfDefaultInstallPath
    $installResult = & "netsh.exe" delete helper $EbpfNetshExtensionName

    # Check the exit code to determine the result.
    if ($LASTEXITCODE -eq 0) {
        Write-Log -level $LogLevelInfo -message "$EbpfNetshExtensionName unregistered successfully."
    } else {
        Write-Log -level $LogLevelError -message "Failed to unregister $EbpfNetshExtensionName. Error message: $installResult"
    }

    Pop-Location
    return $LASTEXITCODE
}

function Stop-eBPFDrivers {
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key
        Stop-Service -Name $driverName -ErrorAction SilentlyContinue
        if ($?) {
            Write-Log -level $LogLevelInfo -message "Stopped driver: $driverName"
        } else {
            Write-Log -level $LogLevelError -message "Failed to stop driver: $driverName"
        }
    }
}

function Install-eBPF {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "Installing eBPF for Windows"

    # Copy the eBPF files to the destination folder.
    $copyResult = Copy-Directory -sourcePath $sourcePath -destinationPath $destinationPath
    if ($copyResult -eq $true) {

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

function Upgrade-eBPF {
    param (
        [string]$operationName,
        [string]$currProductVersion,
        [string]$newProductVersion,
        [string]$installDirectory
    )
    
    Write-Log -level $LogLevelInfo -message "Upgrading eBPF from v$currProductVersion to v$newProductVersion..."

    if (Is-AKS-Environment -eq $true) {
        $statusCode = 1
        Write-Log -level $LogLevelError -message "eBPF [$operationName] not allowed in an AKS environment."
    } else {
        Write-Log -level $LogLevelInfo -message "eBPF [$operationName] in non-AKS environment."

        # For the moment, we just uninstall and install to the current installation folder.
        $statusCode = Uninstall-eBPF "$installDirectory"
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
    }

    return [int]$statusCode
}

#######################################################
# VM Extension Handler Functions
#######################################################

function Reset-eBPF {
    # NOP for this current implementation.
    # TBD: confirm if Reset does not need to generate a status file. The docs say "Yes?"...
}

function Enable-eBPF {
    param (
        [string]$operationName,
        [int]$statusCode
    )

    # This is where any checks for prerequisites should be performed.
    # Currently, we just check if the eBPF drivers are installed and registered.
    $statusInfo = [PSCustomObject]@{
        StatusCode = 0
        StatusString = $StatusSuccess
    }
    $EbpfDrivers.GetEnumerator() | ForEach-Object {
        $driverName = $_.Key
        $currDriverPath = Get-FullDiskPathFromService -serviceName $driverName
        if ($currDriverPath) {
            if ($?) {
                Write-Log -level $LogLevelInfo -message "Enable-Ebpf(from $operationName): $driverName is registered correctly."
            } else {
                Write-Log -level $LogLevelError -message "Enable-Ebpf(from $operationName): $driverName is NOT registered correctly!"
                $statusInfo.StatusCode = 1
                $statusInfo.StatusString = $StatusError
            }
        }
    }

    # Generate the status file
    Create-StatusFile -name $StatusName -operation $operationName -status $statusInfo.StatusString -statusCode $statusInfo.StatusCode -statusMessage "eBPF enabled"

    return [int]$statusCode
}

function Disable-eBPF {
    param (
        [string]$operationName,
        [int]$statusCode
    )

    Stop-eBPFDrivers | Out-Null
    # TBD: confirm if Disable does not need to generate a status file. The docs say "Yes?"...
    #Create-StatusFile -name $StatusName -operation $OperationNameDisable -status $StatusSuccess -statusCode 0 -statusMessage "eBPF disabled"
}

function Uninstall-eBPF {
    param (
        [string]$installDirectory
    )

    Write-Log -level $LogLevelInfo -message "Uninstalling eBPF for Windows"
    
    # Stop all eBPF drivers (which will stop all the services which have a dependency on them).
    Stop-eBPFDrivers | Out-Null 

    # De-register the netsh extension
    Unregister-EbpfNetshExtension | Out-Null 

    # Uninstall the eBPF services and use the results to generate the status file.
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

function InstallOrUpdate-eBPF {
    param (
        [string]$operationName,
        [string]$sourcePath,
        [string]$destinationPath
    )

    Write-Log -level $LogLevelInfo -message "InstallOrUpdate-eBPF eBPF for Windows ->($operationName, $sourcePath, $destinationPath)"

    # Set the default product version to NULL (i.e. not installed).
    $currProductVersion = $null

    # This function is flexible to uninstall/install/upgrade to a different path than the iven one, for those scenarios where the driver is registered from a different folder.
    $currInstallPath = $destinationPath

    # Retrieve the product version of the driver in the extension package (anyone will do, as they should all have the same product version, so we don't have to hardcode a specific driver name)
    $EbpfDriverName = ($EbpfDrivers.GetEnumerator() | Select-Object -First 1).Key
    $newProductVersion = Get-ProductVersionFromFile -filePath (Join-Path -Path $EbpfPackagePath -ChildPath "drivers\$EbpfDriverName.sys")
    
    # Firstly, check if eBPFCore is installed and registered (as a test for eBPF to be installed).
    $currDriverPath = Get-FullDiskPathFromService -serviceName $EbpfDriverName
    if ($currDriverPath) {
        Write-Log -level $LogLevelInfo -message "eBPF driver installed and registered from: '$currDriverPath'"

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
    
    # If there's a $currProductVersion has a value, then a version of eBPF is already installed, let's check if it needs to be updated.
    if ($null -ne $currProductVersion) {
        Write-Log -level $LogLevelInfo -message "eBPF v$currProductVersion is already installed."

        $updateToVersion = [System.Environment]::GetEnvironmentVariable($VmAgentEnvVar_VERSION, [System.EnvironmentVariableTarget]::Machine)
        $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $updateToVersion
        if ($comparison -eq 2) {
            $statusCode = 0
            $statusMessage = "This is a handler-only update to v($updateToVersion) -> no action taken."
            Write-Log -level $LogLevelInfo -message $statusMessage
        } else {

            # If the product version is less than the version distributed with the VM extension, then upgrade it. Otherwise, no update is needed.
            $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
            if ($comparison -lt 0) {
                [int]$statusCode = Upgrade-eBPF -operationName $operationName -currProductVersion $currProductVersion -newProductVersion $newProductVersion -installDirectory "$currInstallPath"
            } elseif ($comparison -gt 0) {
                $statusCode = 0
                $statusMessage = "The installed eBPF version (v$currProductVersion) is newer than the one in the extension package (v$newProductVersion) -> no action taken."
                Write-Log -level $LogLevelWarning -message $statusMessage
            } else {
                $statusCode = 0
                $statusMessage = "eBPF version is up to date (v$currProductVersion)."
                Write-Log -level $LogLevelInfo -message $statusMessage
            }
        }
    } else {
        Write-Log -level $LogLevelInfo -message "No eBPF installation found in [$destinationPath]: installing (v$newProductVersion)."
        
        # Proceed with a new installation from the artifact package within the extension ZIP file.
        $statusCode = Install-eBPF -sourcePath "$EbpfPackagePath" -destinationPath "$currInstallPath"
        if ($statusCode -ne 0) {
            Write-Log -level $LogLevelError -message "Failed to install eBPF v$newProductVersion."
            Create-StatusFile -name $StatusName -operation $operationName -status $StatusError -statusCode 1 -statusMessage "eBPF $operationName FAILED (Clean install failed)."
        } else {
            Write-Log -level $LogLevelInfo -message "eBPF v$newProductVersion installed successfully."
            # If this was an 'Install' operation, the VM Agent will then call 'Enable' on the handler.
        }
    }

    return [int]$statusCode
}

#######################################################
# Main entry point
#######################################################
if ($runTests -eq $false) {
    # Call the Get-HandlerEnvironment function, capture the output and set the global environment variable.
    if (Get-HandlerEnvironment -ne $true) {
        Write-Log -level $LogLevelError -message "Failed to load '$DefaultHandlerEnvironmentPath'."
        exit       
    }
} else
{
    
    # Change the working directory to the root of the test environment, so to simulate the actual env that will be set up by the VM Agent.
    $currentDirectory = Get-Location
    Set-Location "$testRootFolder"

    # Load test-environment (current working folder is the root folder in which the entire ZIP in unzipped).
    if (Get-HandlerEnvironment -handlerEnvironmentFullPath ".\HandlerEnvironment-test.json" -eq $true) {

        # Test cases
        #######################################################
        # Raw environment cleanup
        Write-Log -level $LogLevelInfo -message "= Cleaning up environment =================================================================================================="        
        $null = net stop eBPFCore 2>&1
        $null = sc.exe delete eBPFCore 2>&1
        $null = net stop NetEbpfExt 2>&1
        $null = sc.exe delete NetEbpfExt 2>&1
        $null = netsh delete helper ebpfnetsh.dll 2>&1
        $null = Remove-DirectoryFromSystemPath "$EbpfDefaultInstallPath" 2>&1
        $null = Remove-Item -Path "$EbpfDefaultInstallPath" -Recurse -Force 2>&1
        $null = Remove-Item -Path "$global:LogFilePath" -Recurse -Force 2>&1

        # Clean-up and set up the test environment with two versions of the eBPF redist package
        $testRedistTargetDirectory = ".\_ebpf-redist"
        Delete-Directory -destinationPath $testRedistTargetDirectory | Out-Null
        DownloadAndUnpackEbpfRedistPackage -packageVersion "0.9.0" -targetDirectory $testRedistTargetDirectory | Out-Null
        DownloadAndUnpackEbpfRedistPackage -packageVersion "0.9.1" -targetDirectory $testRedistTargetDirectory | Out-Null 

        # Do some version comparison tests
        $currProductVersion = "0.9.0"
        $newProductVersion = "0.9.0.1"
        $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
        if ($comparison -eq 2) {
            Write-Log -level $LogLevelInfo -message "(v$currProductVersion) == v$newProductVersion) -> handler-only update!"
        } elseif ($comparison -lt 0) {
            Write-Log -level $LogLevelInfo -message "(v$currProductVersion) < v$newProductVersion)"
        } elseif ($comparison -gt 0) {
            Write-Log -level $LogLevelInfo -message "(v$currProductVersion) == v$newProductVersion)"
        } else {
            Write-Log -level $LogLevelInfo -message "(v$currProductVersion) > v$newProductVersion)"
        }
 
        # Install an old version
        # Add a new handler on the VM (Install and Enable)
        $packageVersion = "0.9.0"
        Write-Log -level $LogLevelInfo -message "= Install an old version =================================================================================================="
        Delete-Directory -destinationPath "$EbpfPackagePath" | Out-Null
        Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath" | Out-Null 
        $statusCode = InstallOrUpdate-eBPF -operationName $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
        # The VM Agent will then call 'Enable' on the handler
        Enable-eBPF -operationName $OperationNameInstall -statusCode $statusCode | Out-Null

        # Test that the status file name has the right sequence number ($EbpfExtensionName.1002.settings is the one modified last)
        $statusFileName = Get-ChildItem -Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)" -Filter "*.status" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($statusFileName.Name -ne "$EbpfExtensionName.1002.status") {
            Write-Log -level $LogLevelError -message "Status file name is not correct: $statusFileName"
        } else {
            Write-Log -level $LogLevelInfo -message "Status file name is correct: $statusFileName"
        }
        
        # Simulate a handler-only update, by changing the handler's new target version in the VERSION environment variable
        Write-Log -level $LogLevelInfo -message "= Simulate a handler-only update ============================================================================================"
        [Environment]::SetEnvironmentVariable($VmAgentEnvVar_VERSION, "0.9.0.1", [System.EnvironmentVariableTarget]::Machine)
        $statusCode = InstallOrUpdate-eBPF -operationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
        # The VM Agent will then call 'Enable' on the handler
        Enable-eBPF -operationName $OperationNameInstall -statusCode $statusCode | Out-Null
        [Environment]::SetEnvironmentVariable($VmAgentEnvVar_VERSION, $null, [System.EnvironmentVariableTarget]::Machine)

        # Update to a newer version
        # Update a handler to different version (Disable and Update)        
        $packageVersion = "0.9.1"
        Write-Log -level $LogLevelInfo -message "= Update to newer version =================================================================================================="
        Disable-eBPF | Out-Null
        Delete-Directory -destinationPath "$EbpfPackagePath" | Out-Null 
        Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath" | Out-Null 
        Create-StatusFile -name $StatusName -operation $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
        InstallOrUpdate-eBPF -operationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath" | Out-Null 
        
        # Update back to an older version
        $packageVersion = "0.9.0"
        Write-Log -level $LogLevelInfo -message "= Update to older version =================================================================================================="
        Delete-Directory -destinationPath "$EbpfPackagePath" | Out-Null 
        Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath" | Out-Null 
        Create-StatusFile -name $StatusName -operation $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
        InstallOrUpdate-eBPF -operationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath" | Out-Null 

        # Uninstall
        # Remove a handler from the VM (Disable and Uninstall): https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#222-remove-a-handler-from-the-vm-disable-and-uninstall
        Write-Log -level $LogLevelInfo -message "= Uninstall =================================================================================================="
        $statusCode = Uninstall-eBPF $EbpfDefaultInstallPath
        if ($statusCode -eq 0) {
            $statusString = $StatusSuccess
            $statusMessage = "eBPF for Windows was successfully uninstalled"
        }
        else {
            $statusString = $StatusError
            $statusMessage = "eBPF for Windows was not uninstalled"
        }
        Create-StatusFile -name $StatusName -operation $OperationNameUninstall -status $statusString -statusCode $statusCode -statusMessage $statusMessage
    } else {
        Write-Log -level $LogLevelError -message "Failed to load .\HandlerEnvironment-test.json."
    }

    Set-Location $currentDirectory    
}