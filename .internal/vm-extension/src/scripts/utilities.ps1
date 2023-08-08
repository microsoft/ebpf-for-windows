# Define the status constants
Set-Variable -Name "StatusTransitioning" -Value "transitioning" -Option Constant
Set-Variable -Name "StatusError" -Value "error" -Option Constant
Set-Variable -Name "StatusSuccess" -Value "success" -Option Constant
Set-Variable -Name "StatusWarning" -Value "warning" -Option Constant

# Define constants for log levels
$LogLevelInfo = "INFO"
$LogLevelWarning = "WARNING"
$LogLevelError = "ERROR"

function Get-HandlerEnvironment {
    # The HandlerEnvironment.json file is always located in the root of where the ZIP package is extracted
    $filePath = ".\HandlerEnvironment.json"
    
    if (Test-Path $filePath) {
        $jsonContent = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        return $jsonContent
    } else {
        Write-Host "HandlerEnvironment.json file not found."
        return $null
    }
}

function Generate-StatusFile {
    param (
        [string]$handlerWorkloadName,
        [string]$operationName,
        [string]$status,
        [int]$statusCode,
        [string]$statusMessage
    )

    # Get the SequenceNumber from the name of the latest created .settings file
    $lastSequenceNumber = Get-ChildItem -Path "$($env:eBPFHandlerEnv.handlerEnvironment.configFolder)" -Filter "*.settings" | Sort-Object CreationTime -Descending | Select-Object -First 1

    if ($lastSequenceNumber -eq $null) {
        Write-Host "No '.settings' file found."
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

    Write-Host "Status file generated: $statusFilePath"
}

function Write-Log {
    param (
        [string]$level,
        [string]$message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$level] $message"

    # Append the log entry to the log file, and also write it to the console
    $logEntry | Out-File -Append -FilePath $($handlerEnvironmentObject.handlerEnvironment.logFolder)
    Write-Host $logEntry
}


# Call the Get-HandlerEnvironment function, capture the output and set the environment variable
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
    Write-Host "HandlerEnvironment.json file not found."
    return
}