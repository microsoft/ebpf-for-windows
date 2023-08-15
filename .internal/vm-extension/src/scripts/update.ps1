# Dot source the utility script
. .\utilities.ps1

# Change VM Extension status to "transitioning"
Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -statusMessage "Starting eBPF update"

# NOTE: The status file will be generated within the function, given its variable scope.
InstallOrUpdate-eBPF $OperationNameUpdate, $EbpfPackagePath, $EbpfDefaultInstallPath

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
