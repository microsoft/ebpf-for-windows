# Dot source the utility script
. .\utilities.ps1

# Change VM Extension status to "transitioning"
Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -statusMessage "Starting eBPF update"

# NOTE: The status file will be generated within the function, given its variable scope.
$res = InstallOrUpdate-eBPF $OperationNameUpdate, $EbpfPackagePath, $EbpfDefaultInstallPath

# Extra step for IMDS (this is not accounted as a result of the eBPF VM Extension): Start ProxyAgent
$res = Start-Service -Name "GuestProxyAgent"
if ($res -ne 0) {
    Write-Log -level $LogLevelError -message "Failed to start GuestProxyAgent. Error code: $res"
}
