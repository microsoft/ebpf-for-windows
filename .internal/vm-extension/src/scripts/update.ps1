# Dot source the utility script
. .\scripts\common.ps1

# Update a handler to different version: https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#223update-a-handler-to-different-version

# Change VM Extension status to "transitioning"
Create-StatusFile -name $StatusName -operation $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -statusMessage "Starting update" 

# Update eBPF for Windows
$res = InstallOrUpdate-eBPF -operation $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
if ($res -eq 0) {
    # Restart the Guest Proxy Agent service: this is an extended operation that is not part of the eBPF VM Extension,
    # therefore, we do not account success/failure of this operation in the update status.
    $GuestProxyAgentServiceName = "GuestProxyAgent"
    $service = Get-Service -Name $GuestProxyAgentServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log -level $LogLevelWarning -message "Service '$GuestProxyAgentServiceName' is not installed -> no action taken."
    } else {
        Write-Log -level $LogLevelInfo -message "Restarting service '$GuestProxyAgentServiceName'..."
        
        Restart-Service -Name $GuestProxyAgentServiceName -Force
        if ($?) {
            Write-Log -level $LogLevelInfo -message "Service '$GuestProxyAgentServiceName' was succesfully restarted."
        } else {
            Write-Log -level $LogLevelError -message "Failed to restart service '$GuestProxyAgentServiceName'."
        }
    }
}
return $res