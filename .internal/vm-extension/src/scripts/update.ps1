# Dot source the utility script
. .\scripts\common.ps1

# Update a handler to different version: https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#223update-a-handler-to-different-version

# Change VM Extension status to "transitioning"
Create-StatusFile -name $StatusName -operation $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -statusMessage "Starting eBPF update" 

# NOTE: The status file will be generated within the function, given its variable scope.
InstallOrUpdate-eBPF $OperationNameUpdate, $EbpfPackagePath, $EbpfDefaultInstallPath | Out-Null

# TBC: restart GuestProxyAgent service.
# Ideally, we ahould have a way to verify if we are in the IMDS scenario or not, e.g. registry key, etc.
if ($true) {
    Restart-Service -Name "GuestProxyAgent" -Force
}
