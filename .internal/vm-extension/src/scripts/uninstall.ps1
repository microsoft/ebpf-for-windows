# Dot source the utility script
. .\common.ps1

# Remove a handler from the VM (Disable and Uninstall): https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#222-remove-a-handler-from-the-vm-disable-and-uninstall
#

# Uninstall eBPF from the default installation directory
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
# Generate the status file
Create-StatusFile -name $StatusName -operation $OperationNameUninstall -status $statusString -statusCode $statusCode -statusMessage $statusMessage
return $res