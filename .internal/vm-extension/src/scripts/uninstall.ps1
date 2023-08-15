# Dot source the utility script
. .\common.ps1

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
Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUninstall -status $statusString -statusCode $statusCode -statusMessage $statusMessage
