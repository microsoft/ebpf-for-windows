# Dot source the utility script
. .\common.ps1

# Uninstall eBPF from the default installation directory
$res = Uninstall-eBPF $EbpfDefaultInstallPath
if ($res -eq $true) {
    $overallStatus = $StatusSuccess
    $overallStatusCode = 0
    $statusMessage = "eBPF for Windows was successfully uninstalled"
}
else {
    $overallStatus = $StatusError
    $overallStatusCode = 1
    $statusMessage = "eBPF for Windows was not uninstalled"
}

# Generate the status file
Create-StatusFile -handlerWorkloadName "eBPFforWindows" -operationName "uninstall" -status $overallStatus -statusCode $overallStatusCode -statusMessage $statusMessage
