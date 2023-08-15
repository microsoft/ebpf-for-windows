# Dot source the utility script
. .\common.ps1

# Change VM Extension status to "transitioning"
Create-StatusFile -handlerWorkloadName $HandlerWorkloadName -operationName $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -statusMessage "Starting eBPF update"

# NOTE: The status file will be generated within the function, given its variable scope.
InstallOrUpdate-eBPF $OperationNameUpdate, $EbpfPackagePath, $EbpfDefaultInstallPath
