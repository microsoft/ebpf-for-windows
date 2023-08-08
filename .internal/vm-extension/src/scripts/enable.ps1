# Dot source the utility script
. .\utilities.ps1

# This is where any checks for prerequisites should be performed

# Generate the status file
Generate-StatusFile -handlerWorkloadName "eBPFforWindows" -operationName "enable" -status "success" -statusCode 0 -statusMessage "eBPF enabled"
