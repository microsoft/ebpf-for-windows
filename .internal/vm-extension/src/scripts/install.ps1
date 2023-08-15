# Dot source the utility script
. .\utilities.ps1

# Install or Update eBPF from the artifact package within the extension ZIP file
#
# NOTE: Since the VM Agent does not know if eBPF was already provisioned by WinPA, it may call install
# eventhough it would be an update. Therefore, we always update we always call InstallOrUpdate-eBPF
# so we check if the eBPF package is already installed.
#
# NOTE: The status file will be generated within the function, given its variable scope.
InstallOrUpdate-eBPF $OperationNameInstall $EbpfPackagePath, $EbpfDefaultInstallPath