# Dot source the utility script
. .\scripts\common.ps1

# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#231-install-command
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#221-add-a-new-handler-on-the-vm-install-and-enable
#
# Install or Update eBPF from the artifact package within the extension ZIP file
#
# NOTE: Since the VM Agent does not know if eBPF was already provisioned by WinPA, it may call install
# eventhough it would be an update. Therefore, we always update we always call InstallOrUpdate-eBPF
# so we check if the eBPF package is already installed.
#
# NOTE: The status file will be generated within the function, given its variable scope.
return InstallOrUpdate-eBPF $OperationNameInstall $EbpfPackagePath, $EbpfDefaultInstallPath