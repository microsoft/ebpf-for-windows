# Dot source the utility script
. .\scripts\common.ps1

# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#231-install-command
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#221-add-a-new-handler-on-the-vm-install-and-enable
#
# Install or Update eBPF from the artifact package within the extension ZIP file.
#
# Since the VM Agent does not know whether or not eBPF was already provisioned by WinPA, it may call install
# eventhough it would be an update. Therefore, we always update we always call InstallOrUpdate-eBPF
# so we check if the eBPF package is already installed.

# Install or Update eBPF for Windows
# NOTE: The install operation does not generate a status file, since the VM Agent will afterwards call the enable operation.
return InstallOrUpdate-eBPF -operation $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"