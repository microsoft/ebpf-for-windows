# Dot source the utility script
. .\scripts\common.ps1

# Remove a handler from the VM (Disable and Uninstall):
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#222-remove-a-handler-from-the-vm-disable-and-uninstall
#
exit Uninstall-eBPF-Handler