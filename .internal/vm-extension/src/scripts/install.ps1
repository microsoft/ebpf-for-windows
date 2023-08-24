# Dot source the utility script
. .\scripts\common.ps1

# Install the eBPF VM Extension handler on the VM:
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#231-install-command
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#221-add-a-new-handler-on-the-vm-install-and-enable
#
return Install-eBPF-Handler