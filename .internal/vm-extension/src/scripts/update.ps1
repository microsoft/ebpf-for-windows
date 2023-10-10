# Dot source the utility script
. .\scripts\common.ps1

# Update the eBPF VM Extension handler on the VM:
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#223update-a-handler-to-different-version
#
return Update-eBPF-Handler