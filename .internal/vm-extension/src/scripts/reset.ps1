# Dot source the utility script
. .\scripts\common.ps1

# ResetState
# There are two main scenarios when extension handler state needs to be reset:
# - VM is captured and restored
# - VM is backed up and restored In Azure, when a VM is captured/backed-up, snapshot of the VM will be saved as an image and a new VM will be created from the image during restoration.
#
# NOTE: If the handler does not create or set any values thus there is nothing to be cleaned up after restoration, then resetState command does not have to be provided.
#
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#235-resetstate
#
return Reset-eBPF-Handler