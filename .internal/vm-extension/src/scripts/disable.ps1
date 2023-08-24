# Dot source the utility script
. .\scripts\common.ps1

# The disable command will be invoked every time before:
# - the VM Extension is uninstalled
# - the VM Extension is updated
# NOTE: A user might explicitly request to disable a handler without uninstalling it.
#
# On disable Azure VM Agent will execute the disable command in a separate process with ADMINISTRATIVE privileges.
# On the execution of the disable command the handler is expected to complete the pending tasks and then 
# stop any processes or services related to the handler that have been running on the machine.
# The disable command should be idempotent. If the command is invoked multiple times, the command should check
# if all the processes are disabled as expected, if yes, then the command should just exit with a success code.
#
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#233-disable-command
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#222-remove-a-handler-from-the-vm-disable-and-uninstall
#
return Disable-eBPF-Handler