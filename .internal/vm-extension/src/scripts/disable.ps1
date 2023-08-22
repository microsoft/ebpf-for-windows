# Dot source the utility script
. .\scripts\common.ps1

# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#233-disable-command
#
# A user might explicitly request to disable a handler without uninstalling it.
# On disable Azure VM Agent will execute the disable command in a separate process with ADMINISTRATIVE privileges.
# On the execution of the disable command the handler is expected to complete the pending tasks and then 
# stop any processes or services related to the handler that have been running on the machine.
Disable-eBPf