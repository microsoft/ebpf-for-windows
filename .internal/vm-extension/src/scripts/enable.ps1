# Dot source the utility script
. .\scripts\common.ps1

# The enable command will be invoked every time:
# - the machine reboots
# - the machine receives a new configuration settings file.
# - if the install process exits SUCCESSFULLY (exit code 0)
# Enable will have 5 minutes to complete its task, after which Azure VM Agent will kill the process.
# The enable command should be idempotent. If the command is invoked multiple times, the command should check
# if all the processes are running as expected, if yes, then the command should just exit with a success code.
#
# https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#232-enable-command
#
exit Enable-eBPF-Handler
