# Setup instructions for self-hosted runners

The CI/CD tests for `eBPF for Windows` requires installing kernel drivers, that are not supported in Github-hosted runners.
That is why self-host runners are needed to run those tests. The `run_tests` job in the `Kernel_Test_VM` Github workflow (`driver_test_vm.yml`) runs on self-host runners that use Hyper-V VMs to deploy the eBPF components and run the CI/CD tests on. Using Hyper-V VMs enable the Github workflow to start from a clean state every time the test runs by restoring the VMs to a "baseline" snapshot.
This document discusses the steps to set up such a selfhosted actions-runner that can run the workflow for CI/CD tests on a fork of the eBPF for Windows repo.

1) Install Windows Server 2019 - build 17763.
   1) [Windows Server 2019 Azure VM](https://portal.azure.com/#create/Microsoft.WindowsServer2019Datacenter-ARM)
2) [Download and install action runner](https://github.com/actions/runner/releases) following the instructions for Windows x64.
3) Create a new selfhosted runner for the fork. This requires administrator permissions in the project. Go to the settings menu in Github UI, select `Actions`->`Runners` and click on the `New selfhosted-runner` button. This will generate a token for the selfhosted runner.
4) Configure action runner as follows:
   ```./config.cmd --url <fork URL> --labels 'ebpf_cicd_tests' --token <action runner token> --runasservice --windowslogonaccount <account> --windowslogonpassword <password> ```
   For the `--url` parameter provide the URL to the fork for which seflhosted runner is being configured.<br/>
   For the `--token` parameter provide the token obtained in step 3.<br/>
   The value for `--labels` parameter (`ebpf_cicd_tests`) must be the same as the `environment` field in the job named `driver` in `cicd.yml`.<br/>
   The `--runasservice` parameter makes the action runner run as a Windows service. The runner service runs as
   `NetworkService` by default. However, the `Kernel_Test_VM` workflow performs operations on a test VM that requires
   administrator privilege. So, the credentials of an account with administrator privilege must be supplied in
   `windowslogonaccount` and `windowslogonpassword` parameters.
6) Follow the [VM Installation Instructions](vm-setup.md) to set up **two test VMs** and perform one-time setup steps. Then create a snapshot named **baseline** for each of the VMs.
7) Connect the two test VMs.
   1) Create a new VMSwitch instance: `New-VMSwitch -Name <VMSwitch Name> -SwitchType Private`
   2) Add two VM NICs on the first VM and one VM NIC on the other VM. Connect the NICs to the private VMSwitch: `Add-VMNetworkAdapter -VMName <VMName> -SwitchName <VMSwitch Name>`
8) Edit test configuration JSON files.
   1) Edit `test_execution.json` file. Add the name of the one of the VMs in `BasicTest` section. Add the names of both the VMs in `MultiVMTest` section along with the "Interfaces" section that must contain information about the network interfaces created in step 7.2 Above. This section must contain the interface alias, and IPv4 and IPv6 addresses. The CICD test automation would apply these IP addresses on the NICs of the test VM.
   2) Edit `vm_list.json` with the names of the two test VMs.
9) Store the VM administrator credential:
   1) `Install-Module CredentialManager -force`
   2) `New-StoredCredential -Target `**`TEST_VM`**` -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine`
10) Set up Windows Error Reporting [Local Dump Collection](https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps) on the VMs with the following commands.
    ```New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue```
    ```New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue```
    ```New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "c:\dumps" -PropertyType ExpandString -ErrorAction SilentlyContinue -Force```
12) Reboot the runner.
