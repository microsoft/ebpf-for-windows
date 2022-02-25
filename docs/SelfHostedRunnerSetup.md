# Setup instructions for self-hosted runners

The CI/CD tests for `eBPF for Windows` requires installing kernel drivers, that are not supported in Github-hosted runners.
That is why self-host runners are needed to run those tests. The `run_tests` job in the `Kernel_Test_VM` Github workflow (`driver_test_vm.yml`) runs on self-host runners that use Hyper-V VMs to deploy the eBPF components and run the CI/CD tests on. Using Hyper-V VMs enable the Github workflow to start from a clean state every time the test runs by restoring the VMs to a "baseline" snapshot.
This document discusses the steps to set up such a selfhosted actions-runner that can run the workflow for CI/CD tests on a fork of the eBPF for Windows repo.

1) Install Windows Server 2019 - build 17763.
   1) [Windows Server 2019 Azure VM](https://portal.azure.com/#create/Microsoft.WindowsServer2019Datacenter-ARM)
2) Download and install action runner (using PowerShell).
   1) ```cd c:\```
   2) ```mkdir actions-runner; cd actions-runner```
   3) ```Invoke-WebRequest -Uri https://github.com/actions/runner/releases/download/v2.281.1/actions-runner-win-x64-2.281.1.zip -OutFile actions-runner-win-x64-2.281.1.zip```
   4) ```if((Get-FileHash -Path actions-runner-win-x64-2.281.1.zip -Algorithm SHA256).Hash.ToUpper() -ne 'b8dccfef39c5d696443d98edd1ee57881075066bb62adef0a344fcb11bd19f1b'.ToUpper()){ throw 'Computed checksum did not match' }```
   5) ```Add-Type -AssemblyName System.IO.Compression.FileSystem ; [System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD/actions-runner-win-x64-2.281.1.zip", "$PWD")```
3) Create a new selfhosted runner for the fork. This requires administrator permissions in the project. Go to the settings menu in Github UI, select `Actions`->`Runners` and click on the `New selfhosted-runner` button. This will generate a token for the selfhosted runner.
4) Configure action runner as follows:
   ```./config.cmd --url <fork URL> --labels 'ebpf_cicd_tests' --token <action runner token> --runasservice --windowslogonaccount <account> --windowslogonpassword <password> ```
   For the `--url` parameter provide the URL to the fork for which seflhosted runner is being configured.
   For the `--token` parameter provide the token obtained in step 3.
   The value for `--labels` parameter (`ebpf_cicd_tests`) is same as the `runs-on` field in the `run_tests` job defined in `run_tests.yml`.
   The `--runasservice` parameter makes the action runner run as a Windows service. The runner service runs as
   `NetworkService` by default. However, the `Kernel_Test_VM` workflow performs operations on a test VM that requires
   administrator privilege. So, the credentials of an account with administrator privilege must be supplied in
   `windowslogonaccount` and `windowslogonpassword` parameters.
6) Follow the [VM Installation Instructions](vm-setup.md) to set up **two test VMs** and perform one-time setup steps. Then create a snapshot named **baseline** for each of the VMs.
7) Connect the two test VMs.
   1) Create a new VMSwitch instance: `New-VMSwitch -Name <VMSwitch Name> -SwitchType Private`
   2) Add a VM NIC on each VM and connect to the private VMSwitch: `Add-VMNetworkAdapter -VMName <VMName> -SwitchName <VMSwitch Name>`
   3) Assign IP address on the NICs on the VM (run from inside the VM): `New-NetIPAddress -InterfaceAlias <Interface Name> -IPAddress <IP address> -PrefixLength <Prefix length>`. The tests require one IPv4 and one IPv6 address on each of the VM NICs.
8) Edit test configuration JSON files.
   1) Edit `test_execution.json` file. Add the name of the one of the VMs in `BasicTest` section. Add the names of both the VMs in `MultiVMTest` section along with IPv4 and IPv6 addresses assigned in step (3) above.
   2) Edit `vm_list.json` with the names of the two test VMs.
9) Store the VM administrator credential:
   1) `Install-Module CredentialManager -force`
   2) `New-StoredCredential -Target `**`TEST_VM`**` -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine`
10) Reboot the runner.
