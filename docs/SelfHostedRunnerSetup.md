# Setup instructions for self-hosted runners

Some CI/CD tests for `eBPF for Windows` require installing kernel drivers, but the Github-hosted runners cannot be used to collect kernel-mode dumps should a crash occur. Self-hosted runners allow us to use nested VMs and collect KM dumps. We use them to run the `driver` job in the `CI/CD` Github workflow (`cicd.yml`). On each test run, we restore the VM to a saved checkpoint for a clean run.
Since these runners only run jobs for PRs in the official `eBPF for Windows` repo, you can follow the steps below to set one up for your fork.

1) Install Windows Server 2019 - build 17763.
   1) [Windows Server 2019 Azure VM](https://portal.azure.com/#create/Microsoft.WindowsServer2019Datacenter-ARM)
2) [Download and install action runner](https://github.com/actions/runner/releases) following the instructions for Windows x64.
3) Create a new self-hosted runner for the fork. This requires administrator permissions in the project. Go to the settings menu in Github UI, select `Actions`->`Runners` and click on the `New self-hosted-runner` button. This will generate a token for the self-hosted runner.
4) Configure action runner as follows:
   ```./config.cmd --url <fork URL> --labels 'ebpf_cicd_tests_ws2019' --token <action runner token> --runasservice --windowslogonaccount <account> --windowslogonpassword <password> ```
   For the `--url` parameter provide the URL to the fork for which self-hosted runner is being configured.<br/>
   For the `--token` parameter provide the token obtained in step 3.<br/>
   The value for `--labels` parameter (`ebpf_cicd_tests_ws2019`) must be the same as the `environment` field in the job named `driver` in `cicd.yml`.<br/>
   The `--runasservice` parameter makes the action runner run as a Windows service. The runner service runs as
   `NetworkService` by default. However, the `Kernel_Test_VM` workflow performs operations on a test VM that requires
   administrator privilege. So, the credentials of an account with administrator privilege must be supplied in
   `windowslogonaccount` and `windowslogonpassword` parameters.
6) Follow the [VM Installation Instructions](vm-setup.md) to set up **one test VM** and perform one-time setup steps. Then create a snapshot named **baseline** for the VMs.
7) Follow the [Method 3 in InstallEbpf.md](InstallEbpf.md#method-3-install-files-you-built-yourself-with-a-vm-checkpoint) instructions.
8) Set up Windows Error Reporting [Local Dump Collection](https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps) on the VM with the following commands.
    ```New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue```
    ```New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue```
    ```New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "c:\dumps" -PropertyType ExpandString -ErrorAction SilentlyContinue -Force```
11) Reboot the runner.
