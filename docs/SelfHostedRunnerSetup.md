# Setup instructions for self-hosted runners

The CI/CD workflow for `eBPF for Windows` has two categories of tests. The first category is for the user mode tests
(including the unit tests, fault injection tests etc.), that run on the GitHub runners.
The other category are the kernel driver tests in that run on specialized pool of runners as discussed in [1es/README.md](../1es/README.md).
It is recommended, that a developer runs the CI/CD tests in their local development environment before submitting a pull-request.
While the user mode tests can be run on the development machine without a lot of prior setup, that is not true for the kernel tests.

This document describes step-by-step how a self-hosted runner can be configured to run the CI/CD kernel driver tests.

1. Create the Self-Hosted Runner
This section discusses how to create a new self-hosted runner for the developer's fork of the `eBPF for Windows` project.
This requires administrator permissions in the project.
1. From the settings menu in Github UI, select `Actions`->`Runners` and click on the `New self-hosted-runner` button.
This will generate a token for the self-hosted runner.
1. The self-hosted runner must be a Windows device running a 64-bit Windows OS.
   1. If the runner is a physical machine, it must satisfy the
   [hardware requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v?pivots=windows#check-requirements-for-windows) for installing Hyper-V.
   1. If the runner is a virtual machine, it must support
   [nested virtualization](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/enable-nested-virtualization#prerequisites).
1. On the self-hosted runner [download and install action runner](https://github.com/actions/runner/releases) following the instructions for Windows x64.
1. Configure action runner as follows:
   ```./config.cmd --url <fork URL> --labels 'ebpf_cicd_tests_ws2019' --token <action runner token> --runasservice --windowslogonaccount <account> --windowslogonpassword <password> ```
   For the `--url` parameter provide the URL to the fork for which self-hosted runner is being configured.<br/>
   For the `--token` parameter provide the token obtained in step 3.<br/>
   The value for `--labels` parameter must be set to `self-hosted`, matching the value of `environment` field in the jobs named
   `driver_tests` and `driver_native_only_tests` in `cicd.yml`.<br/>
   The `--runasservice` parameter makes the action runner run as a Windows service. The runner service runs as
   `NetworkService` by default. However, the `Kernel_Test_VM` workflow performs operations on a test VM that requires
   administrator privilege. So, the credentials of an account with administrator privilege must be supplied in
   `windowslogonaccount` and `windowslogonpassword` parameters.
1. Reboot the self-hosted runner.
1. Run the [`setup.ps1`](../1es/Setup.ps1) script to configure the self-hosted runner and install a test VM inside it.
   1. The script requires a VHD file for the test VM, which can be downloaded from the [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/).
   1. The script requires the following powershell modules:
      - `scripts\common.psm1`
      - `scripts\config_test_vm.psm1`
   1. The script requires an `unattend` file. One is available in [`unattend.xml`](../1es/unattend.xml).
1. Run the [`configure_vm.ps1`](../1es/configure_vm.ps1) script to configure the test VM.
