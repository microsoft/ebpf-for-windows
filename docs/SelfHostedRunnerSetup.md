# Setup instructions for self-hosted runners

Self-hosted runners are necessary as GitHub-hosted runners don't have the requisite permissions to install drivers.

1) Install Windows Server 2019 - build 17763.
   1) [Windows Server 2019 Azure VM](https://portal.azure.com/#create/Microsoft.WindowsServer2019Datacenter-ARM)
3) Enable Test Signing mode.
   1) ``` bcdedit /set testsigning on ```
4) Enable driver verifier.
   1) ``` verifier /standard /bootmode persistent /driver ebpfcore.sys netebpfext.sys sample_ebpf_ext.sys  ```
5) Download and install action runner (using PowerShell).
   1) ```cd c:\```
   2) ```mkdir actions-runner; cd actions-runner```
   3) ```Invoke-WebRequest -Uri https://github.com/actions/runner/releases/download/v2.281.1/actions-runner-win-x64-2.281.1.zip -OutFile actions-runner-win-x64-2.281.1.zip```
   4) ```if((Get-FileHash -Path actions-runner-win-x64-2.281.1.zip -Algorithm SHA256).Hash.ToUpper() -ne 'b8dccfef39c5d696443d98edd1ee57881075066bb62adef0a344fcb11bd19f1b'.ToUpper()){ throw 'Computed checksum did not match' }```
   5) ```Add-Type -AssemblyName System.IO.Compression.FileSystem ; [System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD/actions-runner-win-x64-2.281.1.zip", "$PWD")```
5) Obtain an [authentication token](https://github.com/microsoft/ebpf-for-windows/settings/actions/runners/new). This requires administrator permissions in the project.
6) Configure action runner.
   1) ```./config.cmd --url https://github.com/microsoft/ebpf-for-windows --token <action runner token>```
8) Change action runner service to run as "LocalSystem".
   1) Open services.msc.
   2) Locate "GitHub Action Runner ...".
   3) Right Click -> Properties -> Log On.
   4) Change "Log on as:" to "Local System Account".
8) Install the [Visual C++ Runtime Files](https://docs.microsoft.com/en-us/visualstudio/releases/2019/redistribution#visual-c-runtime-files)
9) Reboot the runner.
