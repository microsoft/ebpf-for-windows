# Setup instructions for self-hosted runners

The CI/CD tests for `eBPF for Windows` requires installing kernel drivers, that are not supported in Github-hosted runners.
That is why self-host runners are needed to run those tests. The `Kernel_Test_VM` Github workflow runs on self-host runners that uses Hyper-V VM to deploy
the eBPF components and runs the CI/CD tests on it. Using a Hyper-V VM enables the Github workflow to start from a clean state every time the test runs
by restoring the VM to a "baseline" snapshot.
This document discusses the steps to set up such a selfhost-runner that can run workflow for CI/CD tests.

1) Install Windows Server 2019 - build 17763.
   1) [Windows Server 2019 Azure VM](https://portal.azure.com/#create/Microsoft.WindowsServer2019Datacenter-ARM)
2) Download and install action runner (using PowerShell).
   1) ```cd c:\```
   2) ```mkdir actions-runner; cd actions-runner```
   3) ```Invoke-WebRequest -Uri https://github.com/actions/runner/releases/download/v2.281.1/actions-runner-win-x64-2.281.1.zip -OutFile actions-runner-win-x64-2.281.1.zip```
   4) ```if((Get-FileHash -Path actions-runner-win-x64-2.281.1.zip -Algorithm SHA256).Hash.ToUpper() -ne 'b8dccfef39c5d696443d98edd1ee57881075066bb62adef0a344fcb11bd19f1b'.ToUpper()){ throw 'Computed checksum did not match' }```
   5) ```Add-Type -AssemblyName System.IO.Compression.FileSystem ; [System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD/actions-runner-win-x64-2.281.1.zip", "$PWD")```
3) Obtain an [authentication token](https://github.com/microsoft/ebpf-for-windows/settings/actions/runners/new). This requires administrator permissions in the project.
4) Configure action runner as follows:
   ```./config.cmd --url https://github.com/microsoft/ebpf-for-windows --labels 'kernel_test_vm' --token <action runner token> --runasservice --windowslogonaccount <account> --windowslogonpassword <password> ```
   The `--runasservice` parameter makes the action runner run as a Windows service. The runner service runs as
   `NetworkService` by default. However, the `Kernel_Test_VM` workflow performs operations on a test VM that requires
   administrator privilege. So, the credentials of an account with administrator privilege must be supplied in
   `windowslogonaccount` and `windowslogonpassword` parameters.
5) Install the build tools as follows:
   1) Install [Git for Windows 64-bit](https://git-scm.com/download/win).
   2) Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe).
   3) From the Visual Studio Installer GUI choose the following:
      1) MSVC v142 - VS 2019 C++ x64/x86 build tools (Latest).
      2) Windows 10 SDK. Choose the latest available version.
      3) C++ CMake tools for Windows.
      4) MSVC v142 - VS 2019 C++ x64/x86 Spectre Mitigated libs (Latest).
   4) [Windows Driver Kit for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854). The WDK
     version is 10.0.19041.685. Care must be taken that the version of the Windows 10 SDK in step 5.3.2 matches the
     WDK version. If the build fails with `error MSB8020: The build tools for WindowsKernelModeDriver10.0 cannot
     be found` then perform the following mitigation steps:
      1) Copy `c:\Program Files (x86)\Windows Kits\10\Vsix\VS2019\WDK.vsix` to a file with the extension set to `.zip` instead of `.vsix` and extract it.
      2) Copy all files under `$MSBuild\Microsoft\*` to `c:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Microsoft`.
   5) Download [Nuget.exe](https://www.nuget.org/downloads). Do not copy the nuget.exe file in `Windows\System32` folder, as that causes issues
   running the `nuget restore` command. Instead copy it in some other folder and make sure that the path to that folder is added to the PATH system environmental variable.
6) [Set up a test VM](https://github.com/microsoft/ebpf-for-windows/blob/master/docs/vm-setup.md) and create a snapshot named **baseline**.
7) Store the VM administrator credential:
   1) `Install-Module CredentialManager -force`
   2) `New-StoredCredential -Target `**`TEST_VM`**` -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine`
8)  Reboot the runner.
