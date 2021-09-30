# Setup instructions for self-hosted runners

Self-hosted runners are necessary as GitHub-hosted runners don't have the requisite permissions to install drivers.

1) Install Windows Server 2019 - build 17763.
   1) [Windows Server 2019 Azure VM](https://portal.azure.com/#create/Microsoft.WindowsServer2019Datacenter-ARM)
2) Enable Test Signing mode.
   1) ``` bcdedit /set testsigning on ```
3) Enable driver verifier.
   1) ``` verifier /standard /bootmode persistent /driver ebpfcore.sys netebpfext.sys sample_ebpf_ext.sys  ```
4) Download and install action runner (using PowerShell).
   1) ```cd c:\```
   2) ```mkdir actions-runner; cd actions-runner```
   3) ```Invoke-WebRequest -Uri https://github.com/actions/runner/releases/download/v2.281.1/actions-runner-win-x64-2.281.1.zip -OutFile actions-runner-win-x64-2.281.1.zip```
   4) ```if((Get-FileHash -Path actions-runner-win-x64-2.281.1.zip -Algorithm SHA256).Hash.ToUpper() -ne 'b8dccfef39c5d696443d98edd1ee57881075066bb62adef0a344fcb11bd19f1b'.ToUpper()){ throw 'Computed checksum did not match' }```
   5) ```Add-Type -AssemblyName System.IO.Compression.FileSystem ; [System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD/actions-runner-win-x64-2.281.1.zip", "$PWD")```
5) Obtain an [authentication token](https://github.com/microsoft/ebpf-for-windows/settings/actions/runners/new). This requires administrator permissions in the project.
6) Configure action runner.
   1) ```./config.cmd --url https://github.com/microsoft/ebpf-for-windows --token <action runner token>```
7) Change action runner service to run as "LocalSystem".
   1) Open services.msc.
   2) Locate "GitHub Action Runner ...".
   3) Right Click -> Properties -> Log On.
   4) Select "This Account" radio button and give credentials for a local account with administrator privilege. This is needed since the `Kernel_Test` workflow performs operations on a test VM that requires administrator privilege.
8) Install the build tools as follows:
   1) Install [Git for Windows 64-bit](https://git-scm.com/download/win).
   2) Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe).
   3) From the Visual Studio Installer GUI choose the following:
      1) MSVC v142 - VS 2019 C++ x64/x86 build tools (Latest).
      2) Windows 10 SDK. Choose the latest available version.
      3) C++ CMake tools for Windows.
      4) MSVC v142 - VS 2019 C++ x64/x86 Spectre Mitigated libs (Latest).
   4) [Windows Driver Kit for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854). The WDK version is 10.0.19041.685. Care must be taken that the version of Windows 10 SDK in step 8.3.2 matches the WDK version. If build fails with `error MSB8020: The build tools for WindowsKernelModeDriver10.0 cannot be found` then perform the following mitigation steps:
      1) Copy `c:\Program Files (x86)\Windows Kits\10\Vsix\VS2019\WDK.vsix` as a ZIP file and extract it.
      2) Copy all files under `$MSBuild\Microsoft\*` to `c:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Microsoft`
   5) Download [Nuget.exe](https://www.nuget.org/downloads). Do not copy the nuget.exe file in Windows\System32 folder. Instead copy it in some other folder and make sure it the path to that folder is added to the PATH system environmental variable.
9) Reboot the runner.
