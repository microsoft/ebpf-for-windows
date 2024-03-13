## Installing eBPF into a Test VM

Follow the [VM Installation Instructions](vm-setup.md) for one-time setup of a test VM.
Once the one-time setup has been completed, the following steps will
install or update the eBPF installation in the VM.

### Method 1 (Install a release with the MSI installer)

Do the following from within the VM:

1. Download and install the *VC++ Redist* package from [this location](https://aka.ms/vs/17/release/vc_redist.x64.exe).
1. Download the `eBPF-for-Windows.x.x.x.msi` file from the [latest release on GitHub](https://github.com/microsoft/ebpf-for-windows/releases).
1. Execute the MSI file you downloaded.
1. After accepting the License and selecting the desired installation folder (default will be "`C:\Program Files\ebpf-for-windows`"), the following components will be selectable from the *Installation Wizard*:

    * **Runtime Components** (mandatory): this feature adds the eBPF runtime and core components, which are also required by the other components. If you select only this
      feature, only [native code generation](NativeCodeGeneration.md) is enabled.
        * **JIT** (optional): this sub-feature adds support for JIT-compiled eBPF programs and (in a Debug build only) interpreted eBPF programs.

An **command line install/uninstall** is also supported, through the direct use of `C:\Windows\system32\msiexec.exe` from an *administrative Command Prompt*:

* The installation folder can be customized by assigning the desired path to the `INSTALLFOLDER` parameter (path with spaces must be put between double quotes), i.e.:

    ```bash
    INSTALLFOLDER="C:\Program Files\ebpf-for-windows"
    ```

* The following feature-components are available for customization, and must be assigned as comma-separated values to the `ADDLOCAL` parameter:

  * `eBPF_Runtime_Components` (**mandatory**): runtime components (installed in `[Installation folder]\*`, `[Installation folder]\drivers`).
  * `eBPF_Runtime_Components_JIT` (optional): JIT compiler service (installed in `[Installation folder]\JIT`).

    e.g., (full featured):

    ```bash
    ADDLOCAL=eBPF_Runtime_Components,eBPF_Runtime_Components_JIT
    ```

Below are some examples of CLI installations/uninstallation, using "`C:\Program Files\ebpf-for-windows`" as the installation folder:

* Installation:
    > **Note**: add the "`/qn`" switch for **unattended install**.

    ```bash
    # Debug MSI - fully-featured installation, including the JIT compiler (available on pre-release versions only)
    C:\Windows\system32\msiexec.exe /i eBPF-for-Windows.x.x.x.msi INSTALLFOLDER="C:\Program Files\ebpf-for-windows" ADDLOCAL=eBPF_Runtime_Components,eBPF_Runtime_Components_JIT

    # Debug MSI - minimal installation (only runtime components)
    C:\Windows\system32\msiexec.exe /i eBPF-for-Windows.x.x.x.msi INSTALLFOLDER="C:\Program Files\ebpf-for-windows" ADDLOCAL=eBPF_Runtime_Components

    # Release MSI - fully-featured installation, including the JIT compiler (available on pre-release versions only)
    C:\Windows\system32\msiexec.exe /i eBPF-for-Windows.x.x.x.msi INSTALLFOLDER="C:\Program Files\ebpf-for-windows" ADDLOCAL=eBPF_Runtime_Components,eBPF_Runtime_Components_JIT

    # Release MSI - minimal installation (only runtime components)
    C:\Windows\system32\msiexec.exe /i eBPF-for-Windows.x.x.x.msi INSTALLFOLDER="C:\Program Files\ebpf-for-windows" ADDLOCAL=eBPF_Runtime_Components
    ```

* Uninstallation (here unattended, with the "`/qn`" switch):

    ```bash
    C:\Windows\system32\msiexec.exe /x eBPF-for-Windows.x.x.x.msi /qn
    ```

**Troubleshooting logs** from the Windows Installer can be obtained be appending the `/l[options] <filename>` option to the install command line (for extra-verbose logs use "`/l*vx`"), e.g.:

```bash

C:\Windows\system32\msiexec.exe /i eBPF-for-Windows.x.x.x.msi <other options> /l*vx c:\installer-log.txt

```

### Method 2 (Install files you built yourself)

This method uses a machine that
has already built the binaries for `x64/Debug` or `x64/Release`.

1. Deploy the binaries to `C:\Temp` in your VM, as follows (from within a "*Developer PowerShell for VS 2022*"):

    * If you **built the binaries from inside the VM**, then from your `ebpf-for-windows` directory in the VM, run:

        ```ps
        .\x64\debug\deploy-ebpf -l
        ```

    * Otherwise, if you **built the binaries on the host machine**, then from your `ebpf-for-windows`
        directory on the host machine, start an admin Powershell on the host machine and run:

        ```ps
        .\x64\debug\deploy-ebpf --vm="<test-vm-name>"
        ```

        or, to also copy files needed to run various tests, run:

        ```ps
        .\x64\debug\deploy-ebpf --vm="<test-vm-name>" -t
        ```

        or, to copy files to a specific directory, including file shares, run:

        ```ps
        .\x64\debug\deploy-ebpf -l="c:\some\path"
        ```

2. From within the VM, install the binaries by starting an administrator Command Prompt shell (cmd.exe)
, and running the following commands:

   ```cmd
   cd C:\Temp

   powershell -ExecutionPolicy Bypass .\scripts\setup-ebpf.ps1
   ```

### Method 3 (Install files you built yourself, with a VM checkpoint)

This method uses a machine that
has already built the binaries for `x64/Debug` or `x64/Release`.

Copy the build output in `\x64\[Debug|Release]` to the host of the test VM and run the following in a Powershell
command prompt:

1. Create a snapshot of the test VM named **baseline**, by running:

    ```ps
    Checkpoint-VM -Name <test-vm-name> -CheckpointName baseline
    ```

1. Store the VM administrator credential, by running the following commands:

   ```ps
   Install-Module CredentialManager -force
   ```

   ```ps
   New-StoredCredential -Target TEST_VM -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine
   ```

   > Note that "`TEST_VM`" is literal and is used in step 5 below; it need not be the name of any actual test VM.
1. Enter the `\x64\[Debug|Release]` directory (`cd`) where the build artifacts are stored.
1. Modify `.\vm_list.json` to specify the name of the test VM under `VMList`, eg:

    ```json
    {
        ...

        "VMList":
        [
            {
                "Name": "<test-vm-name>"
            }
        ]
    }
    ```

1. Run the following commands to setup to use the credentials saved with `TEST_VM` in step 2,
 for logging into each of the VMs named in `vm_list.json`:

    ```ps
    Set-ExecutionPolicy unrestricted -Force
    ```

    ```ps
    .\setup_ebpf_cicd_tests.ps1
    ```

## Installing eBPF with host-process container

The following instructions will build an ebpf-for-windows image and deploy a daemonset referencing the image. This is the easiest way
to install eBPF on all Windows nodes in a Kubernetes cluster.

1. Download the `.msi` file from the [latest release on GitHub](https://github.com/microsoft/ebpf-for-windows/releases) and copy it over to [images](../images) directory.

2. Build ebpf-for-windows image.

    * To **build the image on the Windows Host**, make sure docker is installed. [Install docker on Windows Server](https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server/).
Start an admin Powershell on the Windows Host and run the following command and provide parameters for `repository`, `tag` and `OSVersion`:

        ```ps
        .\images\build-images.ps1
        ````

    * To **build the image on a Linux machine** (e.g. Ubuntu), make sure docker is installed (see [install docker on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)), and do the following:

      * Run the following command and provide parameters for `repository`, `tag` and `OSVersion`:

          ```bash
          $HOME/ebpf-for-windows-image/build-images.sh
          ````

3. Push the `ebpf-for-windows` image to your repository.

4. Update `manifests/Kubernetes/ebpf-for-windows-daemonset.yaml` with the container image pointing to your image path. Run the following command:

    ```cmd
    kubectl apply -f manifests/Kubernetes/ebpf-for-windows-daemonset.yaml
    ```
