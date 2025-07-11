## Installing eBPF into a Test VM

Follow the [VM Installation Instructions](vm-setup.md) for one-time setup of a test Hyper-V VM.
Once the one-time setup has been completed, the following steps will
install or update the eBPF installation in the VM.

To install files you built yourself and run CI/CD scripts on a remote VM, follow the [remote VM setup instructions](remote-vm-setup.md) instead.

### Method 1 (Install a release with the MSI installer)

Do the following from within the VM:

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

    * If you **built the binaries from inside the VM**, then from your `ebpf-for-windows` directory in the VM, skip to step 2 (i.e., for running the MSI installer).

    * Otherwise, if you **built the binaries on the host machine**, then from your `ebpf-for-windows`
        build directory on the host machine (e.g., "`ebpf-for-windows\x64\Debug`"), start an admin Powershell on the host machine and run:

        ```ps
        # To copy the files to a VM, run:
        ..\deploy-ebpf.ps1 --dir="c:\some\path" --vm="<test-vm-name>"

        # or, to copy files locally, run:
        .\deploy-ebpf.ps1 --dir="c:\some\path"
        ```

        To also copy files needed to run various tests, simply add the `-t` flag, as follows:

        ```ps
        # To copy the files to a VM, run:
        .\deploy-ebpf.ps1 --dir="c:\some\path" --vm="<test-vm-name>" -t

        # or, to copy files locally, run:
        .\deploy-ebpf.ps1 --dir="c:\some\path" -t
        ```

        >Note: if the `--dir` parameter is not specified, the destination directory defaults to "`c:\temp\eBPF`".

2. From within the VM, install the the eBPF services  by starting an admin Powershell
, and running the MSI installer with the following commands:

   ```ps
   cd "c:\some\path" # or cd c:\temp\eBPF (default location)
   .\setup_ebpf.ps1
   ```

    >**TIP**: the MSI installer will add the installation folder to the system's PATH environment variable, so that the eBPF tools can be run from any command prompt.
    >Therefore, it is recommended to open a new command prompt after the installation is complete, to ensure that the PATH variable is updated.

#### Updating the eBPF installation

If you want to install a new version of eBPF, you must uninstall the previous version by running the following command from within the VM:

```ps
.\setup-ebpf.ps1 -Uninstall
```

### Method 3 (Install files you built yourself, with a VM checkpoint)

This method uses a machine that
has already built the binaries for `x64/Debug` or `x64/Release`.

Copy the build output in `\x64\[Debug|Release]` to the host of the test VM and run the following in a Powershell
command prompt:

1. Modify the environment of the VM as needed. Create a snapshot of the test VM named **baseline**, by running:

    ```ps
    Checkpoint-VM -Name <test-vm-name> -CheckpointName baseline
    ```
    Note: Rename the new checkpoint to `baseline`, and remove the old baseline, if present.

1. Store the VM administrator credential, by running the following commands:

   ```ps
   Install-Module CredentialManager -force
   ```

   ```ps
   New-StoredCredential -Target TEST_VM -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine
   ```

   ```ps
   New-StoredCredential -Target `**`TEST_VM_STANDARD`**` -Username <VM Standard User Name> -Password <VM Standard User account password> -Persist LocalMachine
   ```

   > Note that "`TEST_VM` and `TEST_VM_STANDARD` " are literal and is used in step 5 below. It need not be the name of any actual test VM.
1. Enter the `\x64\[Debug|Release]` directory (`cd`) where the build artifacts are stored.
1. Modify `.\test_execution.json` to specify the name of the test VM under `VMMap`. You only need one entry in this map. eg:

    ```json
    {
        ...

        "VMMap":
        {
            "<host name>":
            [
                {
                    "Name": "<test-vm-name>"
                }
            ]
        },
    }
    ```

1. Run the following commands to use the credentials saved with `TEST_VM` and `TEST_VM_STANDARD` in step 2,
 for logging into each of the VMs named in `test_execution.json`:

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
        ```

    * To **build the image on a Linux machine** (e.g. Ubuntu), make sure docker is installed (see [install docker on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)), and do the following:

      * Run the following command and provide parameters for `repository`, `tag` and `OSVersion`:

          ```bash
          $HOME/ebpf-for-windows-image/build-images.sh
          ```

3. Push the `ebpf-for-windows` image to your repository.

4. Update `manifests/Kubernetes/ebpf-for-windows-daemonset.yaml` with the container image pointing to your image path. Run the following command:

    ```cmd
    kubectl apply -f manifests/Kubernetes/ebpf-for-windows-daemonset.yaml
    ```

## Installing eBPF external extensions

- If your eBPF program requires XDP, install the [xdp-for-windows](https://github.com/microsoft/xdp-for-windows/releases) extension by following the [XDP for Windows installation instructions](https://github.com/microsoft/xdp-for-windows/blob/main/docs/usage.md).
