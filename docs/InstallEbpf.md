## Installing eBPF into a Test VM

Follow the [VM Installation Instructions](vm-setup.md) for one-time setup of a test VM.
Once the one-time setup has been completed, the following steps will
install or update the eBPF installation in the VM.

### Method 1 (Install a release with the MSI installer)

Do the following from within the VM:

1. Download the `.msi` file from the [latest release on GitHub](https://github.com/microsoft/ebpf-for-windows/releases).
1. Execute the `.msi` file you downloaded.

The following components are shown in the MSI to select from:

* **Runtime**: this is the base eBPF runtime, and is required by the other components.  If you select only this
  component, only [native code generation](NativeCodeGeneration.md) is enabled.
* **JIT**: this adds support for JIT-compiled eBPF programs and (in a Debug build only) interpreted eBPF programs.
* **Development**: this adds headers and libraries used for development.  If you only want to use eBPF for development
  rather than running programs, you can [use the NuGet package](GettingStarted.md#using-ebpf-in-development)
  instead of the MSI.
* **Testing**: this adds tests for the eBPF runtime for use by eBPF runtime developers.

### Method 2 (Install files you built yourself)
This method uses a machine that
has already built the binaries for `x64/Debug` or `x64/Release`.

1. Deploy the binaries to `C:\Temp` in your VM, as follows:

    - If you **built the binaries from inside the VM**, then from your `ebpf-for-windows` directory in the VM, run:

        ```ps
        .\x64\debug\deploy-ebpf -l
        ```
    - Otherwise, if you **built the binaries on the host machine**, then from your `ebpf-for-windows`
        directory on the host machine, start an admin Powershell on the host machine and run:

        ```ps
        .\x64\debug\deploy-ebpf --vm="<test-vm-name>"
        ```
        or, to also copy files needed to run various tests, run:
        ```ps
        .\x64\debug\deploy-ebpf --vm="<test-vm-name>" -t
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

1. Deploy the binaries to `C:\Temp` on the machine (Windows Host) where you built the binaries.
   Start an admin Powershell on the Windows Host and run:

    ```ps
    .\x64\debug\deploy-ebpf
    ```

2. Build ebpf-for-windows image.

    * To **build the image on the Windows Host**, make sure docker is installed. [Install docker on Windows Server](https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server/).
Start an admin Powershell on the Windows Host and run the following command and provide parameters for `repository`, `tag` and `OSVersion`:

        ```ps
        .\images\build-images.ps1
        ````

    * To **build the image on a Linux machine** (e.g. Ubuntu), make sure docker is installed (see [install docker on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)), and do the following:

      - Run the following Powershell command on the Windows Host to create zip files containing the binaries.
          ```ps
          Compress-Archive -Update -Path C:\temp -DestinationPath ebpf-for-windows-c-temp.zip
          ```

      - Copy `images\*` and `ebpf-for-windows-c-temp.zip` from the Windows Host to a directory on the Linux machine (e.g. `$HOME/ebpf-for-windows-image`).

      - Run the following command and provide parameters for `repositry`, `tag` and `OSVersion`:
          ```bash
          $HOME/ebpf-for-windows-image/build-images.sh
          ````

3. Push the `ebpf-for-windows` image to your repository.

4. Update `manifests/Kubernetes/ebpf-for-windows-daemonset.yaml` with the container image pointing to your image path. Run the following command:
    ```cmd
    kubectl apply -f manifests/Kubernetes/ebpf-for-windows-daemonset.yaml
    ```
