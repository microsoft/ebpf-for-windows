## Installing eBPF into a Test VM

Follow the [VM Installation Instructions](vm-setup.md) for one-time setup of a test VM.
Once the one-time setup has been completed, the following steps will
install or update the eBPF installation in the VM.

### Method 1 (Install a release)

Do the following from within the VM:

1. Download the .msi file from the latest [release](https://github.com/microsoft/ebpf-for-windows/releases)
2. Execute the .msi file you downloaded

### Method 2 (Install files you built yourself)
This method uses a machine that
has already built the binaries for x64/Debug or x64/Release.

1. Deploy the binaries to `C:\Temp` in your VM, as follows:
    a. If you built the binaries from inside the VM, then from your ebpf-for-windows directory in the VM, do `.\scripts\deploy-ebpf -l`.  Otherwise,
    b. If you built the binaries on the host machine, then from your ebpf-for-windows directory on the host machine, start an admin Powershell on the host machine and do `.\scripts\deploy-ebpf`, or to also copy files needed to run various tests, do `.\scripts\deploy-ebpf -t`.

2. From within the VM, install the binaries as follows:
    1. Start an admin command shell (cmd.exe).
    2. Do 'cd C:\temp'.
    3. Do 'powershell -ExecutionPolicy Bypass .\scripts\setup-ebpf.ps1'.

### Method 3 (Install files you built yourself, with a VM checkpoint)
This method uses a machine that
has already built the binaries for x64/Debug or x64/Release.

Copy the build output to the host of the test VM and run the following in powershell.
1. `Checkpoint-VM -Name <test-vm-name> -CheckpointName baseline` -- Creates a snapshot of the test VM named **baseline**.
2. Store the VM administrator credential:
   1) `Install-Module CredentialManager -force`
   2) `New-StoredCredential -Target `**`TEST_VM`**` -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine`
3. Modify `vm_list.json` to specify the name of the test VM under `VMList`.
4. `Set-ExecutionPolicy unrestricted -Force`
5. `Setup_ebpf_cicd_tests.ps1`

## Installing eBPF with host-process container

The following instructions will build an ebpf-for-windows image and deploy a daemonset referencing the image. This is the easiest way
to install eBPF on all Windows nodes in a Kubernetes cluster.

1. Deploy the binaries to `C:\Temp` on the machine (Windows Host) where you built the binaries.
   Start an admin Powershell on the Windows Host and do `.\scripts\deploy-ebpf`.

2. Build ebpf-for-windows image.

    a.  To build the image on the Windows Host, make sure docker is installed. [install docker on Windows Server](https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server/).
Start an admin Powershell on the Windows Host and run `.\images\build-images.ps1` and provide parameters for `repository`, `tag` and `OSVersion`.

    b.  To build the image on a Linux machine (e.g. Ubuntu), make sure docker is installed. [install docker on Ubuntu](https://docs.docker.com/engine/install/ubuntu/).

    * Run the following Powershell command on the Windows Host to create zip files containing the binaries.
      ```
      Compress-Archive -Update -Path C:\temp -DestinationPath ebpf-for-windows-c-temp.zip
      ```

   * Copy `images\*` and `ebpf-for-windows-c-temp.zip` from the Windows Host to a directory on the Linux machine (e.g. `$HOME/ebpf-for-windows-image`).

   * Run `$HOME/ebpf-for-windows-image/build-images.sh` and provide parameters for `repositry`, `tag` and `OSVersion`.

3. Push the ebpf-for-windows image to your repository.

4. Update `manifests/Kubernetes/ebpf-for-windows-daemonset.yaml` with the container image pointing to your image path. Run the following command:
```
kubectl apply -f manifests/Kubernetes/ebpf-for-windows-daemonset.yaml
```
