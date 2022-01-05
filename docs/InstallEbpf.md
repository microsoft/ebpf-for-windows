# Installing eBPF into a Test VM

Follow the [VM Installation Instructions](vm-setup.md) for one-time setup of a test VM.
Once the one-time setup has been completed, the following steps will
install or update the eBPF installation in the VM, from a machine that
has already built the binaries for x64/Debug or x64/Release.

## Method 1
1. Deploy the binaries to `C:\Temp` in your VM, as follows:
    a. If you built the binaries from inside the VM, then from your ebpf-for-windows directory in the VM, do `.\scripts\deploy-ebpf -l`.  Otherwise,
    b. If you built the binaries on the host machine, then from your ebpf-for-windows directory on the host machine, start an admin Powershell on the host machine and do `.\scripts\deploy-ebpf`.

2. From within the VM, install the binaries as follows:
    1. Start an admin command shell (cmd.exe).
    2. Do 'cd C:\temp'.
    3. Do 'install-ebpf.bat'.

## Method 2
Copy the build output to the host of the test VM and run the following.
1. `Checkpoint-VM -Name <test-vm-name> -CheckpointName baseline` -- Creates a snapshot of the test VM named **baseline**.
2. Store the VM administrator credential:
   1) `Install-Module CredentialManager -force`
   2) `New-StoredCredential -Target `**`TEST_VM`**` -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine`
3. Modify `vm_list.json` to specify the name of the test VM under `VMList`.
4. `Set-ExecutionPolicy unrestricted -Force`
5. `Setup_ebpf_cicd_tests.ps1`