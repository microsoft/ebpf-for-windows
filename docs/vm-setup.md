# VM Installation Instructions

## One-Time Setup

1. Enable Hyper-V as follows:
    1. Type in Hyper-V in the search bar.
    2. If "Hyper-V Manager" does not show up under Apps:
        * Click on "Turn Windows features on or off"
        * Check the Hyper-V checkbox and click OK
        * Reboot when prompted

2. Install a Windows VM as follows:
    1. Run "Hyper-V Manager".
    2. Select the current machine in the left pane.
    3. Click the "Quick Create..." action in the rightmost pane.
    4. When the Create Virtual Machine dialog appears, select "Windows 10 dev environment".
    5. Click the "Create Virtual Machine" button.
    6. Once that is complete click the "Edit Settings" button.
    7. Select security, clear the "Enable Scure Boot" checkbox, and click OK. (This is a prerequisite for
       enabling test signed binaries.)
    8. Click "Connect" and start the VM.

3. From within the VM desktop, enable test signed binaries as follows:
   (see [testsigning](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) for more discussion):
    1. Start an admin command shell (cmd.exe).
    2. Do `bcdedit.exe -set TESTSIGNING ON`.
    3. Restart the VM so that the change will be applied.

## Installing eBPF into a VM

Once the one-time setup has been completed, the following steps will
install or update the eBPF installation in the VM, from a machine that
has already built the binaries for x64/Debug.

1. Deploy the binaries to `C:\Temp` in your VM, as follows:
    a. If you built the binaries from inside the VM, then from your ebpf-for-windows directory in the VM, do `.\scripts\deploy-ebpf -l`.  Otherwise,
    b. If you built the binaries on the host machine, then from your ebpf-for-windows directory on the host machine, start an admin Powershell on the host machine and do `.\scripts\deploy-ebpf`.

2. From within the VM, install the binaries as follows:
    1. Start an admin command shell (cmd.exe).
    2. Do 'cd C:\temp'.
    3. Do 'install-ebpf.bat'.
