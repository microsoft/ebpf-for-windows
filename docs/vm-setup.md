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
    7. Select security, clear the "Enable Secure Boot" checkbox, and click OK. (This is a prerequisite for
       enabling test signed binaries.)
    8. Click "Connect" and start the VM.

3. From within the VM desktop, enable test signed binaries as follows:
   (see [testsigning](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) for more discussion):
    1. Start an admin command shell (cmd.exe).
    2. Do `bcdedit.exe -set TESTSIGNING ON`.
    3. Restart the VM so that the change will be applied.

## Debugging a VM

To debug kernel-mode issues in the VM, see [Setting up a Connection to a Virtual Machine in Visual Studio](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-connection-to-a-virtual-machine-in-visual-studio).

To use WinDbg or KD as the debugger instead of Visual Studio, see [Setting Up Kernel-Mode Debugging of a Virtual Machine Manually using a Virtual COM Port](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/attaching-to-a-virtual-machine--kernel-mode-)

Both of the links above contain the statement:
"In the virtual machine, configure the COM port to map to a named pipe. The debugger will connect through this pipe.
For more information about how to create this pipe, see your virtual machine's documentation."

That step can be done from the *Host* as follows:

1. Start an admin powershell.
2. Do ' Set-VMComPort "Windows 10 dev environment" 2 \\.\pipe\DebugVM -DebuggerMode On'

After this point, use "\\.\pipe\DebugVM" in the rest of the instructions as the pipe name.

Alternatively, debugging over IP rather than named pipes can be used, as discussed in
[Setting Up Network Debugging of a Virtual Machine - KDNET](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host).


## Enable Driver Verifier on eBPF drivers
[Windows Driver Verifier](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier) is a diagnostic tool that can detect illegal operations performed by kernel drivers. This can be optionally enabled on eBPF kernel drivers as follows:
- ``` verifier /standard /bootmode persistent /driver ebpfcore.sys netebpfext.sys sample_ebpf_ext.sys  ```
- Reboot the VM.
