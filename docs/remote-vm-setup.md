# Running Scripts on a Remote VM

This guide explains how to set up and run eBPF for Windows CI/CD scripts on a remote VM.

---

## 1. Prepare the Remote VM

1. **Enable Test Signed Binaries**

   Open an **Administrator PowerShell** prompt and run:
   ```powershell
   bcdedit.exe -set TESTSIGNING ON
   ```

   For more information, see [testsigning documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).

2. **Set Network Profile to Private**

   ```powershell
   Get-NetConnectionProfile
   # For each network that is public, run:
   Set-NetConnectionProfile -Name "YourNetworkName" -NetworkCategory Private
   ```

3. **Enable PowerShell Remoting**

   ```powershell
   Enable-PSRemoting
   ```

4. **Restart the VM**

   ```powershell
   Restart-Computer
   ```

---

## 2. Ensure Remote VM is Reachable

On your host machine, verify that the remote VM is reachable and that WinRM is running by executing:

```powershell
Test-WSMan <remote-vm-ip>
```

If this command fails, ensure the VM is powered on, network connectivity is working, and WinRM is enabled. Running `winrm quickconfig` on the remote VM can help identify and fix common WinRM setup issues.

---

## 3. Store VM Credentials on the Host

On your host machine, save the VM administrator and standard user credentials using the `CredentialManager` module:

```powershell
Install-Module CredentialManager -Force
New-StoredCredential -Target TEST_VM -Username <VM Administrator> -Password <VM Administrator account password> -Persist LocalMachine
New-StoredCredential -Target TEST_VM_STANDARD -Username <VM Standard User Name> -Password <VM Standard User account password> -Persist LocalMachine
```

> **Note:**
> Use the literal names `TEST_VM` and `TEST_VM_STANDARD` for the credential targets.
> These do **not** need to match the actual VM names.

---

## 4. Prepare the Build Artifacts

1. **Navigate to the Build Directory**

   ```powershell
   cd .\x64\Debug
   # or
   cd .\x64\Release
   ```

2. **Edit `test_execution.json`**

   Update the `VMMap` section to specify your test VM.
   Example:

   ```json
   {
       ...
       "VMMap": {
           "<host name>": [
               {
                   "Name": "<test-vm-ip>"
               }
           ]
       }
   }
   ```

---

## 5. Run the CI/CD Setup Script

1. **Set Execution Policy**

   ```powershell
   Set-ExecutionPolicy Unrestricted -Force
   ```

2. **Run the Setup Script**

   ```powershell
   .\setup_ebpf_cicd_tests.ps1 -IsVMRemote
   ```

3. **Run the Test Execution Script**

   ```powershell
   .\execute_ebpf_cicd_tests.ps1 -IsVMRemote
   ```

---
## Additional Notes

- The credentials stored in step 3 will be used for authentication to the VM during test execution.
- If your goal is simply to deploy pre-built binaries to a remote virtual machine, you can use the deploy-ebpf.ps1 script instead. This script will prompt you for credentials during execution.:
  ```powershell
  .\deploy-ebpf.ps1 --dir="c:\some\path" --remote_vm=<remote-vm-ip>
  ```
---