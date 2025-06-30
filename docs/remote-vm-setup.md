# Running CI/CD Scripts on a Remote VM

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

## 2. Store VM Credentials on the Host

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

## 3. Prepare the Build Artifacts

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
                   "Name": "<test-vm-name>"
               }
           ]
       }
   }
   ```

---

## 4. Run the CI/CD Setup Script

1. **Set Execution Policy**

   ```powershell
   Set-ExecutionPolicy Unrestricted -Force
   ```

2. **Run the Setup Script**

   ```powershell
   .\setup_ebpf_cicd_tests.ps1 -IsVMRemote
   ```

---

## Additional Notes

- Ensure that PowerShell Remoting is enabled and accessible between the host and the VM.
- The credentials stored in step 2 will be used for authentication to the VM during test execution.
- If you encounter issues, verify network connectivity and firewall settings between the host and the VM.

---