# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "Install",
        "Rollback",
        "Commit",
        "InstallEbpfSvc",
        "BackupServices",
        "RollbackServices",
        "CommitServices",
        "PrepareRestoreServices",
        "RemoveServices",
        "RestoreServices",
        "StopServices",
        "RollbackRestoreServices",
        "BackupStore",
        "RollbackStore",
        "CommitStore",
        "PrepareRestoreStore",
        "RestoreStore",
        "RollbackRestoreStore",
        "CommitRestoreStore",
        "CommitRestoreAll",
        "PrepareUserStore",
        "ClearStore",
        "PopulateStore",
        "RestoreLinks",
        "RollbackRestoreLinks")]
    [string]$Action,

    [string]$InstallRoot,

    [switch]$UseCanonicalServicePath,

    [string]$SystemRootPath = $env:SystemRoot,

    [ValidateSet("HKLM", "HKCU")]
    [string]$Scope,

    [string]$StateRoot = (Join-Path $env:ProgramData "eBPF-for-Windows\MsiBackup"),

    [string]$StoreRegistryPath,

    [string]$InstallingUserSid,

    [string]$OwnerProductCode,

    [string]$OwnerUpgradeCode,

    [string[]]$ServiceNames = @("eBPFCore", "NetEbpfExt", "eBPFSvc")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not ("EbpfMsi.NativeSecurity" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace EbpfMsi
{
    public static class NativeSecurity
    {
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int ERROR_NOT_ALL_ASSIGNED = 1300;
        private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        private const uint GROUP_SECURITY_INFORMATION = 0x00000002;
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
        private const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct Luid
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenPrivileges
        {
            public uint PrivilegeCount;
            public Luid Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            IntPtr fileHandle, out ByHandleFileInformation fileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string systemName, string name, out Luid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle,
            bool disableAllPrivileges,
            ref TokenPrivileges newState,
            uint bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetFileSecurity(
            string fileName, uint securityInformation, byte[] securityDescriptor);

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr Descriptor;
            public int InheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);

        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityInfo(
            IntPtr handle, int objectType, uint information, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        private static bool IsTrustedSid(System.Security.Principal.SecurityIdentifier sid)
        {
            return sid != null && (sid.Value == "S-1-5-18" || sid.Value == "S-1-5-32-544" ||
                sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        }

        private static void CheckBackupAcl(
            IntPtr handle, string path, bool ancestor, bool directory, string userSid = null)
        {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint error = GetSecurityInfo(
                handle, 1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                out owner, out group, out dacl, out sacl, out descriptor);
            if (error != 0) {
                throw new Win32Exception((int)error, "Cannot read backup security: " + path);
            }
            try {
                byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                RawSecurityDescriptor security = new RawSecurityDescriptor(bytes, 0);
                bool userOwnedFile = !directory && userSid != null && security.Owner != null &&
                    security.Owner.Value == userSid;
                if ((!IsTrustedSid(security.Owner) && !userOwnedFile) || security.DiscretionaryAcl == null) {
                    throw new System.IO.IOException("Untrusted backup owner or missing DACL: " + path);
                }
                // Ancestors may allow creating unrelated children, but never replacing the protected path.
                uint forbidden = ancestor ? 0x100D0040u : 0x500D0156u;
                foreach (GenericAce entry in security.DiscretionaryAcl) {
                    if ((entry.AceFlags & AceFlags.InheritOnly) != 0 && ancestor) {
                        continue;
                    }
                    CommonAce ace = entry as CommonAce;
                    if (ace == null || ace.IsCallback) {
                        throw new System.IO.IOException("Unsupported backup ACE: " + path);
                    }
                    if (ace.AceQualifier != AceQualifier.AccessAllowed || IsTrustedSid(ace.SecurityIdentifier)) {
                        continue;
                    }
                    if (userSid != null && ace.SecurityIdentifier.Value == userSid) {
                        // The user can create files, but cannot delete, re-ACL, or redirect the directory.
                        if (directory && (ace.AceFlags & AceFlags.InheritOnly) == 0 &&
                            ((uint)ace.AccessMask & (forbidden & ~0x2u)) != 0) {
                            throw new System.IO.IOException("Unsafe HKCU directory permissions: " + path);
                        }
                        continue;
                    }
                    if (((uint)ace.AccessMask & forbidden) != 0) {
                        throw new System.IO.IOException("Unprivileged write access to backup path: " + path);
                    }
                }
            } finally {
                LocalFree(descriptor);
            }
        }

        private static IntPtr OpenBackupPath(string path, bool directory, bool ancestor, string userSid = null)
        {
            IntPtr handle = CreateFile(
                path, 0x00020080, directory ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | 0x00200000, IntPtr.Zero);
            if (handle == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot lock backup path: " + path);
            }
            try {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((information.FileAttributes & 0x400) != 0 ||
                    ((information.FileAttributes & 0x10) != 0) != directory ||
                    (!directory && information.NumberOfLinks != 1)) {
                    throw new System.IO.IOException("Backup path is a reparse point, hard link, or wrong type: " + path);
                }
                CheckBackupAcl(handle, path, ancestor, directory, userSid);
                return handle;
            } catch {
                CloseHandle(handle);
                throw;
            }
        }

        private static void CreateBackupDirectory(
            string path, string sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FRFX;;;BU)")
        {
            RawSecurityDescriptor descriptor = new RawSecurityDescriptor(sddl);
            byte[] bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try {
                SecurityAttributes attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf(typeof(SecurityAttributes)),
                    Descriptor = pinned.AddrOfPinnedObject()
                };
                if (!CreateDirectory(path, ref attributes)) {
                    int error = Marshal.GetLastWin32Error();
                    if (error != 183) {
                        throw new Win32Exception(error, "Cannot create protected backup directory: " + path);
                    }
                }
            } finally {
                pinned.Free();
            }
        }

        private sealed class BackupDirectoryLock : IDisposable
        {
            public readonly System.Collections.Generic.List<IntPtr> Handles =
                new System.Collections.Generic.List<IntPtr>();

            public void Dispose()
            {
                for (int index = Handles.Count - 1; index >= 0; index--) {
                    CloseHandle(Handles[index]);
                }
                Handles.Clear();
            }
        }

        public static IDisposable LockBackupDirectory(string path, bool userAction = false)
        {
            path = path.TrimEnd('\\');
            string parent = System.IO.Path.GetDirectoryName(path);
            string boundary = System.IO.Path.GetDirectoryName(parent);
            if (String.IsNullOrEmpty(boundary)) {
                throw new System.IO.IOException("Backup path must have a protected application parent.");
            }
            System.Collections.Generic.List<string> directories = new System.Collections.Generic.List<string>();
            for (string current = path; current != null; current = System.IO.Path.GetDirectoryName(current)) {
                directories.Add(current);
            }
            directories.Reverse();
            BackupDirectoryLock guard = new BackupDirectoryLock();
            try {
                foreach (string directory in directories) {
                    bool managed = directory == parent || directory == path;
                    if (managed && !userAction) {
                        CreateBackupDirectory(directory);
                    }
                    guard.Handles.Add(OpenBackupPath(directory, true, !managed));
                }
                string userStore = System.IO.Path.Combine(path, "UserStore");
                if (!userAction) {
                    foreach (string file in System.IO.Directory.GetFileSystemEntries(path)) {
                        if (String.Equals(file, userStore, StringComparison.OrdinalIgnoreCase)) {
                            continue;
                        }
                        IntPtr handle = OpenBackupPath(file, false, false);
                        CloseHandle(handle);
                    }
                }
                return guard;
            } catch {
                guard.Dispose();
                throw;
            }
        }

        public static IDisposable LockUserStore(string path, string userSid = null)
        {
            BackupDirectoryLock guard = new BackupDirectoryLock();
            try {
                guard.Handles.Add(OpenBackupPath(path, true, false, userSid));
                foreach (string file in System.IO.Directory.GetFileSystemEntries(path)) {
                    IntPtr handle = OpenBackupPath(file, false, false, userSid);
                    CloseHandle(handle);
                }
                return guard;
            } catch {
                guard.Dispose();
                throw;
            }
        }

        public static void ValidateProtectedFile(string path)
        {
            IntPtr handle = OpenBackupPath(path, false, false);
            CloseHandle(handle);
        }

        public static void ValidateUserStoreDirectory(string path, string userSid)
        {
            IntPtr handle = OpenBackupPath(path, true, false, userSid);
            CloseHandle(handle);
        }

        public static void SetBackupAccess(string path, string sddl)
        {
            RawSecurityDescriptor descriptor = new RawSecurityDescriptor(sddl);
            byte[] bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            RestoreFileAcl(path, bytes);
        }

        public static void CreateUserStore(string path, string sddl)
        {
            CreateBackupDirectory(path, sddl);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            IntPtr handle, int informationClass, ref int information, uint size);

        public static bool DeleteEmptyUserStore(string path, string userSid)
        {
            IntPtr handle = CreateFile(
                path, 0x00030080, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | 0x00200000, IntPtr.Zero);
            if (handle == new IntPtr(-1)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 2 || error == 3) {
                    return true;
                }
                throw new Win32Exception(error, "Cannot open HKCU backup directory for cleanup.");
            }
            try {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((information.FileAttributes & 0x410) != 0x10) {
                    throw new System.IO.IOException("HKCU backup directory is a reparse point or wrong type.");
                }
                CheckBackupAcl(handle, path, false, true, userSid);
                int delete = 1;
                if (!SetFileInformationByHandle(handle, 4, ref delete, 4)) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 145) {
                        return false;
                    }
                    throw new Win32Exception(error, "Cannot remove empty HKCU backup directory.");
                }
                return true;
            } finally {
                CloseHandle(handle);
            }
        }

        public static bool TryEnablePrivilege(string privilegeName)
        {
            IntPtr tokenHandle;
            if (!OpenProcessToken(
                    GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try {
                Luid luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                TokenPrivileges privileges = new TokenPrivileges {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                };
                if (!AdjustTokenPrivileges(
                        tokenHandle, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return Marshal.GetLastWin32Error() != ERROR_NOT_ALL_ASSIGNED;
            } finally {
                CloseHandle(tokenHandle);
            }
        }

        public static void RestoreFileAcl(string path, byte[] descriptor)
        {
            RawSecurityDescriptor securityDescriptor = new RawSecurityDescriptor(descriptor, 0);
            uint securityInformation =
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            securityInformation |=
                (securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0
                    ? PROTECTED_DACL_SECURITY_INFORMATION
                    : UNPROTECTED_DACL_SECURITY_INFORMATION;
            if (!SetFileSecurity(path, securityInformation, descriptor)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static bool AreSameFile(string firstPath, string secondPath)
        {
            ByHandleFileInformation first = GetFileInformation(firstPath);
            ByHandleFileInformation second = GetFileInformation(secondPath);
            return first.VolumeSerialNumber == second.VolumeSerialNumber &&
                first.FileIndexHigh == second.FileIndexHigh &&
                first.FileIndexLow == second.FileIndexLow;
        }

        private static ByHandleFileInformation GetFileInformation(string path)
        {
            IntPtr handle = CreateFile(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (handle == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try {
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information;
            } finally {
                CloseHandle(handle);
            }
        }
    }
}
"@
}

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = $PSScriptRoot
}

$system32 = Join-Path $SystemRootPath "System32"
$mappings = @(
    [PSCustomObject]@{
        Source = Join-Path $InstallRoot "bpftool.exe"
        Link = Join-Path $system32 "bpftool.exe"
    },
    [PSCustomObject]@{
        Source = Join-Path $InstallRoot "EbpfApi.dll"
        Link = Join-Path $system32 "ebpfapi.dll"
    },
    [PSCustomObject]@{
        Source = Join-Path $InstallRoot "ebpfnetsh.dll"
        Link = Join-Path $system32 "ebpfnetsh.dll"
    },
    [PSCustomObject]@{
        Source = Join-Path $InstallRoot "JIT\ebpfsvc.exe"
        Link = Join-Path $system32 "ebpfsvc.exe"
    },
    [PSCustomObject]@{
        Source = Join-Path $InstallRoot "drivers\eBPFCore.sys"
        Link = Join-Path $system32 "drivers\eBPFCore.sys"
    },
    [PSCustomObject]@{
        Source = Join-Path $InstallRoot "drivers\NetEbpfExt.sys"
        Link = Join-Path $system32 "drivers\NetEbpfExt.sys"
    }
)

function Invoke-ForAllMappings
{
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation)

    $failures = @()
    foreach ($mapping in $mappings) {
        try {
            & $Operation $mapping
        } catch {
            $failures += "$($mapping.Link): $($_.Exception.Message)"
        }
    }

    if ($failures.Count -ne 0) {
        throw ($failures -join [Environment]::NewLine)
    }
}

function Invoke-NativeCommand
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage)

    & $FilePath @ArgumentList | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

function Enable-SystemFileAccess
{
    param([Parameter(Mandatory = $true)][string]$Path)

    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\takeown.exe") `
        -ArgumentList @("/F", $Path) `
        -FailureMessage "Failed to take ownership of $Path"
    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\icacls.exe") `
        -ArgumentList @($Path, "/grant", "*S-1-5-18:(F)") `
        -FailureMessage "Failed to grant SYSTEM access to $Path"
}

function Get-RestorableFileAcl
{
    param([Parameter(Mandatory = $true)][string]$Path)

    $currentAcl = Get-Acl -LiteralPath $Path
    return @{
        Descriptor = $currentAcl.GetSecurityDescriptorBinaryForm()
        Object = $currentAcl
        AutoInherited =
            ($currentAcl.AreAccessRulesCanonical -and
            $currentAcl.Sddl -match "D:.*AI")
    }
}

function Restore-FileAcl
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [hashtable]$Acl)

    [EbpfMsi.NativeSecurity]::TryEnablePrivilege("SeRestorePrivilege") | Out-Null
    if ($Acl.AutoInherited) {
        Set-Acl -LiteralPath $Path -AclObject $Acl.Object
    } else {
        [EbpfMsi.NativeSecurity]::RestoreFileAcl($Path, $Acl.Descriptor)
    }
}

function Test-SameFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FirstPath,

        [Parameter(Mandatory = $true)]
        [string]$SecondPath)

    return [EbpfMsi.NativeSecurity]::AreSameFile($FirstPath, $SecondPath)
}

function Get-BackupCount
{
    return @(
        $mappings |
            Where-Object { Test-Path -LiteralPath ($_.Link + ".ebpf-msi-backup") -PathType Leaf }
    ).Count
}

function Rollback-InstalledLinks
{
    Invoke-ForAllMappings {
        param($mapping)

        $backup = $mapping.Link + ".ebpf-msi-backup"
        $replacement = $mapping.Link + ".ebpf-msi-new"
        $rollback = $mapping.Link + ".ebpf-msi-rollback"
        if (Test-Path -LiteralPath $rollback -PathType Leaf) {
            $originalAcl = Get-RestorableFileAcl -Path $rollback
            try {
                Enable-SystemFileAccess -Path $rollback
                if (Test-Path -LiteralPath $mapping.Link) {
                    Enable-SystemFileAccess -Path $mapping.Link
                    Remove-Item -LiteralPath $mapping.Link -Force
                }
                Move-Item -LiteralPath $rollback -Destination $mapping.Link
                if ((Test-Path -LiteralPath $backup -PathType Leaf) -and
                    (Test-SameFile -FirstPath $backup -SecondPath $mapping.Link)) {
                    Remove-Item -LiteralPath $backup -Force
                }
            } finally {
                $aclPath =
                    if (Test-Path -LiteralPath $mapping.Link -PathType Leaf) {
                        $mapping.Link
                    } elseif (Test-Path -LiteralPath $rollback -PathType Leaf) {
                        $rollback
                    } else {
                        $null
                    }
                if ($null -ne $aclPath) {
                    Restore-FileAcl -Path $aclPath -Acl $originalAcl
                }
            }
        }
        if (Test-Path -LiteralPath $replacement) {
            Remove-Item -LiteralPath $replacement -Force
        }
    }
}

function Restore-OriginalFileAcls
{
    param(
        [Parameter(Mandatory = $true)][hashtable]$OriginalAcls,
        [Parameter(Mandatory = $true)][bool]$CreatedDurableBackups)

    $failures = @()
    foreach ($mapping in $mappings) {
        if (-not $OriginalAcls.ContainsKey($mapping.Link)) {
            continue
        }

        $candidates = @($mapping.Link + ".ebpf-msi-rollback")
        if ($CreatedDurableBackups) {
            $candidates += @(($mapping.Link + ".ebpf-msi-backup"), $mapping.Link)
        } else {
            $candidates += $mapping.Link
        }
        $aclPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if ($null -eq $aclPath) {
            $failures += "$($mapping.Link): original file path is unavailable"
            continue
        }

        try {
            Restore-FileAcl -Path $aclPath -Acl $OriginalAcls[$mapping.Link]
        } catch {
            $failures += "$($mapping.Link): $($_.Exception.Message)"
        }
    }

    if ($failures.Count -ne 0) {
        throw ($failures -join [Environment]::NewLine)
    }
}

function Restore-OriginalLinks
{
    $backupCount = Get-BackupCount
    if ($backupCount -eq 0) {
        Write-Output "No forced-install eBPF hard-link backups were found."
        return
    }
    if ($backupCount -ne $mappings.Count) {
        throw "Only $backupCount of $($mappings.Count) eBPF hard-link backups exist."
    }

    $originalAcls = @{}
    $msiAcls = @{}
    foreach ($mapping in $mappings) {
        $backup = $mapping.Link + ".ebpf-msi-backup"
        if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
            throw "Installed eBPF binary is missing: $($mapping.Source)"
        }
        if (-not (Test-Path -LiteralPath $mapping.Link -PathType Leaf)) {
            throw "Canonical eBPF binary is missing: $($mapping.Link)"
        }
        if (-not (Test-SameFile -FirstPath $mapping.Link -SecondPath $mapping.Source)) {
            throw "Canonical eBPF binary no longer points to the MSI file: $($mapping.Link)"
        }
        if (Test-SameFile -FirstPath $backup -SecondPath $mapping.Link) {
            throw "The backup and canonical eBPF paths unexpectedly point to the same file: $($mapping.Link)"
        }
        $originalAcls[$mapping.Link] = Get-RestorableFileAcl -Path $backup
        $msiAcls[$mapping.Link] = Get-RestorableFileAcl -Path $mapping.Link
    }

    try {
        foreach ($mapping in $mappings) {
            Enable-SystemFileAccess -Path $mapping.Link
            Enable-SystemFileAccess -Path ($mapping.Link + ".ebpf-msi-backup")
        }
        foreach ($mapping in $mappings) {
            Remove-Item -LiteralPath $mapping.Link -Force
            Move-Item -LiteralPath ($mapping.Link + ".ebpf-msi-backup") -Destination $mapping.Link
            Restore-FileAcl -Path $mapping.Link -Acl $originalAcls[$mapping.Link]
            Restore-FileAcl -Path $mapping.Source -Acl $msiAcls[$mapping.Link]
        }
    } catch {
        $restoreError = $_
        $rollbackFailures = @()
        try {
            Restore-MsiLinks
        } catch {
            $rollbackFailures += $_.Exception.Message
        }
        try {
            Invoke-ForAllMappings {
                param($mapping)

                $backup = $mapping.Link + ".ebpf-msi-backup"
                if (Test-Path -LiteralPath $backup -PathType Leaf) {
                    Restore-FileAcl -Path $backup -Acl $originalAcls[$mapping.Link]
                }
                if (Test-Path -LiteralPath $mapping.Source -PathType Leaf) {
                    Restore-FileAcl -Path $mapping.Source -Acl $msiAcls[$mapping.Link]
                }
            }
        } catch {
            $rollbackFailures += $_.Exception.Message
        }
        if ($rollbackFailures.Count -ne 0) {
            throw "$($restoreError.Exception.Message)$([Environment]::NewLine)Failed to roll back link restoration: $($rollbackFailures -join [Environment]::NewLine)"
        }
        throw $restoreError
    }
}

function Restore-MsiLinks
{
    if ((Get-BackupCount) -eq 0 -and
        -not (Test-Path -LiteralPath (Get-ServicePaths).StateFile -PathType Leaf)) {
        return
    }

    Invoke-ForAllMappings {
        param($mapping)

        $backup = $mapping.Link + ".ebpf-msi-backup"
        if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
            throw "Installed eBPF binary is missing during uninstall rollback: $($mapping.Source)"
        }
        if (-not (Test-Path -LiteralPath $mapping.Link -PathType Leaf)) {
            if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) {
                throw "Both the canonical eBPF binary and its backup are missing: $($mapping.Link)"
            }
            New-Item -ItemType HardLink -Path $mapping.Link -Target $mapping.Source | Out-Null
            Remove-BackupFileIfPresent -Path ($mapping.Link + ".ebpf-msi-new")
            return
        }
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if (Test-SameFile -FirstPath $mapping.Link -SecondPath $mapping.Source) {
                return
            }
            if (-not (Test-SameFile -FirstPath $mapping.Link -SecondPath $backup)) {
                throw "The canonical eBPF binary points to neither the backup nor the MSI file: $($mapping.Link)"
            }
        } elseif (Test-SameFile -FirstPath $mapping.Link -SecondPath $mapping.Source) {
            throw "The canonical eBPF binary points to the MSI file but its backup is missing: $($mapping.Link)"
        }
        $originalAcl = Get-RestorableFileAcl -Path $mapping.Link
        $replacement = $mapping.Link + ".ebpf-msi-new"
        try {
            Enable-SystemFileAccess -Path $mapping.Link
            Remove-BackupFileIfPresent -Path $replacement
            New-Item -ItemType HardLink -Path $replacement -Target $mapping.Source |
                Out-Null
            if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) {
                New-Item -ItemType HardLink -Path $backup -Target $mapping.Link |
                    Out-Null
            }
            Remove-Item -LiteralPath $mapping.Link -Force
            Move-Item -LiteralPath $replacement -Destination $mapping.Link
        } finally {
            $originalPath = if (Test-Path -LiteralPath $backup -PathType Leaf) { $backup } else { $mapping.Link }
            Restore-FileAcl -Path $originalPath -Acl $originalAcl
        }
    }
}

function Get-UserStoreOwner
{
    $ownerFile = Join-Path $StateRoot "hkcu-owner.sid"
    if (-not (Test-Path -LiteralPath $ownerFile -PathType Leaf)) {
        return $null
    }
    [EbpfMsi.NativeSecurity]::ValidateProtectedFile($ownerFile)
    return [System.Security.Principal.SecurityIdentifier]::new(
        (Get-Content -LiteralPath $ownerFile -Raw).Trim()).Value
}

function Prepare-UserStore
{
    $userSid = [System.Security.Principal.SecurityIdentifier]::new($InstallingUserSid).Value
    $directoryAccess = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FRFX;;;BU)"
    [EbpfMsi.NativeSecurity]::SetBackupAccess((Split-Path $StateRoot), $directoryAccess)
    [EbpfMsi.NativeSecurity]::SetBackupAccess($StateRoot, $directoryAccess)
    $userStore = Join-Path $StateRoot "UserStore"
    $owner = Get-UserStoreOwner
    if ($null -ne $owner) {
        # Once user access is granted, SYSTEM must not consume or re-ACL the files inside.
        [EbpfMsi.NativeSecurity]::ValidateUserStoreDirectory($userStore, $owner)
        return
    }

    [EbpfMsi.NativeSecurity]::CreateUserStore(
        $userStore, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    $legacyLock = [EbpfMsi.NativeSecurity]::LockUserStore($userStore)
    try {
        foreach ($suffix in @("json", "reg", "pending", "rollback.json", "rollback.reg", "uninstall.json", "uninstall.reg")) {
            $legacyFile = Join-Path $StateRoot "ebpf-store-hkcu.$suffix"
            $destination = Join-Path $userStore "ebpf-store-hkcu.$suffix"
            if (Test-Path -LiteralPath $legacyFile) {
                if (Test-Path -LiteralPath $destination) {
                    throw "Both legacy and current HKCU backups exist: '$legacyFile'."
                }
                Move-Item -LiteralPath $legacyFile -Destination $destination
            }
        }
        foreach ($suffix in @("json", "rollback.json", "pending", "uninstall.json")) {
            $metadata = Join-Path $userStore "ebpf-store-hkcu.$suffix"
            if (Test-Path -LiteralPath $metadata -PathType Leaf) {
                $state = Get-Content -LiteralPath $metadata -Raw | ConvertFrom-Json
                if ([string]::IsNullOrWhiteSpace([string]$state.UserSid)) {
                    Write-Warning "The legacy HKCU backup has no saved user identity; retaining administrator-only access."
                    return
                }
                $userSid = [System.Security.Principal.SecurityIdentifier]::new([string]$state.UserSid).Value
                break
            }
        }
        $ownerFile = Join-Path $StateRoot "hkcu-owner.sid"
        $temporaryOwnerFile = $ownerFile + ".new"
        Set-Content -LiteralPath $temporaryOwnerFile -Value $userSid -Encoding ASCII
        [EbpfMsi.NativeSecurity]::SetBackupAccess(
            $temporaryOwnerFile, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
        foreach ($file in @(Get-ChildItem -LiteralPath $userStore -File -Force)) {
            [EbpfMsi.NativeSecurity]::SetBackupAccess(
                $file.FullName, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;$userSid)")
        }
        [EbpfMsi.NativeSecurity]::SetBackupAccess(
            $userStore, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200ab;;;$userSid)(A;OIIO;0x1301bf;;;$userSid)")
        Move-Item -LiteralPath $temporaryOwnerFile -Destination $ownerFile
    } finally {
        $legacyLock.Dispose()
    }
}

function Get-StorePaths
{
    param([Parameter(Mandatory = $true)][string]$StoreScope)

    $scopeName = $StoreScope.ToLowerInvariant()
    $storeRoot = if ($StoreScope -eq "HKCU") { Join-Path $StateRoot "UserStore" } else { $StateRoot }
    $rollbackStateFile = Join-Path $storeRoot "ebpf-store-$scopeName.rollback.json"
    $legacyPendingFile = Join-Path $storeRoot "ebpf-store-$scopeName.pending"
    if (Test-Path -LiteralPath $legacyPendingFile) {
        if (Test-Path -LiteralPath $rollbackStateFile) {
            throw "Both legacy and current $StoreScope eBPF store rollback metadata exist in '$StateRoot'."
        }
        $rollbackStateFile = $legacyPendingFile
    }
    return @{
        RegistryPath =
            if ([string]::IsNullOrWhiteSpace($StoreRegistryPath)) {
                "$StoreScope\Software\eBPF"
            } else {
                $StoreRegistryPath
            }
        RegistryFile = Join-Path $storeRoot "ebpf-store-$scopeName.reg"
        StateFile = Join-Path $storeRoot "ebpf-store-$scopeName.json"
        RollbackStateFile = $rollbackStateFile
        RollbackRegistryFile = Join-Path $storeRoot "ebpf-store-$scopeName.rollback.reg"
        UninstallStateFile = Join-Path $storeRoot "ebpf-store-$scopeName.uninstall.json"
        UninstallRegistryFile = Join-Path $storeRoot "ebpf-store-$scopeName.uninstall.reg"
    }
}

function Get-RegistryProviderPath
{
    param([Parameter(Mandatory = $true)][string]$RegistryPath)

    if ($RegistryPath.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "Registry::HKEY_LOCAL_MACHINE\" + $RegistryPath.Substring(5)
    }
    if ($RegistryPath.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "Registry::HKEY_CURRENT_USER\" + $RegistryPath.Substring(5)
    }
    throw "Unsupported registry path '$RegistryPath'."
}

function Remove-RegistryTreeIfPresent
{
    param([Parameter(Mandatory = $true)][string]$RegistryPath)

    $providerPath = Get-RegistryProviderPath -RegistryPath $RegistryPath
    if (Test-Path -LiteralPath $providerPath) {
        Remove-Item -LiteralPath $providerPath -Recurse -Force
    }
}

function Get-ServicePaths
{
    $paths = @{
        StateFile = Join-Path $StateRoot "ebpf-services.original.json"
        RollbackStateFile = Join-Path $StateRoot "ebpf-services.rollback.json"
        UninstallRollbackFile = Join-Path $StateRoot "ebpf-services.uninstall-rollback.json"
    }
    foreach ($entry in @(
        @{ Key = "StateFile"; LegacyFileName = "ebpf-services.json" },
        @{ Key = "RollbackStateFile"; LegacyFileName = "ebpf-services.pending.json" }
    )) {
        $legacyFile = Join-Path $StateRoot $entry.LegacyFileName
        if (Test-Path -LiteralPath $legacyFile) {
            if (Test-Path -LiteralPath $paths[$entry.Key]) {
                throw "Both legacy and current eBPF service $($entry.Key) metadata exist in '$StateRoot'."
            }
            $paths[$entry.Key] = $legacyFile
        }
    }
    return $paths
}

function Get-ServiceRegistryPath
{
    param([Parameter(Mandatory = $true)][string]$Name)

    return "HKLM\SYSTEM\CurrentControlSet\Services\$Name"
}

function Get-ServiceState
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$RegistryFile)

    $providerPath = Get-RegistryProviderPath -RegistryPath (Get-ServiceRegistryPath -Name $Name)
    if (-not (Test-Path -LiteralPath $providerPath)) {
        return [PSCustomObject]@{
            Name = $Name
            Existed = $false
            WasRunning = $false
            RegistryFile = $null
        }
    }

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $values = Get-ItemProperty -LiteralPath $providerPath
    $securityDescriptor = & (Join-Path $env:SystemRoot "System32\sc.exe") sdshow $Name
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read the $Name service security descriptor."
    }
    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
        -ArgumentList @("export", (Get-ServiceRegistryPath -Name $Name), $RegistryFile, "/y") `
        -FailureMessage "Failed to save the $Name service registry key"

    [string[]]$dependencies = @()
    if ($null -ne $values.PSObject.Properties["DependOnService"]) {
        $dependencies =
            @($values.DependOnService) |
                ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    return [PSCustomObject]@{
        Name = $Name
        Existed = $true
        WasRunning =
            $null -ne $service -and
            $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running
        RegistryFile = [System.IO.Path]::GetFileName($RegistryFile)
        ImagePath = [string]$values.ImagePath
        Start = [int]$values.Start
        Type = [int]$values.Type
        ErrorControl = [int]$values.ErrorControl
        DisplayName =
            if ($null -ne $values.PSObject.Properties["DisplayName"]) {
                [string]$values.DisplayName
            } else {
                $null
            }
        ObjectName =
            if ($null -ne $values.PSObject.Properties["ObjectName"]) {
                [string]$values.ObjectName
            } else {
                $null
            }
        DependOnService = $dependencies
        DependOnGroup =
            if ($null -ne $values.PSObject.Properties["DependOnGroup"]) {
                @($values.DependOnGroup)
            } else {
                @()
            }
        Description =
            if ($null -ne $values.PSObject.Properties["Description"]) {
                [string]$values.Description
            } else {
                $null
            }
        HasDescription = $null -ne $values.PSObject.Properties["Description"]
        DelayedAutoStart =
            if ($null -ne $values.PSObject.Properties["DelayedAutoStart"]) {
                [int]$values.DelayedAutoStart
            } else {
                $null
            }
        HasDelayedAutoStart = $null -ne $values.PSObject.Properties["DelayedAutoStart"]
        HasServiceSidType = $null -ne $values.PSObject.Properties["ServiceSidType"]
        ServiceSidType =
            if ($null -ne $values.PSObject.Properties["ServiceSidType"]) {
                [int]$values.ServiceSidType
            } else {
                $null
            }
        SecurityDescriptor = ($securityDescriptor | Where-Object { $_ -match "^D:" } | Select-Object -First 1)
    }
}

function Get-ScStartName
{
    param(
        [Parameter(Mandatory = $true)][int]$Start,
        [AllowNull()][object]$DelayedAutoStart)

    if ($Start -eq 2 -and $null -ne $DelayedAutoStart -and [int]$DelayedAutoStart -ne 0) {
        return "delayed-auto"
    }
    switch ($Start) {
        0 { return "boot" }
        1 { return "system" }
        2 { return "auto" }
        3 { return "demand" }
        4 { return "disabled" }
        default { throw "Unsupported service start value '$Start'." }
    }
}

function Get-ScTypeName
{
    param([Parameter(Mandatory = $true)][int]$Type)

    switch ($Type) {
        1 { return "kernel" }
        2 { return "filesys" }
        16 { return "own" }
        32 { return "share" }
        default { throw "Unsupported service type value '$Type'." }
    }
}

function Get-ScErrorName
{
    param([Parameter(Mandatory = $true)][int]$ErrorControl)

    switch ($ErrorControl) {
        0 { return "ignore" }
        1 { return "normal" }
        2 { return "severe" }
        3 { return "critical" }
        default { throw "Unsupported service error-control value '$ErrorControl'." }
    }
}

function Stop-ServiceIfPresent
{
    param([Parameter(Mandatory = $true)][string]$Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $service -and
        $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $Name -Force
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(60))
    }
}

function Remove-ServiceIfPresent
{
    param([Parameter(Mandatory = $true)][string]$Name)

    Stop-ServiceIfPresent -Name $Name
    if ($null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @("delete", $Name) `
            -FailureMessage "Failed to delete the $Name service"
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            if ($null -eq (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
                return
            }
            Start-Sleep -Seconds 1
        }
        throw "The $Name service remained pending deletion."
    }
}

function Set-ServiceFromState
{
    param(
        [Parameter(Mandatory = $true)][object]$ServiceState,
        [Parameter(Mandatory = $true)][bool]$StartIfPreviouslyRunning)

    $name = [string]$ServiceState.Name
    if (-not [bool]$ServiceState.Existed) {
        Remove-ServiceIfPresent -Name $name
        return
    }

    if ($null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
        $createArguments = @(
            "create",
            $name,
            "type=",
            (Get-ScTypeName -Type ([int]$ServiceState.Type)),
            "start=",
            (Get-ScStartName -Start ([int]$ServiceState.Start) -DelayedAutoStart $null),
            "error=",
            (Get-ScErrorName -ErrorControl ([int]$ServiceState.ErrorControl)),
            "binPath=",
            [string]$ServiceState.ImagePath)
        if (-not [string]::IsNullOrWhiteSpace([string]$ServiceState.DisplayName)) {
            $createArguments += @("DisplayName=", [string]$ServiceState.DisplayName)
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$ServiceState.ObjectName)) {
            $createArguments += @("obj=", [string]$ServiceState.ObjectName)
        }
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList $createArguments `
            -FailureMessage "Failed to recreate the $name service"
    }

    Stop-ServiceIfPresent -Name $name
    $registryFile = Join-Path $StateRoot ([string]$ServiceState.RegistryFile)
    if (-not (Test-Path -LiteralPath $registryFile -PathType Leaf)) {
        throw "The saved $name service registry file is missing: $registryFile"
    }
    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
        -ArgumentList @("import", $registryFile) `
        -FailureMessage "Failed to restore the $name service registry key"

    $arguments = @(
        "config",
        $name,
        "type=",
        (Get-ScTypeName -Type ([int]$ServiceState.Type)),
        "start=",
        (Get-ScStartName -Start ([int]$ServiceState.Start) -DelayedAutoStart $ServiceState.DelayedAutoStart),
        "error=",
        (Get-ScErrorName -ErrorControl ([int]$ServiceState.ErrorControl)),
        "binPath=",
        [string]$ServiceState.ImagePath)
    if (-not [string]::IsNullOrWhiteSpace([string]$ServiceState.DisplayName)) {
        $arguments += @("DisplayName=", [string]$ServiceState.DisplayName)
    }
    $dependencies = @($ServiceState.DependOnService)
    $dependencyState = $ServiceState
    if ($null -eq $dependencyState.PSObject.Properties["DependOnGroup"]) {
        # Older snapshots preserve group dependencies only in the registry export imported above.
        $dependencyState = Get-ItemProperty `
            -LiteralPath (Get-RegistryProviderPath -RegistryPath (Get-ServiceRegistryPath -Name $name))
    }
    if ($null -ne $dependencyState.PSObject.Properties["DependOnGroup"]) {
        $dependencies += @($dependencyState.DependOnGroup) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { "+$_" }
    }
    if ($dependencies.Count -ne 0) {
        $arguments += @("depend=", ($dependencies -join "/"))
    } else {
        $arguments += @("depend=", "/")
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ServiceState.ObjectName)) {
        $arguments += @("obj=", [string]$ServiceState.ObjectName)
    }
    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
        -ArgumentList $arguments `
        -FailureMessage "Failed to restore the $name service configuration"

    if ([bool]$ServiceState.HasDescription) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @("description", $name, [string]$ServiceState.Description) `
            -FailureMessage "Failed to restore the $name service description"
    } else {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @("description", $name, "") `
            -FailureMessage "Failed to clear the $name service description"
    }
    if (-not [bool]$ServiceState.HasDelayedAutoStart) {
        Remove-ItemProperty `
            -LiteralPath (Get-RegistryProviderPath -RegistryPath (Get-ServiceRegistryPath -Name $name)) `
            -Name "DelayedAutoStart" `
            -ErrorAction SilentlyContinue
    }
    if ([int]$ServiceState.Type -in @(16, 32) -and [bool]$ServiceState.HasServiceSidType) {
        $sidType =
            switch ([int]$ServiceState.ServiceSidType) {
                0 { "none" }
                1 { "unrestricted" }
                3 { "restricted" }
                default { throw "Unsupported service SID type '$($ServiceState.ServiceSidType)' for $name." }
            }
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @("sidtype", $name, $sidType) `
            -FailureMessage "Failed to restore the $name service SID type"
    } elseif ([int]$ServiceState.Type -in @(16, 32)) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @("sidtype", $name, "none") `
            -FailureMessage "Failed to restore the $name service SID type"
        Remove-ItemProperty `
            -LiteralPath (Get-RegistryProviderPath -RegistryPath (Get-ServiceRegistryPath -Name $name)) `
            -Name "ServiceSidType" `
            -ErrorAction SilentlyContinue
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ServiceState.SecurityDescriptor)) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @("sdset", $name, [string]$ServiceState.SecurityDescriptor) `
            -FailureMessage "Failed to restore the $name service security descriptor"
    }
    if ($StartIfPreviouslyRunning -and [bool]$ServiceState.WasRunning) {
        Start-Service -Name $name
        (Get-Service -Name $name).WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(60))
    }
}

function Install-MsiEbpfService
{
    $name = "eBPFSvc"
    $servicePath =
        if ($UseCanonicalServicePath) {
            Join-Path $SystemRootPath "System32\ebpfsvc.exe"
        } else {
            Join-Path $InstallRoot "JIT\ebpfsvc.exe"
        }
    $imagePath = '"' + $servicePath + '"'
    if ($null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
            -ArgumentList @(
                "create",
                $name,
                "type=",
                "own",
                "start=",
                "auto",
                "error=",
                "normal",
                "binPath=",
                $imagePath,
                "DisplayName=",
                "eBPF Service") `
            -FailureMessage "Failed to create the eBPFSvc service"
    }

    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
        -ArgumentList @(
            "config",
            $name,
            "type=",
            "own",
            "start=",
            "auto",
            "error=",
            "normal",
            "binPath=",
            $imagePath,
            "obj=",
            "NT AUTHORITY\LocalService",
            "DisplayName=",
            "eBPF Service") `
        -FailureMessage "Failed to configure the eBPFSvc service"
    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
        -ArgumentList @("description", $name, "eBPF Service") `
        -FailureMessage "Failed to configure the eBPFSvc service description"
    Invoke-NativeCommand `
        -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
        -ArgumentList @("sidtype", $name, "restricted") `
        -FailureMessage "Failed to configure the eBPFSvc service SID type"
}

function Read-ServiceState
{
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $state = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([int]$state.SchemaVersion -ne 1) {
        throw "Unsupported eBPF service backup schema version '$($state.SchemaVersion)'."
    }
    $savedNames = @($state.Services | ForEach-Object { [string]$_.Name })
    if ($savedNames.Count -ne $ServiceNames.Count -or
        @($ServiceNames | Where-Object { $_ -notin $savedNames }).Count -ne 0) {
        throw "The eBPF service backup does not contain the expected service set."
    }
    foreach ($serviceState in @($state.Services)) {
        if ([bool]$serviceState.Existed) {
            $registryFileName = [string]$serviceState.RegistryFile
            $expectedFiles = @("original", "rollback", "uninstall-rollback") |
                ForEach-Object { "$($serviceState.Name).$_.reg" }
            if ($registryFileName -notin $expectedFiles -or
                -not (Test-Path -LiteralPath (Join-Path $StateRoot $registryFileName) -PathType Leaf)) {
                throw "The saved $($serviceState.Name) service registry file is missing or invalid."
            }
        }
    }
    return $state
}

function Save-CurrentServices
{
    param(
        [Parameter(Mandatory = $true)][string]$StateFile,
        [Parameter(Mandatory = $true)][string]$FileSuffix)

    $services = @()
    foreach ($name in $ServiceNames) {
        $services += Get-ServiceState `
            -Name $name `
            -RegistryFile (Join-Path $StateRoot "$name.$FileSuffix.reg")
    }
    [PSCustomObject]@{
        SchemaVersion = 1
        Services = $services
        OwnerProductCode = $OwnerProductCode
        OwnerUpgradeCode = $OwnerUpgradeCode
        Created = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

function Apply-ServiceState
{
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][bool]$StartIfPreviouslyRunning)

    foreach ($serviceState in @($State.Services)) {
        Set-ServiceFromState `
            -ServiceState $serviceState `
            -StartIfPreviouslyRunning $StartIfPreviouslyRunning
    }
}

function Remove-ServiceStateFiles
{
    param([Parameter(Mandatory = $true)][string]$FileSuffix)

    foreach ($name in $ServiceNames) {
        Remove-BackupFileIfPresent -Path (Join-Path $StateRoot "$name.$FileSuffix.reg")
    }
}

function Remove-BackupFileIfPresent
{
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
}

function Backup-Services
{
    $paths = Get-ServicePaths
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    if ((Test-Path -LiteralPath $paths.RollbackStateFile) -or
        (Test-Path -LiteralPath $paths.UninstallRollbackFile)) {
        throw "Incomplete eBPF service transaction exists in '$StateRoot'."
    }

    $shouldCreateDurableBackup = -not (Test-Path -LiteralPath $paths.StateFile -PathType Leaf)
    if ($shouldCreateDurableBackup) {
        $existingOriginalFiles =
            @($ServiceNames | Where-Object {
                Test-Path -LiteralPath (Join-Path $StateRoot "$_.original.reg") -PathType Leaf
            })
        if ($existingOriginalFiles.Count -ne 0) {
            throw "Incomplete eBPF service backup exists in '$StateRoot'."
        }
    }
    Save-CurrentServices -StateFile $paths.RollbackStateFile -FileSuffix "rollback"
    $rollbackState = Read-ServiceState -Path $paths.RollbackStateFile
    $rollbackState | Add-Member -NotePropertyName CreatedDurableBackup -NotePropertyValue $shouldCreateDurableBackup
    $rollbackState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $paths.RollbackStateFile -Encoding UTF8
    if ($shouldCreateDurableBackup) {
        Save-CurrentServices -StateFile $paths.StateFile -FileSuffix "original"
    } else {
        Read-ServiceState -Path $paths.StateFile | Out-Null
    }
}

function Rollback-ServiceTransaction
{
    $paths = Get-ServicePaths
    $rollbackState = Read-ServiceState -Path $paths.RollbackStateFile
    if ($null -eq $rollbackState) {
        return
    }

    Apply-ServiceState -State $rollbackState -StartIfPreviouslyRunning $true
    Remove-ServiceStateFiles -FileSuffix "rollback"
    Remove-Item -LiteralPath $paths.RollbackStateFile -Force
    if ([bool]$rollbackState.CreatedDurableBackup) {
        Remove-ServiceStateFiles -FileSuffix "original"
        Remove-Item -LiteralPath $paths.StateFile -Force
    }
}

function Remove-MsiServices
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.StateFile
    if ($null -eq $state) {
        foreach ($name in $ServiceNames) {
            Remove-ServiceIfPresent -Name $name
        }
        return
    }

    foreach ($serviceState in @($state.Services)) {
        if (-not [bool]$serviceState.Existed) {
            Remove-ServiceIfPresent -Name ([string]$serviceState.Name)
        }
    }
}

function Prepare-ServiceRestore
{
    $paths = Get-ServicePaths
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    if (Test-Path -LiteralPath $paths.UninstallRollbackFile) {
        throw "Incomplete eBPF service restoration exists in '$StateRoot'."
    }

    # Commit runs after RemoveFiles, so retain a copy in the already validated, protected directory.
    $cleanupScript = Join-Path $StateRoot "ForceEbpfStack.cleanup.ps1"
    Copy-Item -LiteralPath $PSCommandPath -Destination $cleanupScript -Force
    [EbpfMsi.NativeSecurity]::SetBackupAccess(
        $cleanupScript, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
    Save-CurrentServices -StateFile $paths.UninstallRollbackFile -FileSuffix "uninstall-rollback"
}

function Restore-Services
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.StateFile
    if ($null -eq $state) {
        return
    }
    Apply-ServiceState -State $state -StartIfPreviouslyRunning $true
}

function Rollback-ServiceRestore
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.UninstallRollbackFile
    if ($null -eq $state) {
        return
    }

    Apply-ServiceState -State $state -StartIfPreviouslyRunning $true
    Remove-ServiceStateFiles -FileSuffix "uninstall-rollback"
    Remove-Item -LiteralPath $paths.UninstallRollbackFile -Force
}

function Get-CurrentUserSid
{
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Assert-StoreRegistryPath
{
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][hashtable]$Paths)

    if ($RegistryPath -ine $Paths.RegistryPath -or
        -not $RegistryPath.StartsWith("$Scope\Software\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The saved $Scope registry destination is invalid: '$RegistryPath'."
    }
}

function Import-StoreRegistryFile
{
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RegistryPath)

    $logicalRoot =
        if ($Scope -eq "HKCU") { "HKEY_CURRENT_USER" } else { "HKEY_LOCAL_MACHINE" }
    $logicalPath = $logicalRoot + $RegistryPath.Substring(4)
    $lines = @(Get-Content -LiteralPath $Path)
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = $lines[$index].TrimStart()
        if ($line.StartsWith("[")) {
            if (-not $line.EndsWith("]")) {
                throw "Invalid registry export header in '$Path'."
            }
            $key = $line.Substring(1, $line.Length - 2)
            if ($key -ine $logicalPath -and
                -not $key.StartsWith($logicalPath + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Registry export '$Path' contains a key outside the saved $Scope store."
            }
        }
    }
    $importFile = $Path + ".import"
    try {
        $lines | Set-Content -LiteralPath $importFile -Encoding Unicode
        Remove-RegistryTreeIfPresent -RegistryPath $RegistryPath
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
            -ArgumentList @("import", $importFile) `
            -FailureMessage "Failed to restore the $Scope eBPF store"
    } finally {
        if (Test-Path -LiteralPath $importFile) {
            Remove-Item -LiteralPath $importFile -Force
        }
    }
}

function Backup-Store
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for BackupStore."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if ((Test-Path -LiteralPath $paths.RollbackStateFile) -or
        (Test-Path -LiteralPath $paths.RollbackRegistryFile)) {
        throw "Incomplete $Scope eBPF store transaction exists in '$StateRoot'."
    }

    $providerPath = Get-RegistryProviderPath -RegistryPath $paths.RegistryPath
    $storeExisted = Test-Path -LiteralPath $providerPath
    if ($storeExisted) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
            -ArgumentList @("export", $paths.RegistryPath, $paths.RollbackRegistryFile, "/y") `
            -FailureMessage "Failed to save the current $Scope eBPF store for rollback"
    }

    $shouldCreateDurableBackup = -not (Test-Path -LiteralPath $paths.StateFile -PathType Leaf)
    if ($shouldCreateDurableBackup) {
        if (Test-Path -LiteralPath $paths.RegistryFile) {
            throw "Incomplete $Scope eBPF store backup exists in '$StateRoot'."
        }
        if ($storeExisted) {
            Copy-Item -LiteralPath $paths.RollbackRegistryFile -Destination $paths.RegistryFile
        }

        $state = [PSCustomObject]@{
            SchemaVersion = 1
            Scope = $Scope
            RegistryPath = $paths.RegistryPath
            StoreExisted = $storeExisted
            UserSid = if ($Scope -eq "HKCU") { Get-CurrentUserSid } else { $null }
            OwnerProductCode = $OwnerProductCode
            OwnerUpgradeCode = $OwnerUpgradeCode
            Created = (Get-Date).ToUniversalTime().ToString("o")
        }
        $temporaryStateFile = $paths.StateFile + ".new"
        $state | ConvertTo-Json | Set-Content -LiteralPath $temporaryStateFile -Encoding UTF8
        Move-Item -LiteralPath $temporaryStateFile -Destination $paths.StateFile
    } else {
        Read-StoreState -Paths $paths | Out-Null
    }

    $rollbackState = [PSCustomObject]@{
        SchemaVersion = 1
        Scope = $Scope
        RegistryPath = $paths.RegistryPath
        StoreExisted = $storeExisted
        UserSid = if ($Scope -eq "HKCU") { Get-CurrentUserSid } else { $null }
        CreatedDurableBackup = $shouldCreateDurableBackup
    }
    $rollbackState | ConvertTo-Json | Set-Content -LiteralPath $paths.RollbackStateFile -Encoding UTF8
}

function Read-StoreState
{
    param([Parameter(Mandatory = $true)][hashtable]$Paths)

    if (-not (Test-Path -LiteralPath $Paths.StateFile -PathType Leaf)) {
        return $null
    }
    $state = Get-Content -LiteralPath $Paths.StateFile -Raw | ConvertFrom-Json
    if ([int]$state.SchemaVersion -ne 1) {
        throw "Unsupported eBPF store backup schema version '$($state.SchemaVersion)'."
    }
    if ([string]$state.Scope -ne $Scope) {
        throw "The eBPF store backup scope does not match '$Scope'."
    }
    Assert-StoreRegistryPath -RegistryPath ([string]$state.RegistryPath) -Paths $Paths
    return $state
}

function Test-StoreRestoreUser
{
    param([AllowNull()][object]$State)

    if ($Scope -ne "HKCU") {
        return $true
    }
    if ($null -eq $State) {
        Write-Warning "Skipping HKCU restoration: no saved installing-user identity. The current user's store is unchanged."
        return $false
    }
    if ([string]$State.UserSid -ne (Get-CurrentUserSid)) {
        Write-Warning "Skipping HKCU restoration: backup belongs to '$($State.UserSid)', not the current user. Retaining the backup."
        return $false
    }
    return $true
}

function Rollback-StoreTransaction
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store rollback."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if (-not (Test-Path -LiteralPath $paths.RollbackStateFile -PathType Leaf)) {
        return
    }

    $rollbackState = Get-Content -LiteralPath $paths.RollbackStateFile -Raw | ConvertFrom-Json
    if ([int]$rollbackState.SchemaVersion -ne 1 -or [string]$rollbackState.Scope -ne $Scope) {
        throw "Invalid $Scope eBPF store rollback transaction."
    }
    if (-not (Test-StoreRestoreUser -State $rollbackState)) {
        return
    }

    Assert-StoreRegistryPath -RegistryPath ([string]$rollbackState.RegistryPath) -Paths $paths
    if ([bool]$rollbackState.StoreExisted) {
        if (-not (Test-Path -LiteralPath $paths.RollbackRegistryFile -PathType Leaf)) {
            throw "The $Scope eBPF rollback store file is missing: $($paths.RollbackRegistryFile)"
        }
        Import-StoreRegistryFile -Path $paths.RollbackRegistryFile -RegistryPath ([string]$rollbackState.RegistryPath)
    } else {
        Remove-RegistryTreeIfPresent -RegistryPath ([string]$rollbackState.RegistryPath)
    }

    Remove-Item -LiteralPath $paths.RollbackRegistryFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $paths.RollbackStateFile -Force
    if ([bool]$rollbackState.CreatedDurableBackup) {
        Remove-Item -LiteralPath $paths.RegistryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $paths.StateFile -Force
    }
}

function Restore-Store
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store restoration."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    $state = Read-StoreState -Paths $paths
    if (-not (Test-StoreRestoreUser -State $state)) {
        return
    }
    $uninstallState = $null
    if ($Scope -eq "HKCU" -and (Test-Path -LiteralPath $paths.UninstallStateFile -PathType Leaf)) {
        $uninstallState = Get-Content -LiteralPath $paths.UninstallStateFile -Raw | ConvertFrom-Json
        if (-not (Test-StoreRestoreUser -State $uninstallState)) {
            return
        }
    }
    if ($null -eq $state) {
        Remove-RegistryTreeIfPresent -RegistryPath $paths.RegistryPath
        return
    }

    if ([bool]$state.StoreExisted) {
        if (-not (Test-Path -LiteralPath $paths.RegistryFile -PathType Leaf)) {
            throw "The saved $Scope eBPF store file is missing: $($paths.RegistryFile)"
        }
        Import-StoreRegistryFile -Path $paths.RegistryFile -RegistryPath ([string]$state.RegistryPath)
    } else {
        Remove-RegistryTreeIfPresent -RegistryPath ([string]$state.RegistryPath)
    }

    if ($null -ne $uninstallState) {
        $uninstallState | Add-Member -NotePropertyName RestoreCompleted -NotePropertyValue $true -Force
        $uninstallState | ConvertTo-Json | Set-Content -LiteralPath $paths.UninstallStateFile -Encoding UTF8
    }
}

function Prepare-StoreRestore
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store restoration preparation."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if ((Test-Path -LiteralPath $paths.UninstallStateFile) -or
        (Test-Path -LiteralPath $paths.UninstallRegistryFile)) {
        throw "Incomplete $Scope eBPF store uninstall transaction exists in '$StateRoot'."
    }
    if ($Scope -eq "HKCU" -and -not (Test-StoreRestoreUser -State (Read-StoreState -Paths $paths))) {
        return
    }

    $providerPath = Get-RegistryProviderPath -RegistryPath $paths.RegistryPath
    $storeExisted = Test-Path -LiteralPath $providerPath
    if ($storeExisted) {
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
            -ArgumentList @("export", $paths.RegistryPath, $paths.UninstallRegistryFile, "/y") `
            -FailureMessage "Failed to save the current $Scope eBPF store for uninstall rollback"
    }

    [PSCustomObject]@{
        SchemaVersion = 1
        Scope = $Scope
        RegistryPath = $paths.RegistryPath
        StoreExisted = $storeExisted
        UserSid = if ($Scope -eq "HKCU") { Get-CurrentUserSid } else { $null }
        RestoreCompleted = $false
    } | ConvertTo-Json | Set-Content -LiteralPath $paths.UninstallStateFile -Encoding UTF8
}

function Rollback-StoreRestore
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store restoration rollback."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if (-not (Test-Path -LiteralPath $paths.UninstallStateFile -PathType Leaf)) {
        return
    }

    $state = Get-Content -LiteralPath $paths.UninstallStateFile -Raw | ConvertFrom-Json
    if ([int]$state.SchemaVersion -ne 1 -or [string]$state.Scope -ne $Scope) {
        throw "Invalid pending $Scope eBPF store uninstall transaction."
    }
    if (-not (Test-StoreRestoreUser -State $state)) {
        return
    }

    Assert-StoreRegistryPath -RegistryPath ([string]$state.RegistryPath) -Paths $paths
    if ([bool]$state.StoreExisted) {
        if (-not (Test-Path -LiteralPath $paths.UninstallRegistryFile -PathType Leaf)) {
            throw "The $Scope eBPF uninstall rollback store file is missing: $($paths.UninstallRegistryFile)"
        }
        Import-StoreRegistryFile -Path $paths.UninstallRegistryFile -RegistryPath ([string]$state.RegistryPath)
    } else {
        Remove-RegistryTreeIfPresent -RegistryPath ([string]$state.RegistryPath)
    }

    Remove-Item -LiteralPath $paths.UninstallRegistryFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $paths.UninstallStateFile -Force
}

function Commit-StoreRestore
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store restoration commit."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if ($Scope -eq "HKCU") {
        $uninstallState =
            if (Test-Path -LiteralPath $paths.UninstallStateFile -PathType Leaf) {
                Get-Content -LiteralPath $paths.UninstallStateFile -Raw | ConvertFrom-Json
            } else {
                $null
            }
        if ($null -eq $uninstallState -or
            $null -eq $uninstallState.PSObject.Properties["RestoreCompleted"] -or
            -not [bool]$uninstallState.RestoreCompleted) {
            Write-Warning "HKCU restoration was not completed; retaining the original HKCU backup."
            Remove-BackupFileIfPresent -Path $paths.UninstallRegistryFile
            Remove-BackupFileIfPresent -Path $paths.UninstallStateFile
            return
        }
    }
    foreach ($path in @(
        $paths.RegistryFile, $paths.StateFile, $paths.RollbackStateFile, $paths.RollbackRegistryFile,
        $paths.UninstallRegistryFile, $paths.UninstallStateFile)) {
        Remove-BackupFileIfPresent -Path $path
    }
}

$backupLock = $null
$userStoreLock = $null
try {
    if ($Action -match "(Services|Store)$" -or $Action -eq "CommitRestoreAll") {
        $StateRoot = [System.IO.Path]::GetFullPath($StateRoot)
        $userStoreAction = $Scope -eq "HKCU"
        $backupLock = [EbpfMsi.NativeSecurity]::LockBackupDirectory($StateRoot, $userStoreAction)
        if ($userStoreAction) {
            $owner = Get-UserStoreOwner
            if ($null -eq $owner -or $owner -ne (Get-CurrentUserSid)) {
                Write-Warning "Skipping HKCU action '$Action': the current user does not own the installer's HKCU backup area."
                return
            }
            $userStoreLock = [EbpfMsi.NativeSecurity]::LockUserStore((Join-Path $StateRoot "UserStore"), $owner)
        }
    }
    switch ($Action) {
        "Install" {
            $originalAcls = @{}
            $backupCount = Get-BackupCount
            if ($backupCount -ne 0 -and $backupCount -ne $mappings.Count) {
                throw "Only $backupCount of $($mappings.Count) eBPF hard-link backups exist."
            }
            $createDurableBackups = $backupCount -eq 0
            foreach ($mapping in $mappings) {
                $backup = $mapping.Link + ".ebpf-msi-backup"
                $replacement = $mapping.Link + ".ebpf-msi-new"
                $rollback = $mapping.Link + ".ebpf-msi-rollback"
                if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
                    throw "Installed eBPF binary is missing: $($mapping.Source)"
                }
                if (-not (Test-Path -LiteralPath $mapping.Link -PathType Leaf)) {
                    throw "Canonical eBPF binary is missing: $($mapping.Link)"
                }
                if ((Test-Path -LiteralPath $replacement) -or (Test-Path -LiteralPath $rollback)) {
                    throw "Stale eBPF hard-link staging file exists for: $($mapping.Link)"
                }
                $originalAcls[$mapping.Link] = Get-RestorableFileAcl -Path $mapping.Link
                if (-not $createDurableBackups -and (Test-SameFile -FirstPath $backup -SecondPath $mapping.Link)) {
                    throw "The backup and canonical eBPF paths unexpectedly point to the same file: $($mapping.Link)"
                }
            }

            try {
                foreach ($mapping in $mappings) {
                    Enable-SystemFileAccess -Path $mapping.Link
                }

                foreach ($mapping in $mappings) {
                    Write-Output "Staging hard links for $($mapping.Link)"
                    New-Item -ItemType HardLink -Path ($mapping.Link + ".ebpf-msi-rollback") -Target $mapping.Link |
                        Out-Null
                    if ($createDurableBackups) {
                        New-Item -ItemType HardLink -Path ($mapping.Link + ".ebpf-msi-backup") -Target $mapping.Link |
                            Out-Null
                    }
                    New-Item -ItemType HardLink -Path ($mapping.Link + ".ebpf-msi-new") -Target $mapping.Source |
                        Out-Null
                }

                foreach ($mapping in $mappings) {
                    Remove-Item -LiteralPath $mapping.Link -Force
                    Move-Item -LiteralPath ($mapping.Link + ".ebpf-msi-new") -Destination $mapping.Link
                    Restore-FileAcl `
                        -Path ($mapping.Link + ".ebpf-msi-rollback") `
                        -Acl $originalAcls[$mapping.Link]
                }
            } catch {
                $installError = $_
                $rollbackError = $null
                $aclError = $null
                try {
                    Rollback-InstalledLinks
                } catch {
                    $rollbackError = $_
                }
                try {
                    Restore-OriginalFileAcls `
                        -OriginalAcls $originalAcls `
                        -CreatedDurableBackups $createDurableBackups
                } catch {
                    $aclError = $_
                }
                $failureMessages = @($installError.Exception.Message)
                if ($null -ne $rollbackError) {
                    $failureMessages += "Link restoration failure: $($rollbackError.Exception.Message)"
                }
                if ($null -ne $aclError) {
                    $failureMessages += "ACL restoration failure: $($aclError.Exception.Message)"
                }
                throw ($failureMessages -join [Environment]::NewLine)
            }
        }

        "Rollback" {
            Rollback-InstalledLinks
        }

        "Commit" {
            Invoke-ForAllMappings {
                param($mapping)

                $rollback = $mapping.Link + ".ebpf-msi-rollback"
                if (Test-Path -LiteralPath $rollback -PathType Leaf) {
                    $rollbackAcl = Get-RestorableFileAcl -Path $rollback
                    $restorePath =
                        @(($mapping.Link + ".ebpf-msi-backup"), $mapping.Source) |
                            Where-Object {
                                (Test-Path -LiteralPath $_ -PathType Leaf) -and
                                (Test-SameFile -FirstPath $rollback -SecondPath $_)
                            } |
                            Select-Object -First 1
                    try {
                        Enable-SystemFileAccess -Path $rollback
                        Remove-Item -LiteralPath $rollback -Force
                    } finally {
                        if ($null -ne $restorePath -and (Test-Path -LiteralPath $restorePath -PathType Leaf)) {
                            Restore-FileAcl -Path $restorePath -Acl $rollbackAcl
                        }
                    }
                }
            }
        }

        "InstallEbpfSvc" {
            Install-MsiEbpfService
        }

        "BackupServices" {
            Backup-Services
        }

        "RollbackServices" {
            Rollback-ServiceTransaction
        }

        "CommitServices" {
            $paths = Get-ServicePaths
            Remove-ServiceStateFiles -FileSuffix "rollback"
            Remove-BackupFileIfPresent -Path $paths.RollbackStateFile
        }

        "PrepareRestoreServices" {
            Prepare-ServiceRestore
        }

        "RemoveServices" {
            Remove-MsiServices
        }

        "RestoreServices" {
            Restore-Services
        }

        "StopServices" {
            $failures = @()
            for ($index = $ServiceNames.Count - 1; $index -ge 0; $index--) {
                try {
                    Stop-ServiceIfPresent -Name $ServiceNames[$index]
                } catch {
                    $failures += "$($ServiceNames[$index]): $($_.Exception.Message)"
                }
            }
            if ($failures.Count -ne 0) {
                throw ($failures -join [Environment]::NewLine)
            }
        }

        "RollbackRestoreServices" {
            Rollback-ServiceRestore
        }

        "BackupStore" {
            Backup-Store
        }

        "PrepareUserStore" {
            Prepare-UserStore
        }

        "ClearStore" {
            Invoke-NativeCommand -FilePath (Join-Path $InstallRoot "export_program_info.exe") `
                -ArgumentList @("--clear") -FailureMessage "Failed to clear the user eBPF store"
        }

        "PopulateStore" {
            & (Join-Path $InstallRoot "export_program_info.exe")
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to populate the user eBPF store (exit code $LASTEXITCODE)."
            }
        }

        "RollbackStore" {
            Rollback-StoreTransaction
        }

        "CommitStore" {
            if ([string]::IsNullOrWhiteSpace($Scope)) {
                throw "Scope is required for store commit."
            }
            $paths = Get-StorePaths -StoreScope $Scope
            Remove-BackupFileIfPresent -Path $paths.RollbackStateFile
            Remove-BackupFileIfPresent -Path $paths.RollbackRegistryFile
        }

        "RestoreStore" {
            Restore-Store
        }

        "PrepareRestoreStore" {
            Prepare-StoreRestore
        }

        "RollbackRestoreStore" {
            Rollback-StoreRestore
        }

        "CommitRestoreStore" {
            Commit-StoreRestore
        }

        "CommitRestoreAll" {
            $Scope = "HKLM"
            Commit-StoreRestore
            $paths = Get-ServicePaths
            Remove-ServiceStateFiles -FileSuffix "original"
            Remove-ServiceStateFiles -FileSuffix "uninstall-rollback"
            foreach ($path in @($paths.StateFile, $paths.UninstallRollbackFile)) {
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Force
                }
            }
            $owner = Get-UserStoreOwner
            if ($null -ne $owner -and
                [EbpfMsi.NativeSecurity]::DeleteEmptyUserStore((Join-Path $StateRoot "UserStore"), $owner)) {
                Remove-Item -LiteralPath (Join-Path $StateRoot "hkcu-owner.sid") -Force
            }
            Remove-Item -LiteralPath (Join-Path $StateRoot "ForceEbpfStack.cleanup.ps1") -Force
        }

        "RestoreLinks" {
            Restore-OriginalLinks
        }

        "RollbackRestoreLinks" {
            Restore-MsiLinks
        }
    }
} finally {
    if ($null -ne $userStoreLock) {
        $userStoreLock.Dispose()
    }
    if ($null -ne $backupLock) {
        $backupLock.Dispose()
    }
}
