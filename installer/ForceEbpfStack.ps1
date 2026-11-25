# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "Install",
        "BackupLinks",
        "PrepareRepair",
        "Repair",
        "RollbackRepair",
        "CommitRepair",
        "Rollback",
        "InstallEbpfSvc",
        "BackupServices",
        "RollbackServices",
        "PrepareRestoreServices",
        "RemoveServices",
        "RestoreServices",
        "StopServices",
        "RollbackRestoreServices",
        "BackupStore",
        "RollbackStore",
        "PrepareRestoreStore",
        "RestoreStore",
        "RollbackRestoreStore",
        "CommitRestoreStore",
        "CommitRestoreAll",
        "PrepareUserStore",
        "RollbackUserStore",
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

    [string]$StateRoot = (Join-Path ([Environment]::GetFolderPath("ProgramFiles")) "ebpf-for-windows\MsiBackup"),

    [string]$StoreRegistryPath,

    [string]$InstallingUserSid,

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

        // Rejects untrusted ownership or permissions that let ordinary users tamper with protected backup paths.
        // HKCU checks allow the recorded user limited directory access and access to their own backup files.
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
                // DELETE, WRITE_DAC, WRITE_OWNER, FILE_DELETE_CHILD, and GENERIC_ALL:
                // ancestors may allow creating unrelated children, but not replacing the protected path.
                const uint forbiddenAncestorAccess = 0x100D0040u;
                // Also forbid FILE_WRITE_DATA/FILE_ADD_FILE, FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY,
                // FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, and GENERIC_WRITE on backup files/directories.
                const uint forbiddenBackupAccess = 0x500D0156u;
                uint forbidden = ancestor ? forbiddenAncestorAccess : forbiddenBackupAccess;
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
                    // Program Files inherits a CREATOR OWNER rule for new children, not the directory itself.
                    // Each backup file's actual owner is checked above.
                    if (directory && (ace.AceFlags & AceFlags.InheritOnly) != 0 &&
                        ace.SecurityIdentifier.IsWellKnown(System.Security.Principal.WellKnownSidType.CreatorOwnerSid)) {
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

        // Opens and validates a backup path, rejecting redirection, hard-linked files, and unsafe permissions.
        // Returns a handle that the caller must close after use.
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

        // Creates the user backup directory with the supplied permissions applied at creation.
        // An existing directory is left unchanged for separate validation.
        public static void CreateUserStore(string path, string sddl)
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

        // Checks the backup folder and its ancestors; machine actions also create managed folders and check backup files.
        // User actions require existing folders, and UserStore contents are checked separately.
        public static void ValidateBackupDirectory(string path, bool userAction = false)
        {
            path = System.IO.Path.GetFullPath(path).TrimEnd('\\');
            string parent = System.IO.Path.GetDirectoryName(path);
            if (String.IsNullOrEmpty(parent) || String.IsNullOrEmpty(System.IO.Path.GetDirectoryName(parent))) {
                throw new System.IO.IOException("Backup path must have a protected application parent.");
            }
            string programFiles = System.IO.Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd('\\');
            System.Collections.Generic.List<string> directories = new System.Collections.Generic.List<string>();
            // Program Files is the trusted boundary; overrides elsewhere still validate every ancestor.
            for (string current = path;
                current != null && !String.Equals(current, programFiles, StringComparison.OrdinalIgnoreCase);
                current = System.IO.Path.GetDirectoryName(current)) {
                directories.Add(current);
            }
            directories.Reverse();
            foreach (string directory in directories) {
                bool managed = directory == parent || directory == path;
                if (managed && !userAction) {
                    System.IO.Directory.CreateDirectory(directory);
                }
                IntPtr handle = OpenBackupPath(directory, true, !managed);
                CloseHandle(handle);
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
        }

        // Validates the user backup directory and its files, keeping the directory locked against replacement.
        // The caller must dispose the returned lock when the action finishes.
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
        [AllowEmptyString()]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage,

        [string]$WorkingDirectory)

    # Encode for the Windows native argv parser, bypassing Windows PowerShell's lossy argument marshalling.
    $encoded = foreach ($argument in $ArgumentList) {
        '"' + [regex]::Replace([regex]::Replace($argument, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $encoded -join " "
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $startInfo.WorkingDirectory = $WorkingDirectory
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "$FailureMessage (exit code $($process.ExitCode))`n$output`n$errorOutput"
        }
    } finally {
        $process.Dispose()
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

function Get-OriginalLinks
{
    $path = Join-Path $StateRoot "ebpf-binary-links.original.json"
    $links = @{}
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $links
    }

    $entries = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if (@($entries).Count -ne $mappings.Count) {
        throw "The original eBPF binary link record is incomplete: $path"
    }
    $replacedPaths = @($mappings.Link) + @($mappings.Source)
    foreach ($mapping in $mappings) {
        $entry = @($entries | Where-Object { $_.Canonical -eq $mapping.Link })
        if ($entry.Count -ne 1 -or [string]::IsNullOrWhiteSpace($entry[0].Original) -or
            $entry[0].Original -in $replacedPaths) {
            throw "Invalid original hard-link record for: $($mapping.Link)"
        }
        $original = [string]$entry[0].Original
        if (-not (Test-Path -LiteralPath $original -PathType Leaf)) {
            throw "The original eBPF hard link is missing: $original"
        }
        $links[$mapping.Link] = $original
    }
    return $links
}

# Changes only the canonical name; both original and MSI binaries retain their permissions.
function Set-BinaryLink
{
    param(
        [Parameter(Mandatory = $true)]$Mapping,
        [Parameter(Mandatory = $true)][string]$Original,
        [Parameter(Mandatory = $true)][string]$Target)

    if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) {
        throw "The eBPF hard-link target is missing: $Target"
    }
    $current = $null
    if (Test-Path -LiteralPath $Mapping.Link -PathType Leaf) {
        if (Test-SameFile -FirstPath $Mapping.Link -SecondPath $Target) {
            return
        }
        $current = if ($Target -eq $Original) { $Mapping.Source } else { $Original }
        if (-not (Test-SameFile -FirstPath $Mapping.Link -SecondPath $current)) {
            throw "The canonical eBPF binary points to neither the original nor the MSI file: $($Mapping.Link)"
        }
    }
    $acls = @{}
    if ($Target -eq $Original) {
        $acls[$Original] = Get-RestorableFileAcl -Path $Original
    }
    if ($null -ne $current) {
        $acls[$current] = Get-RestorableFileAcl -Path $current
    }
    $failures = @()
    try {
        if ($Target -eq $Original) {
            Enable-SystemFileAccess -Path $Original
        }
        if ($null -ne $current) {
            Enable-SystemFileAccess -Path $Mapping.Link
            Remove-Item -LiteralPath $Mapping.Link -Force
        }
        New-Item -ItemType HardLink -Path $Mapping.Link -Target $Target | Out-Null
    } catch {
        $failures += $_.Exception.Message
    } finally {
        foreach ($path in $acls.Keys) {
            try {
                Restore-FileAcl -Path $path -Acl $acls[$path]
            } catch {
                $failures += "$path`: $($_.Exception.Message)"
            }
        }
    }
    if ($failures.Count -ne 0) {
        throw ($failures -join [Environment]::NewLine)
    }
}

# Restores the original links and discards the record only after every restoration succeeds.
function Rollback-InstalledLinks
{
    $originalLinks = Get-OriginalLinks
    if ($originalLinks.Count -eq 0) {
        return
    }
    Invoke-ForAllMappings {
        param($mapping)
        Set-BinaryLink -Mapping $mapping -Original $originalLinks[$mapping.Link] -Target $originalLinks[$mapping.Link]
    }
    Remove-BackupFileIfPresent -Path (Join-Path $StateRoot "ebpf-binary-links.original.json")
}

# Records existing hard-link names without changing the original Windows binaries.
function Backup-OriginalLinks
{
    $path = Join-Path $StateRoot "ebpf-binary-links.original.json"
    if (Test-Path -LiteralPath $path) {
        throw "An original eBPF binary link record already exists: $path"
    }
    $entries = @()
    $replacedPaths = @($mappings.Link) + @($mappings.Source)
    foreach ($mapping in $mappings) {
        if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
            throw "Installed eBPF binary is missing: $($mapping.Source)"
        }
        if (-not (Test-Path -LiteralPath $mapping.Link -PathType Leaf)) {
            throw "Canonical eBPF binary is missing: $($mapping.Link)"
        }
        if (@(Get-ChildItem -Path ($mapping.Link + ".ebpf-msi-*") -Force).Count -ne 0) {
            throw "Existing eBPF backup or staging file requires recovery before installation: $($mapping.Link)"
        }
        $file = Get-Item -LiteralPath $mapping.Link -Force
        if ($file.LinkType -ne "HardLink") {
            throw "Cannot force-install: $($mapping.Link) must have an existing hard link."
        }
        $original = @($file.Target | Where-Object { $_ -notin $replacedPaths } |
                Select-Object -First 1)
        if ($original.Count -eq 0 -or
            -not (Test-SameFile -FirstPath $mapping.Link -SecondPath $original[0])) {
            throw "No existing original hard-link name is available for: $($mapping.Link)"
        }
        $entries += [PSCustomObject]@{ Canonical = $mapping.Link; Original = $original[0] }
    }
    try {
        $entries | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
    } catch {
        Remove-BackupFileIfPresent -Path $path
        throw
    }
}

# Restores the original Windows binary paths from recorded existing hard links during uninstall.
function Restore-OriginalLinks
{
    $originalLinks = Get-OriginalLinks
    if ($originalLinks.Count -eq 0) {
        Write-Output "No forced-install eBPF original link record was found."
        return
    }
    try {
        foreach ($mapping in $mappings) {
            Set-BinaryLink -Mapping $mapping -Original $originalLinks[$mapping.Link] -Target $originalLinks[$mapping.Link]
        }
    } catch {
        $restoreError = $_
        try {
            Restore-MsiLinks
        } catch {
            throw "$($restoreError.Exception.Message)`nFailed to roll back link restoration: $($_.Exception.Message)"
        }
        throw $restoreError
    }
}

# Reinstates the MSI binary links without changing the recorded original links when uninstall rolls back.
function Restore-MsiLinks
{
    $originalLinks = Get-OriginalLinks
    if ($originalLinks.Count -eq 0 -and
        -not (Test-Path -LiteralPath (Get-ServicePaths).StateFile -PathType Leaf)) {
        return
    }

    Invoke-ForAllMappings {
        param($mapping)

        if (-not $originalLinks.ContainsKey($mapping.Link)) {
            throw "The original hard-link record is missing for: $($mapping.Link)"
        }
        Set-BinaryLink -Mapping $mapping -Original $originalLinks[$mapping.Link] -Target $mapping.Source
    }
}

# Removes temporary repair snapshots and hard links without deleting the original stack backups.
function Remove-RepairFiles
{
    Invoke-ForAllMappings {
        param($mapping)

        $backup = $mapping.Link + ".ebpf-msi-repair"
        if (Test-Path -LiteralPath $backup) {
            $acl = Get-RestorableFileAcl -Path $backup
            $restorePaths = @($mapping.Link, $mapping.Source) | Where-Object {
                (Test-Path -LiteralPath $_) -and (Test-SameFile -FirstPath $_ -SecondPath $backup)
            }
            try {
                Enable-SystemFileAccess -Path $backup
                Remove-Item -LiteralPath $backup -Force
            } finally {
                foreach ($path in $restorePaths) {
                    if (Test-Path -LiteralPath $path) {
                        Restore-FileAcl -Path $path -Acl $acl
                    }
                }
            }
        }
    }
    Remove-ServiceStateFiles -FileSuffix "repair"
    Remove-BackupFileIfPresent -Path (Join-Path $StateRoot "ebpf-repair.json")
}

# Saves current service state and surviving forced-install binary links so repair can be rolled back.
function Prepare-Repair
{
    $originalLinks = Get-OriginalLinks
    $journal = Join-Path $StateRoot "ebpf-repair.json"
    $stale = @(Get-ChildItem -LiteralPath $StateRoot -Filter "*.repair.reg")
    if ((Test-Path -LiteralPath $journal) -or $stale.Count -ne 0 -or
        @($mappings | Where-Object { Test-Path -LiteralPath ($_.Link + ".ebpf-msi-repair") }).Count -ne 0) {
        throw "An incomplete eBPF repair requires recovery before retrying."
    }
    $forced = Test-Path -LiteralPath (Get-ServicePaths).StateFile
    if ($forced -and $originalLinks.Count -ne $mappings.Count) {
        throw "Repair requires a complete original binary link record."
    }
    if (-not $forced -and $originalLinks.Count -ne 0) {
        throw "An original binary link record exists without the original service snapshot."
    }
    $present = @()
    try {
        if ($forced) {
            Read-ServiceState -Path (Get-ServicePaths).StateFile | Out-Null
            foreach ($mapping in $mappings) {
                if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
                    throw "Repaired MSI binary is missing: $($mapping.Source)"
                }
                $exists = Test-Path -LiteralPath $mapping.Link -PathType Leaf
                $present += $exists
                if ($exists) {
                    if (Test-SameFile -FirstPath $mapping.Link -SecondPath $originalLinks[$mapping.Link]) {
                        throw "The original binary has already been restored: $($mapping.Link)"
                    }
                    $acl = Get-RestorableFileAcl -Path $mapping.Link
                    try {
                        Enable-SystemFileAccess -Path $mapping.Link
                        New-Item -ItemType HardLink -Path ($mapping.Link + ".ebpf-msi-repair") -Target $mapping.Link |
                            Out-Null
                    } finally {
                        Restore-FileAcl -Path $mapping.Link -Acl $acl
                    }
                }
            }
        }
        Save-CurrentServices -StateFile $journal -FileSuffix "repair"
        $state = Read-ServiceState -Path $journal
        $state | Add-Member -NotePropertyName Forced -NotePropertyValue $forced
        $state | Add-Member -NotePropertyName LinksPresent -NotePropertyValue $present
        $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $journal -Encoding UTF8
    } catch {
        Remove-RepairFiles
        throw
    }
}

# Repairs forced-install binary links, recreates a missing eBPFSvc, and restarts previously running forced-stack services.
function Repair-Stack
{
    $state = Read-ServiceState -Path (Join-Path $StateRoot "ebpf-repair.json")
    if ($null -eq $state) {
        throw "The eBPF repair snapshot is missing."
    }
    if ([bool]$state.Forced) {
        for ($index = $ServiceNames.Count - 1; $index -ge 0; $index--) {
            Stop-ServiceIfPresent -Name $ServiceNames[$index]
        }
        foreach ($mapping in $mappings) {
            if ((Test-Path -LiteralPath $mapping.Link) -and
                (Test-SameFile -FirstPath $mapping.Link -SecondPath $mapping.Source)) {
                continue
            }
            $saved = $mapping.Link + ".ebpf-msi-repair"
            $acl = if (Test-Path -LiteralPath $saved) { Get-RestorableFileAcl -Path $saved } else { $null }
            try {
                if (Test-Path -LiteralPath $mapping.Link) {
                    Enable-SystemFileAccess -Path $mapping.Link
                    Remove-Item -LiteralPath $mapping.Link -Force
                }
                New-Item -ItemType HardLink -Path $mapping.Link -Target $mapping.Source | Out-Null
            } finally {
                if ($null -ne $acl) {
                    Restore-FileAcl -Path $saved -Acl $acl
                }
            }
        }
    }
    if ($null -eq (Get-Service -Name "eBPFSvc" -ErrorAction SilentlyContinue)) {
        $UseCanonicalServicePath = [bool]$state.Forced
        Install-MsiEbpfService
    }
    if ([bool]$state.Forced) {
        foreach ($service in @($state.Services)) {
            if ([bool]$service.WasRunning) {
                Start-Service -Name $service.Name
            }
        }
    }
}

# Restores saved binary links and running state and removes any eBPFSvc created by the failed repair.
function Rollback-Repair
{
    $journal = Join-Path $StateRoot "ebpf-repair.json"
    $state = Read-ServiceState -Path $journal
    if ($null -eq $state) {
        return
    }
    if ([bool]$state.Forced) {
        for ($index = $ServiceNames.Count - 1; $index -ge 0; $index--) {
            Stop-ServiceIfPresent -Name $ServiceNames[$index]
        }
        if (@($state.LinksPresent).Count -ne $mappings.Count) {
            throw "Invalid binary repair snapshot."
        }
        Invoke-ForAllMappings {
            param($mapping)

            $index = [Array]::IndexOf($mappings, $mapping)
            $saved = $mapping.Link + ".ebpf-msi-repair"
            if ([bool]$state.LinksPresent[$index]) {
                if (Test-Path -LiteralPath $saved) {
                    $acl = Get-RestorableFileAcl -Path $saved
                    try {
                        Enable-SystemFileAccess -Path $saved
                        if (Test-Path -LiteralPath $mapping.Link) {
                            Remove-Item -LiteralPath $mapping.Link -Force
                        }
                        Move-Item -LiteralPath $saved -Destination $mapping.Link
                    } finally {
                        $path = if (Test-Path -LiteralPath $saved) { $saved } else { $mapping.Link }
                        Restore-FileAcl -Path $path -Acl $acl
                    }
                }
            } else {
                Remove-BackupFileIfPresent -Path $mapping.Link
            }
        }
    }
    # Existing service configuration is never changed by repair; only undo a newly created service.
    foreach ($service in @($state.Services)) {
        if ($service.Name -eq "eBPFSvc" -and -not [bool]$service.Existed) {
            Remove-ServiceIfPresent -Name $service.Name
        } elseif ([bool]$state.Forced -and [bool]$service.WasRunning) {
            Start-Service -Name $service.Name
        }
    }
    Remove-RepairFiles
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

# Creates or validates the HKCU backup directory and grants the installing user access to its backup files.
function Prepare-UserStore
{
    $userSid = [System.Security.Principal.SecurityIdentifier]::new($InstallingUserSid).Value
    $userStore = Join-Path $StateRoot "UserStore"
    $owner = Get-UserStoreOwner
    if ($null -ne $owner) {
        # Once user access is granted, SYSTEM must not consume or re-ACL the files inside.
        [EbpfMsi.NativeSecurity]::ValidateUserStoreDirectory($userStore, $owner)
        return
    }

    [EbpfMsi.NativeSecurity]::CreateUserStore(
        $userStore, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    $userStoreLock = [EbpfMsi.NativeSecurity]::LockUserStore($userStore)
    try {
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
        $userStoreLock.Dispose()
    }
}

# Removes the HKCU backup directory and owner marker only when the directory is empty.
function Remove-EmptyUserStore
{
    $owner = Get-UserStoreOwner
    if ($null -eq $owner) {
        return
    }
    if ([EbpfMsi.NativeSecurity]::DeleteEmptyUserStore((Join-Path $StateRoot "UserStore"), $owner)) {
        Remove-Item -LiteralPath (Join-Path $StateRoot "hkcu-owner.sid") -Force
    } else {
        Write-Warning "Retaining the nonempty HKCU backup directory and its owner marker."
    }
}

function Get-StorePaths
{
    param([Parameter(Mandatory = $true)][string]$StoreScope)

    $scopeName = $StoreScope.ToLowerInvariant()
    $storeRoot = if ($StoreScope -eq "HKCU") { Join-Path $StateRoot "UserStore" } else { $StateRoot }
    return @{
        RegistryPath =
            if ([string]::IsNullOrWhiteSpace($StoreRegistryPath)) {
                "$StoreScope\Software\eBPF"
            } else {
                $StoreRegistryPath
            }
        RegistryFile = Join-Path $storeRoot "ebpf-store-$scopeName.reg"
        StateFile = Join-Path $storeRoot "ebpf-store-$scopeName.json"
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
    return @{
        StateFile = Join-Path $StateRoot "ebpf-services.original.json"
        UninstallRollbackFile = Join-Path $StateRoot "ebpf-services.uninstall-rollback.json"
    }
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
    $registryPath = Get-ServiceRegistryPath -Name $name
    $registryHeader = "[HKEY_LOCAL_MACHINE$($registryPath.Substring(4))]"
    if (@(Get-Content -LiteralPath $registryFile) -inotcontains $registryHeader) {
        throw "The saved $name service registry file does not contain its service key: $registryFile"
    }
    Remove-RegistryTreeIfPresent -RegistryPath "$registryPath\Parameters"
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
        # Disabling startup does not stop a running service. Temporarily allow startup to restore
        # a saved Running + Disabled state, then restore Disabled even if starting fails.
        $restoreDisabled = [int]$ServiceState.Start -eq 4
        if ($restoreDisabled) {
            Invoke-NativeCommand `
                -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
                -ArgumentList @("config", $name, "start=", "demand") `
                -FailureMessage "Failed to temporarily enable the $name service for restoration"
        }
        try {
            Start-Service -Name $name
            (Get-Service -Name $name).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(60))
        } finally {
            if ($restoreDisabled) {
                Invoke-NativeCommand `
                    -FilePath (Join-Path $env:SystemRoot "System32\sc.exe") `
                    -ArgumentList @("config", $name, "start=", "disabled") `
                    -FailureMessage "Failed to restore the $name service's disabled startup configuration"
            }
        }
    }
}

# Creates or configures eBPFSvc to run as LocalService using the MSI or canonical Windows executable path.
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
            $expectedFiles = @("original", "uninstall-rollback", "repair") |
                ForEach-Object { "$($serviceState.Name).$_.reg" }
            if ($registryFileName -notin $expectedFiles -or
                -not (Test-Path -LiteralPath (Join-Path $StateRoot $registryFileName) -PathType Leaf)) {
                throw "The saved $($serviceState.Name) service registry file is missing or invalid."
            }
        }
    }
    return $state
}

function Test-NetshHelperRegistered
{
    $path = "HKLM:\SOFTWARE\Microsoft\NetSh"
    if (-not (Test-Path -LiteralPath $path)) {
        return $false
    }

    $key = Get-Item -LiteralPath $path
    try {
        foreach ($name in $key.GetValueNames()) {
            $value = $key.GetValue($name)
            if ($value -is [string] -and [IO.Path]::GetFileName($value) -ieq "ebpfnetsh.dll") {
                return $true
            }
        }
        return $false
    } finally {
        $key.Dispose()
    }
}

function Restore-NetshHelper
{
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$HelperPath)

    if ($null -eq $State.PSObject.Properties["NetshHelperRegistered"]) {
        Write-Warning "The service snapshot predates netsh helper tracking; leaving its registration unchanged."
        return
    }
    if ($State.NetshHelperRegistered -isnot [bool]) {
        throw "The saved netsh helper registration flag is invalid."
    }

    $netsh = Join-Path $env:SystemRoot "System32\netsh.exe"
    if (Test-NetshHelperRegistered) {
        Invoke-NativeCommand -FilePath $netsh -ArgumentList @("delete", "helper", "ebpfnetsh.dll") `
            -FailureMessage "Failed to remove the current eBPF netsh helper registration"
        if (Test-NetshHelperRegistered) {
            throw "The current eBPF netsh helper registration was not removed."
        }
    }
    if ($State.NetshHelperRegistered) {
        # Inbox restoration uses the canonical DLL, not an arbitrary saved registration path.
        Invoke-NativeCommand -FilePath $netsh -ArgumentList @("add", "helper", $HelperPath) `
            -WorkingDirectory (Split-Path -Parent $HelperPath) `
            -FailureMessage "Failed to restore the eBPF netsh helper registration"
    }
    if ((Test-NetshHelperRegistered) -ne $State.NetshHelperRegistered) {
        throw "The eBPF netsh helper registration does not match the saved state."
    }
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
        NetshHelperRegistered = Test-NetshHelperRegistered
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

# Saves the original service configuration, running state, and netsh helper registration before forced replacement.
function Backup-Services
{
    $paths = Get-ServicePaths
    $existingFiles = @(Get-ChildItem -LiteralPath $StateRoot -Filter "ebpf-services.*" -Force)
    foreach ($name in $ServiceNames) {
        $existingFiles += @(Get-ChildItem -LiteralPath $StateRoot -Filter "$name.*.reg" -Force)
    }
    if ($existingFiles.Count -ne 0) {
        throw "Existing eBPF service backup requires recovery before installation: '$StateRoot'."
    }

    try {
        Save-CurrentServices -StateFile $paths.StateFile -FileSuffix "original"
    } catch {
        Remove-ServiceStateFiles -FileSuffix "original"
        Remove-BackupFileIfPresent -Path $paths.StateFile
        throw
    }
}

# Restores the original services and netsh helper registration after a failed forced install.
function Rollback-ServiceTransaction
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.StateFile
    if ($null -eq $state) {
        return
    }

    Apply-ServiceState -State $state -StartIfPreviouslyRunning $true
    Restore-NetshHelper -State $state -HelperPath (Join-Path $SystemRootPath "System32\ebpfnetsh.dll")
    Remove-ServiceStateFiles -FileSuffix "original"
    Remove-Item -LiteralPath $paths.StateFile -Force
}

# Stops the eBPF stack and removes only service registrations that did not exist before MSI installation.
function Remove-MsiServices
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.StateFile
    # Release service and extension handles before stopping the core or deleting registrations.
    for ($index = $ServiceNames.Count - 1; $index -ge 0; $index--) {
        Stop-ServiceIfPresent -Name $ServiceNames[$index]
    }
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

# Validates original backups, snapshots current services, and preserves the cleanup script for uninstall commit.
function Prepare-ServiceRestore
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.StateFile
    $backupCount = (Get-OriginalLinks).Count
    if ($null -eq $state -and $backupCount -ne 0) {
        throw "An original eBPF binary link record exists but the service snapshot is missing: $($paths.StateFile)"
    }
    if ($null -ne $state -and $backupCount -ne $mappings.Count) {
        throw "The original eBPF service snapshot exists but only $backupCount of $($mappings.Count) original binary links are recorded."
    }

    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    $snapshotFiles = @($paths.UninstallRollbackFile)
    $snapshotFiles += $ServiceNames | ForEach-Object { Join-Path $StateRoot "$_.uninstall-rollback.reg" }
    foreach ($path in $snapshotFiles) {
        if (Test-Path -LiteralPath $path) {
            throw "Incomplete eBPF service restoration exists in '$StateRoot'."
        }
    }

    # Commit runs after RemoveFiles, so retain a copy in the already validated, protected directory.
    $cleanupScript = Join-Path $StateRoot "ForceEbpfStack.cleanup.ps1"
    Copy-Item -LiteralPath $PSCommandPath -Destination $cleanupScript -Force
    try {
        Save-CurrentServices -StateFile $paths.UninstallRollbackFile -FileSuffix "uninstall-rollback"
    } catch {
        Remove-ServiceStateFiles -FileSuffix "uninstall-rollback"
        Remove-BackupFileIfPresent -Path $paths.UninstallRollbackFile
        throw
    }
}

# Restores the original service configuration, running state, and netsh helper registration during uninstall.
function Restore-Services
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.StateFile
    if ($null -eq $state) {
        return
    }
    Apply-ServiceState -State $state -StartIfPreviouslyRunning $true
    Restore-NetshHelper -State $state -HelperPath (Join-Path $SystemRootPath "System32\ebpfnetsh.dll")
}

# Restores the pre-uninstall services and MSI netsh helper registration when uninstall fails.
function Rollback-ServiceRestore
{
    $paths = Get-ServicePaths
    $state = Read-ServiceState -Path $paths.UninstallRollbackFile
    if ($null -eq $state) {
        return
    }

    Apply-ServiceState -State $state -StartIfPreviouslyRunning $true
    Restore-NetshHelper -State $state -HelperPath (Join-Path $InstallRoot "ebpfnetsh.dll")
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

# Saves the selected original eBPF registry store, recording its prior existence and HKCU owner.
function Backup-Store
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for BackupStore."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if (@(Get-ChildItem -LiteralPath (Split-Path $paths.StateFile) -Filter "ebpf-store-$Scope.*" -Force).Count -ne 0) {
        throw "Existing $Scope eBPF store backup requires recovery before installation: '$StateRoot'."
    }

    $providerPath = Get-RegistryProviderPath -RegistryPath $paths.RegistryPath
    $storeExisted = Test-Path -LiteralPath $providerPath
    try {
        if ($storeExisted) {
            Invoke-NativeCommand `
                -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
                -ArgumentList @("export", $paths.RegistryPath, $paths.RegistryFile, "/y") `
                -FailureMessage "Failed to save the original $Scope eBPF store"
        }

        $state = [PSCustomObject]@{
            SchemaVersion = 1
            Scope = $Scope
            RegistryPath = $paths.RegistryPath
            StoreExisted = $storeExisted
            UserSid = if ($Scope -eq "HKCU") { Get-CurrentUserSid } else { $null }
            Created = (Get-Date).ToUniversalTime().ToString("o")
        }
        $state | ConvertTo-Json | Set-Content -LiteralPath $paths.StateFile -Encoding UTF8
    } catch {
        Remove-BackupFileIfPresent -Path $paths.RegistryFile
        Remove-BackupFileIfPresent -Path $paths.StateFile
        throw
    }
}

function Read-StoreState
{
    param([Parameter(Mandatory = $true)][hashtable]$Paths)

    if (-not (Test-Path -LiteralPath $Paths.StateFile -PathType Leaf)) {
        if ($Scope -eq "HKCU" -and
            (Test-Path -LiteralPath (Get-ServicePaths).StateFile -PathType Leaf)) {
            throw "The original HKCU eBPF store snapshot is missing: $($Paths.StateFile)"
        }
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
        return (Get-UserStoreOwner) -eq (Get-CurrentUserSid)
    }
    if ([string]$State.UserSid -ne (Get-CurrentUserSid)) {
        Write-Warning "Skipping HKCU restoration: backup belongs to '$($State.UserSid)', not the current user. Retaining the backup."
        return $false
    }
    return $true
}

# Restores the selected original eBPF registry store after a failed install and removes its backup.
function Rollback-StoreTransaction
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store rollback."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    $state = Read-StoreState -Paths $paths
    if ($null -eq $state -or -not (Test-StoreRestoreUser -State $state)) {
        return
    }

    Restore-Store
    Remove-BackupFileIfPresent -Path $paths.RegistryFile
    Remove-Item -LiteralPath $paths.StateFile -Force
}

# Restores the selected original registry store or clears MSI metadata, skipping HKCU owned by another user.
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
        Invoke-NativeCommand -FilePath (Join-Path $InstallRoot "export_program_info.exe") `
            -ArgumentList @("--clear") `
            -FailureMessage "Failed to remove MSI-owned eBPF metadata"
    } elseif ([bool]$state.StoreExisted) {
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

# Saves the selected current eBPF registry store so uninstall restoration can be rolled back.
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
    try {
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
    } catch {
        Remove-BackupFileIfPresent -Path $paths.UninstallRegistryFile
        Remove-BackupFileIfPresent -Path $paths.UninstallStateFile
        throw
    }
}

# Restores the selected pre-uninstall registry store when uninstall fails, honoring HKCU ownership.
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

# Deletes completed store-restoration backups while retaining original HKCU backups if restoration was skipped.
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
        $paths.RegistryFile, $paths.StateFile,
        $paths.UninstallRegistryFile, $paths.UninstallStateFile)) {
        Remove-BackupFileIfPresent -Path $path
    }
}

$userStoreLock = $null
try {
    if ($Action -match "(Services|Store|Repair)$" -or $Action -eq "CommitRestoreAll" -or
        $Action -in @("BackupLinks", "Install", "Rollback", "RestoreLinks", "RollbackRestoreLinks")) {
        $StateRoot = [System.IO.Path]::GetFullPath($StateRoot)
        $userStoreAction = $Scope -eq "HKCU"
        [EbpfMsi.NativeSecurity]::ValidateBackupDirectory($StateRoot, $userStoreAction)
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
        "PrepareRepair" {
            Prepare-Repair
        }
        "Repair" {
            Repair-Stack
        }
        "RollbackRepair" {
            Rollback-Repair
        }
        "CommitRepair" {
            Remove-RepairFiles
        }
        "BackupLinks" {
            Backup-OriginalLinks
        }

        # Replaces canonical Windows binary paths with hard links to the installed MSI files.
        "Install" {
            $originalLinks = Get-OriginalLinks
            if ($originalLinks.Count -eq 0) {
                throw "The original eBPF hard-link record is missing."
            }
            foreach ($mapping in $mappings) {
                if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
                    throw "Installed eBPF binary is missing: $($mapping.Source)"
                }
                if (-not (Test-SameFile -FirstPath $originalLinks[$mapping.Link] -SecondPath $mapping.Link)) {
                    throw "The canonical eBPF binary changed after backup: $($mapping.Link)"
                }
            }

            try {
                foreach ($mapping in $mappings) {
                    Set-BinaryLink -Mapping $mapping -Original $originalLinks[$mapping.Link] -Target $mapping.Source
                }
            } catch {
                $installError = $_
                try {
                    Rollback-InstalledLinks
                } catch {
                    throw "$($installError.Exception.Message)`nLink restoration failure: $($_.Exception.Message)"
                }
                throw $installError
            }
        }

        "Rollback" {
            Rollback-InstalledLinks
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

        "PrepareRestoreServices" {
            Prepare-ServiceRestore
        }

        "RemoveServices" {
            Remove-MsiServices
        }

        "RestoreServices" {
            Restore-Services
        }

        # Stops the eBPF stack before uninstall rollback restores its pre-uninstall state.
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

        "RollbackUserStore" {
            Remove-EmptyUserStore
        }

        # Clears the calling user's eBPF registry metadata before populating it from the MSI.
        "ClearStore" {
            Invoke-NativeCommand -FilePath (Join-Path $InstallRoot "export_program_info.exe") `
                -ArgumentList @("--clear") -FailureMessage "Failed to clear the user eBPF store"
        }

        # Populates the calling user's eBPF registry store using the installed metadata exporter.
        "PopulateStore" {
            & (Join-Path $InstallRoot "export_program_info.exe")
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to populate the user eBPF store (exit code $LASTEXITCODE)."
            }
        }

        "RollbackStore" {
            Rollback-StoreTransaction
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

        # Cleans up HKLM and service backups, an empty HKCU backup directory, and the retained cleanup script.
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
            Remove-BackupFileIfPresent -Path (Join-Path $StateRoot "ebpf-binary-links.original.json")
            Remove-EmptyUserStore
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
}
