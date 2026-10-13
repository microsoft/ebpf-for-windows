# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "Install",
        "Rollback",
        "Commit",
        "RestoreService",
        "BackupStore",
        "RollbackStore",
        "CommitStore",
        "RestoreStore")]
    [string]$Action,

    [string]$InstallRoot,

    [string]$SystemRootPath = $env:SystemRoot,

    [string]$ServiceName,

    [string]$ImagePath,

    [ValidateSet("HKLM", "HKCU")]
    [string]$Scope,

    [string]$StateRoot = (Join-Path $env:ProgramData "eBPF-for-Windows\MsiBackup"),

    [string]$StoreRegistryPath,

    [string]$OwnerProductCode,

    [string]$OwnerUpgradeCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not ("EbpfMsi.NativeSecurity" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

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

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

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
            uint securityInformation =
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            if (!SetFileSecurity(path, securityInformation, descriptor)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
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
    [EbpfMsi.NativeSecurity]::RestoreFileAcl($Path, $Acl.Descriptor)
}

function Get-StorePaths
{
    param([Parameter(Mandatory = $true)][string]$StoreScope)

    $scopeName = $StoreScope.ToLowerInvariant()
    return @{
        RegistryPath =
            if ([string]::IsNullOrWhiteSpace($StoreRegistryPath)) {
                "$StoreScope\Software\eBPF"
            } else {
                $StoreRegistryPath
            }
        RegistryFile = Join-Path $StateRoot "ebpf-store-$scopeName.reg"
        StateFile = Join-Path $StateRoot "ebpf-store-$scopeName.json"
        PendingFile = Join-Path $StateRoot "ebpf-store-$scopeName.pending"
        RollbackRegistryFile = Join-Path $StateRoot "ebpf-store-$scopeName.rollback.reg"
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

function Get-CurrentUserSid
{
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Backup-Store
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for BackupStore."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    if ((Test-Path -LiteralPath $paths.PendingFile) -or
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

    $createdDurableBackup = -not (Test-Path -LiteralPath $paths.StateFile -PathType Leaf)
    if ($createdDurableBackup) {
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

    $pendingState = [PSCustomObject]@{
        SchemaVersion = 1
        Scope = $Scope
        RegistryPath = $paths.RegistryPath
        StoreExisted = $storeExisted
        UserSid = if ($Scope -eq "HKCU") { Get-CurrentUserSid } else { $null }
        CreatedDurableBackup = $createdDurableBackup
    }
    $pendingState | ConvertTo-Json | Set-Content -LiteralPath $paths.PendingFile -Encoding UTF8
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
    if ($Scope -eq "HKCU" -and [string]$state.UserSid -ne (Get-CurrentUserSid)) {
        throw "The HKCU eBPF store belongs to user SID '$($state.UserSid)', not the current user."
    }
    return $state
}

function Rollback-StoreTransaction
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store rollback."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    if (-not (Test-Path -LiteralPath $paths.PendingFile -PathType Leaf)) {
        return
    }

    $pendingState = Get-Content -LiteralPath $paths.PendingFile -Raw | ConvertFrom-Json
    if ([int]$pendingState.SchemaVersion -ne 1 -or [string]$pendingState.Scope -ne $Scope) {
        throw "Invalid pending $Scope eBPF store transaction."
    }
    if ($Scope -eq "HKCU" -and [string]$pendingState.UserSid -ne (Get-CurrentUserSid)) {
        throw "The pending HKCU eBPF store transaction belongs to a different user."
    }

    Remove-RegistryTreeIfPresent -RegistryPath ([string]$pendingState.RegistryPath)
    if ([bool]$pendingState.StoreExisted) {
        if (-not (Test-Path -LiteralPath $paths.RollbackRegistryFile -PathType Leaf)) {
            throw "The $Scope eBPF rollback store file is missing: $($paths.RollbackRegistryFile)"
        }
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
            -ArgumentList @("import", $paths.RollbackRegistryFile) `
            -FailureMessage "Failed to roll back the $Scope eBPF store"
    }

    Remove-Item -LiteralPath $paths.RollbackRegistryFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $paths.PendingFile -Force
    if ([bool]$pendingState.CreatedDurableBackup) {
        Remove-Item -LiteralPath $paths.RegistryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $paths.StateFile -Force
    }
    if ((Test-Path -LiteralPath $StateRoot -PathType Container) -and
        -not (Get-ChildItem -LiteralPath $StateRoot -Force)) {
        Remove-Item -LiteralPath $StateRoot -Force
    }
}

function Restore-Store
{
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        throw "Scope is required for store restoration."
    }

    $paths = Get-StorePaths -StoreScope $Scope
    $state = Read-StoreState -Paths $paths
    if ($null -eq $state) {
        Remove-RegistryTreeIfPresent -RegistryPath $paths.RegistryPath
        return
    }

    Remove-RegistryTreeIfPresent -RegistryPath ([string]$state.RegistryPath)
    if ([bool]$state.StoreExisted) {
        if (-not (Test-Path -LiteralPath $paths.RegistryFile -PathType Leaf)) {
            throw "The saved $Scope eBPF store file is missing: $($paths.RegistryFile)"
        }
        Invoke-NativeCommand `
            -FilePath (Join-Path $env:SystemRoot "System32\reg.exe") `
            -ArgumentList @("import", $paths.RegistryFile) `
            -FailureMessage "Failed to restore the $Scope eBPF store"
    }

    Remove-Item -LiteralPath $paths.RegistryFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $paths.StateFile -Force
    Remove-Item -LiteralPath $paths.PendingFile -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $StateRoot -PathType Container) -and
        -not (Get-ChildItem -LiteralPath $StateRoot -Force)) {
        Remove-Item -LiteralPath $StateRoot -Force
    }
}

switch ($Action) {
    "Install" {
        $originalAcls = @{}
        foreach ($mapping in $mappings) {
            $backup = $mapping.Link + ".ebpf-msi-backup"
            $replacement = $mapping.Link + ".ebpf-msi-new"
            if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
                throw "Installed eBPF binary is missing: $($mapping.Source)"
            }
            if (-not (Test-Path -LiteralPath $mapping.Link -PathType Leaf)) {
                throw "Canonical eBPF binary is missing: $($mapping.Link)"
            }
            if ((Test-Path -LiteralPath $backup) -or (Test-Path -LiteralPath $replacement)) {
                throw "Stale eBPF hard-link staging file exists for: $($mapping.Link)"
            }
            $originalAcls[$mapping.Link] = Get-RestorableFileAcl -Path $mapping.Link
        }

        try {
            foreach ($mapping in $mappings) {
                Enable-SystemFileAccess -Path $mapping.Link
            }

            foreach ($mapping in $mappings) {
                Write-Output "Staging hard links for $($mapping.Link)"
                New-Item -ItemType HardLink -Path ($mapping.Link + ".ebpf-msi-backup") -Target $mapping.Link |
                    Out-Null
                New-Item -ItemType HardLink -Path ($mapping.Link + ".ebpf-msi-new") -Target $mapping.Source |
                    Out-Null
            }

            foreach ($mapping in $mappings) {
                Remove-Item -LiteralPath $mapping.Link -Force
                Move-Item -LiteralPath ($mapping.Link + ".ebpf-msi-new") -Destination $mapping.Link
                Restore-FileAcl `
                    -Path ($mapping.Link + ".ebpf-msi-backup") `
                    -Acl $originalAcls[$mapping.Link]
            }
        } catch {
            $installError = $_
            $restoreFailures = @()
            foreach ($mapping in $mappings) {
                try {
                    $backup = $mapping.Link + ".ebpf-msi-backup"
                    $replacement = $mapping.Link + ".ebpf-msi-new"
                    if (Test-Path -LiteralPath $backup -PathType Leaf) {
                        if (Test-Path -LiteralPath $mapping.Link) {
                            Remove-Item -LiteralPath $mapping.Link -Force
                        }
                        Move-Item -LiteralPath $backup -Destination $mapping.Link
                    }
                    if (Test-Path -LiteralPath $replacement) {
                        Remove-Item -LiteralPath $replacement -Force
                    }
                    if ($originalAcls.ContainsKey($mapping.Link) -and
                        (Test-Path -LiteralPath $mapping.Link -PathType Leaf)) {
                        Restore-FileAcl -Path $mapping.Link -Acl $originalAcls[$mapping.Link]
                    }
                } catch {
                    $restoreFailures += "$($mapping.Link): $($_.Exception.Message)"
                }
            }

            if ($restoreFailures.Count -ne 0) {
                throw "$($installError.Exception.Message)$([Environment]::NewLine)Restoration failures:$([Environment]::NewLine)$($restoreFailures -join [Environment]::NewLine)"
            }
            throw $installError
        }
    }

    "Rollback" {
        Invoke-ForAllMappings {
            param($mapping)

            $backup = $mapping.Link + ".ebpf-msi-backup"
            $replacement = $mapping.Link + ".ebpf-msi-new"
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if (Test-Path -LiteralPath $mapping.Link) {
                    Remove-Item -LiteralPath $mapping.Link -Force
                }
                Move-Item -LiteralPath $backup -Destination $mapping.Link
            }
            if (Test-Path -LiteralPath $replacement) {
                Remove-Item -LiteralPath $replacement -Force
            }
        }
    }

    "Commit" {
        Invoke-ForAllMappings {
            param($mapping)

            Remove-Item -LiteralPath ($mapping.Link + ".ebpf-msi-backup") -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath ($mapping.Link + ".ebpf-msi-new") -Force -ErrorAction SilentlyContinue
        }
    }

    "RestoreService" {
        if ([string]::IsNullOrWhiteSpace($ServiceName) -or [string]::IsNullOrWhiteSpace($ImagePath)) {
            throw "ServiceName and ImagePath are required for RestoreService."
        }
        if ($ImagePath.StartsWith("#%")) {
            $ImagePath = $ImagePath.Substring(2)
        }

        & "$env:SystemRoot\System32\sc.exe" config $ServiceName binpath= $ImagePath
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restore the $ServiceName service ImagePath."
        }
    }

    "BackupStore" {
        Backup-Store
    }

    "RollbackStore" {
        Rollback-StoreTransaction
    }

    "CommitStore" {
        foreach ($storeScope in @("HKLM", "HKCU")) {
            $paths = Get-StorePaths -StoreScope $storeScope
            Remove-Item -LiteralPath $paths.PendingFile -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $paths.RollbackRegistryFile -Force -ErrorAction SilentlyContinue
        }
    }

    "RestoreStore" {
        Restore-Store
    }
}
