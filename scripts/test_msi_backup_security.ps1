# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

#Requires -RunAsAdministrator

[CmdletBinding()]
param([string]$HelperPath = (Join-Path $PSScriptRoot "..\installer\ForceEbpfStack.ps1"))

$ErrorActionPreference = "Stop"
$HelperPath = (Resolve-Path -LiteralPath $HelperPath).Path
$testId = [Guid]::NewGuid().ToString("N")
$testParent = Join-Path $env:ProgramData "EbpfBackupSecurityTests-$testId"
$stateRoot = Join-Path $testParent "MsiBackup"
$registrySubkey = "Software\EbpfBackupSecurityTests-$testId"
$serviceName = "EbpfBackupSecurityTests-$testId"
$userStore = Join-Path $stateRoot "UserStore"

function Assert-Rejected
{
    param([scriptblock]$Operation, [string]$Message)

    $rejected = $false
    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -notlike "*$Message*") {
            throw
        }
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Expected rejection: $Message"
    }
}

function Invoke-StoreAction
{
    param([string]$Action, [string]$Scope)

    & $HelperPath -Action $Action -Scope $Scope -StateRoot $stateRoot -StoreRegistryPath "$Scope\$registrySubkey"
}

try {
    & $HelperPath -Action CommitStore -StateRoot $stateRoot
    foreach ($directory in @($testParent, $stateRoot, $userStore)) {
        $acl = Get-Acl -LiteralPath $directory
        if (-not $acl.AreAccessRulesProtected -or
            $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") {
            throw "Directory was not created with a protected administrator-owned ACL: $directory"
        }
    }

    $guard = [EbpfMsi.NativeSecurity]::LockBackupDirectory($stateRoot)
    try {
        Assert-Rejected { [IO.Directory]::Move($stateRoot, "$stateRoot-renamed") } "denied"
    } finally {
        $guard.Dispose()
    }

    $file = Join-Path $stateRoot "sentinel.txt"
    Set-Content -LiteralPath $file -Value "unchanged"
    foreach ($path in @($testParent, $stateRoot, $userStore, $file)) {
        $originalAcl = Get-Acl -LiteralPath $path
        $unsafeAcl = Get-Acl -LiteralPath $path
        $unsafeAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11"),
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.AccessControlType]::Allow))
        Set-Acl -LiteralPath $path -AclObject $unsafeAcl
        try {
            Assert-Rejected { & $HelperPath -Action CommitStore -StateRoot $stateRoot } "Unprivileged write access"
        } finally {
            Set-Acl -LiteralPath $path -AclObject $originalAcl
        }
    }

    if (-not [EbpfMsi.NativeSecurity]::TryEnablePrivilege("SeRestorePrivilege")) {
        throw "Owner rejection test requires SeRestorePrivilege."
    }
    $originalAcl = Get-Acl -LiteralPath $file
    $unsafeAcl = Get-Acl -LiteralPath $file
    $unsafeAcl.SetOwner([System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-545"))
    Set-Acl -LiteralPath $file -AclObject $unsafeAcl
    try {
        Assert-Rejected { & $HelperPath -Action CommitStore -StateRoot $stateRoot } "Untrusted backup owner"
    } finally {
        Set-Acl -LiteralPath $file -AclObject $originalAcl
    }

    $hardLink = Join-Path $userStore "linked.reg"
    New-Item -ItemType HardLink -Path $hardLink -Target $file | Out-Null
    try {
        Assert-Rejected { & $HelperPath -Action CommitStore -StateRoot $stateRoot } "hard link"
    } finally {
        Remove-Item -LiteralPath $hardLink -Force
    }

    $junction = "$testParent-junction"
    New-Item -ItemType Junction -Path $junction -Target $testParent | Out-Null
    try {
        Assert-Rejected {
            & $HelperPath -Action CommitStore -StateRoot (Join-Path $junction "MsiBackup")
        } "reparse point"
    } finally {
        [IO.Directory]::Delete($junction)
    }
    if ((Get-Content -LiteralPath $file) -ne "unchanged") {
        throw "Rejected inputs modified the sentinel."
    }
    Remove-Item -LiteralPath $file

    foreach ($scope in @("HKLM", "HKCU")) {
        $key = "${scope}:\$registrySubkey"
        New-Item -Path $key -Force | Out-Null
        Set-ItemProperty -LiteralPath $key -Name "Value" -Value "original"
        Invoke-StoreAction "BackupStore" $scope
        Set-ItemProperty -LiteralPath $key -Name "Value" -Value "replacement"
        Invoke-StoreAction "RollbackStore" $scope
        if ((Get-ItemProperty -LiteralPath $key).Value -ne "original") {
            throw "$scope install rollback did not restore the original value."
        }
        Invoke-StoreAction "BackupStore" $scope
        Set-ItemProperty -LiteralPath $key -Name "Value" -Value "replacement"
        & $HelperPath -Action CommitStore -StateRoot $stateRoot
        if ($scope -eq "HKCU") {
            foreach ($name in @("ebpf-store-hkcu.json", "ebpf-store-hkcu.reg")) {
                Move-Item -LiteralPath (Join-Path $userStore $name) -Destination (Join-Path $stateRoot $name)
            }
        }
        Invoke-StoreAction "PrepareRestoreStore" $scope
        if ($scope -eq "HKCU" -and (Test-Path -LiteralPath (Join-Path $stateRoot "ebpf-store-hkcu.json"))) {
            throw "Trusted legacy HKCU state was not migrated."
        }
        Invoke-StoreAction "RestoreStore" $scope
        Invoke-StoreAction "RollbackRestoreStore" $scope
        if ((Get-ItemProperty -LiteralPath $key).Value -ne "replacement") {
            throw "$scope uninstall rollback did not restore the replacement value."
        }
        $storeRoot = if ($scope -eq "HKCU") { $userStore } else { $stateRoot }
        $metadata = Join-Path $storeRoot "ebpf-store-$($scope.ToLowerInvariant()).json"
        $originalMetadata = Get-Content -LiteralPath $metadata -Raw
        $invalidMetadata = $originalMetadata | ConvertFrom-Json
        $invalidMetadata.RegistryPath = "$scope\Software\OutOfScope"
        $invalidMetadata | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding UTF8
        Assert-Rejected { Invoke-StoreAction "RestoreStore" $scope } "registry destination is invalid"
        Set-Content -LiteralPath $metadata -Value $originalMetadata -Encoding UTF8
        if ($scope -eq "HKCU") {
            $invalidMetadata = $originalMetadata | ConvertFrom-Json
            $invalidMetadata.UserSid = "S-1-5-19"
            $invalidMetadata | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding UTF8
            Assert-Rejected { Invoke-StoreAction "RestoreStore" $scope } "not the current user"
            Set-Content -LiteralPath $metadata -Value $originalMetadata -Encoding UTF8
        }
        $export = Join-Path $storeRoot "ebpf-store-$($scope.ToLowerInvariant()).reg"
        $originalExport = Get-Content -LiteralPath $export -Raw
        Add-Content -LiteralPath $export -Encoding Unicode -Value "`r`n[HKEY_LOCAL_MACHINE\Software\OutOfScope]"
        Assert-Rejected { Invoke-StoreAction "RestoreStore" $scope } "outside the saved"
        if ((Get-ItemProperty -LiteralPath $key).Value -ne "replacement") {
            throw "Rejected $scope export changed the registry."
        }
        Set-Content -LiteralPath $export -Value $originalExport -Encoding Unicode
        Invoke-StoreAction "RestoreStore" $scope
        if ((Get-ItemProperty -LiteralPath $key).Value -ne "original") {
            throw "$scope final restoration failed."
        }
        Invoke-StoreAction "CommitRestoreStore" $scope
        Remove-Item -LiteralPath $key -Recurse
        Invoke-StoreAction "BackupStore" $scope
        New-Item -Path $key -Force | Out-Null
        Invoke-StoreAction "RestoreStore" $scope
        if (Test-Path -LiteralPath $key) {
            throw "$scope absent-store restoration failed."
        }
        Invoke-StoreAction "CommitRestoreStore" $scope
    }

    & $HelperPath -Action BackupServices -StateRoot $stateRoot -ServiceNames $serviceName
    & $HelperPath -Action CommitServices -StateRoot $stateRoot -ServiceNames $serviceName
    & $HelperPath -Action PrepareRestoreServices -StateRoot $stateRoot -ServiceNames $serviceName
    $cleanup = Join-Path $stateRoot "ForceEbpfStack.cleanup.ps1"
    & $cleanup -Action CommitRestoreAll -StateRoot $stateRoot -ServiceNames $serviceName
    if (@(Get-ChildItem -LiteralPath $stateRoot -File).Count -ne 0 -or
        @(Get-ChildItem -LiteralPath $userStore -Force).Count -ne 0) {
        throw "Commit cleanup left backup files behind."
    }
    Write-Output "PASS: backup ACLs, owners, directory locks, junctions, hard links, store rollback/restore, and commit cleanup."
} finally {
    foreach ($scope in @("HKLM", "HKCU")) {
        $key = "${scope}:\$registrySubkey"
        if (Test-Path -LiteralPath $key) {
            Remove-Item -LiteralPath $key -Recurse -Force
        }
    }
    if (Test-Path -LiteralPath $testParent) {
        Remove-Item -LiteralPath $testParent -Recurse -Force
    }
}
