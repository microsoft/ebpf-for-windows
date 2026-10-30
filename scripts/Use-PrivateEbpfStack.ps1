# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Temporarily replaces an inbox eBPF for Windows stack with private binaries.

.DESCRIPTION
Stages a version-matched private stack, backs up the inbox service configuration
and eBPF registry store, redirects the existing services, refreshes the store,
and starts the private stack. DeveloperScenario additionally installs
sample_ebpf_ext and exports its program information. Restore reverses the
operation and removes the sample extension service.

Run this script from an elevated PowerShell session. A VM checkpoint is strongly
recommended before enabling the private stack.

.EXAMPLE
.\Use-PrivateEbpfStack.ps1 Enable `
    -ArtifactDirectory C:\ebpf\x64\Debug `
    -PrivateDirectory "C:\Program Files\eBPF-for-Windows-Private\build-1234" `
    -DeveloperScenario `
    -TestApplicationDirectory C:\ebpf-tests,C:\additional-tests

.EXAMPLE
.\Use-PrivateEbpfStack.ps1 Enable `
    -ArtifactDirectory C:\ebpf\x64\Debug `
    -PrivateDirectory "C:\Program Files\eBPF-for-Windows-Private\build-1234" `
    -TestApplicationDirectories "C:\ebpf-tests;C:\additional-tests"

.EXAMPLE
.\Use-PrivateEbpfStack.ps1 Restore

.EXAMPLE
.\Use-PrivateEbpfStack.ps1 Status
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Enable", "Restore", "Status")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$ArtifactDirectory,

    [Parameter(Mandatory = $false)]
    [string]$PrivateDirectory,

    [Parameter(Mandatory = $false)]
    [string]$BackupDirectory,

    [Parameter(Mandatory = $false)]
    [switch]$DeveloperScenario,

    [Parameter(Mandatory = $false)]
    [Alias("TestApplicationDirectories")]
    [string[]]$TestApplicationDirectory = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$serviceNames = @("EbpfCore", "NetEbpfExt", "eBPFSvc")
$requiredFiles = @(
    "EbpfCore.sys",
    "NetEbpfExt.sys",
    "EbpfSvc.exe",
    "EbpfApi.dll",
    "export_program_info.exe"
)
$developerScenarioFiles = @(
    "sample_ebpf_ext.sys",
    "export_program_info_sample.exe"
)
$sampleExtensionServiceName = "sample_ebpf_ext"
$stateRoot = Join-Path $env:ProgramData "eBPF-for-Windows\PrivateStack"
$activeStatePath = Join-Path $stateRoot "active.json"

function Assert-Administrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated PowerShell session."
    }
}

function Invoke-NativeCommand
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "'$FilePath $($ArgumentList -join ' ')' failed with exit code $LASTEXITCODE."
    }
}

function Get-ServiceConfiguration
{
    param([Parameter(Mandatory = $true)][string]$Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        throw "Required service '$Name' is not installed."
    }

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $registryValues = Get-ItemProperty -Path $registryPath
    [PSCustomObject]@{
        Name = $Name
        ImagePath = [string]$registryValues.ImagePath
        Start = [int]$registryValues.Start
        WasRunning =
            $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running
        DelayedAutoStart =
            if ($null -ne $registryValues.PSObject.Properties["DelayedAutoStart"]) {
                [int]$registryValues.DelayedAutoStart
            } else {
                $null
            }
    }
}

function Convert-StartValueToScName
{
    param([Parameter(Mandatory = $true)][int]$Start)

    switch ($Start) {
        0 { "boot" }
        1 { "system" }
        2 { "auto" }
        3 { "demand" }
        4 { "disabled" }
        default { throw "Unsupported service Start value '$Start'." }
    }
}

function Set-ServiceConfiguration
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ImagePath,

        [Parameter(Mandatory = $true)]
        [int]$Start
    )

    $arguments = @(
        "config",
        $Name,
        "binPath=",
        $ImagePath,
        "start=",
        (Convert-StartValueToScName -Start $Start)
    )
    Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sc.exe" -ArgumentList $arguments
}

function Stop-EbpfStack
{
    param([Parameter(Mandatory = $false)][bool]$IncludeDeveloperScenario = $false)

    $servicesToStop = @("eBPFSvc")
    if ($IncludeDeveloperScenario) {
        $servicesToStop += $sampleExtensionServiceName
    }
    $servicesToStop += @("NetEbpfExt", "EbpfCore")

    foreach ($name in $servicesToStop) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            if ($name -eq $sampleExtensionServiceName) {
                continue
            }
            throw "Required service '$name' is not installed."
        }
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Write-Host "Stopping $name..."
            Stop-Service -Name $name -Force
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(60))
        }
    }
}

function Start-EbpfStack
{
    param([Parameter(Mandatory = $false)][bool]$IncludeDeveloperScenario = $false)

    $servicesToStart = @("EbpfCore", "NetEbpfExt")
    if ($IncludeDeveloperScenario) {
        $servicesToStart += $sampleExtensionServiceName
    }
    $servicesToStart += "eBPFSvc"

    foreach ($name in $servicesToStart) {
        Write-Host "Starting $name..."
        Start-Service -Name $name
        (Get-Service -Name $name).WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
    }
}

function Export-RegistryKey
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $providerPath =
        if ($RegistryPath.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
            "Registry::HKEY_LOCAL_MACHINE\" + $RegistryPath.Substring(5)
        } elseif ($RegistryPath.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
            "Registry::HKEY_CURRENT_USER\" + $RegistryPath.Substring(5)
        } else {
            throw "Unsupported registry path '$RegistryPath'."
        }
    $exists = Test-Path -LiteralPath $providerPath

    if ($exists) {
        Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\reg.exe" `
            -ArgumentList @("export", $RegistryPath, $DestinationPath, "/y")
    }

    return $exists
}

function Remove-RegistryTreeIfPresent
{
    param([Parameter(Mandatory = $true)][string]$RegistryPath)

    $providerPath =
        if ($RegistryPath.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
            "Registry::HKEY_LOCAL_MACHINE\" + $RegistryPath.Substring(5)
        } elseif ($RegistryPath.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
            "Registry::HKEY_CURRENT_USER\" + $RegistryPath.Substring(5)
        } else {
            throw "Unsupported registry path '$RegistryPath'."
        }

    if (Test-Path -LiteralPath $providerPath) {
        Remove-Item -LiteralPath $providerPath -Recurse -Force
    }
}

function Set-PrivateDirectoryAcl
{
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        $acl.RemoveAccessRuleSpecific($existingRule) | Out-Null
    }

    $inheritanceFlags =
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $rules = @(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "BUILTIN\Administrators", "FullControl", $inheritanceFlags, $propagationFlags, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "NT AUTHORITY\SYSTEM", "ReadAndExecute", $inheritanceFlags, $propagationFlags, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "NT SERVICE\eBPFSvc", "ReadAndExecute", $inheritanceFlags, $propagationFlags, $allow),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "BUILTIN\Users", "ReadAndExecute", $inheritanceFlags, $propagationFlags, $allow)
    )
    foreach ($rule in $rules) {
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Copy-PrivateStack
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeDeveloperScenario = $false
    )

    $sourcePath = (Resolve-Path -Path $Source).Path
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $destinationPath = (Resolve-Path -Path $Destination).Path
    if ($sourcePath.TrimEnd("\") -eq $destinationPath.TrimEnd("\")) {
        throw "ArtifactDirectory and PrivateDirectory must be different."
    }

    $filesToCopy = @($requiredFiles)
    if ($IncludeDeveloperScenario) {
        $filesToCopy += $developerScenarioFiles
    }

    foreach ($fileName in $filesToCopy) {
        $sourceFile = Join-Path $sourcePath $fileName
        if (-not (Test-Path -Path $sourceFile -PathType Leaf)) {
            throw "Required private component '$sourceFile' was not found."
        }
        Copy-Item -Path $sourceFile -Destination $destinationPath -Force
    }

    # Keep service and test executable dependencies app-local. This also covers
    # debug CRT binaries when they are included in the artifact directory.
    Get-ChildItem -Path $sourcePath -Filter "*.dll" -File | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $destinationPath -Force
    }
    Get-ChildItem -Path $sourcePath -Filter "*.pdb" -File | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $destinationPath -Force
    }

    Set-PrivateDirectoryAcl -Path $destinationPath
    return $destinationPath
}

function Install-SampleExtension
{
    param([Parameter(Mandatory = $true)][string]$DriverPath)

    if ($null -ne (Get-Service -Name $sampleExtensionServiceName -ErrorAction SilentlyContinue)) {
        throw "Service '$sampleExtensionServiceName' already exists. Remove the stale service before enabling the developer scenario."
    }

    Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sc.exe" `
        -ArgumentList @(
            "create",
            $sampleExtensionServiceName,
            "type=",
            "kernel",
            "start=",
            "demand",
            "binPath=",
            $DriverPath)
}

function Remove-SampleExtension
{
    $service = Get-Service -Name $sampleExtensionServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }

    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $sampleExtensionServiceName -Force
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(60))
    }
    Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sc.exe" `
        -ArgumentList @("delete", $sampleExtensionServiceName)
}

function Backup-TestApplicationDlls
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Directories,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $true)]
        [string]$PrivateEbpfApiPath
    )

    $results = @()
    $index = 0
    foreach ($directory in $Directories) {
        $resolvedDirectory = (Resolve-Path -Path $directory).Path
        $destination = Join-Path $resolvedDirectory "EbpfApi.dll"
        $existed = Test-Path -Path $destination -PathType Leaf
        $savedPath = $null
        if ($existed) {
            $savedPath = Join-Path $BackupPath "app-dll-$index\EbpfApi.dll"
            New-Item -ItemType Directory -Path (Split-Path $savedPath) -Force | Out-Null
            Copy-Item -Path $destination -Destination $savedPath -Force
        }
        Copy-Item -Path $PrivateEbpfApiPath -Destination $destination -Force
        $results += [PSCustomObject]@{
            Directory = $resolvedDirectory
            Existed = $existed
            BackupPath = $savedPath
        }
        $index++
    }
    return $results
}

function Expand-TestApplicationDirectories
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Directories)

    return @(
        $Directories |
            ForEach-Object { $_ -split ";" } |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

function Restore-TestApplicationDlls
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Entries)

    foreach ($entry in $Entries) {
        if ($null -eq $entry -or $null -eq $entry.PSObject.Properties["Directory"]) {
            continue
        }
        $destination = Join-Path $entry.Directory "EbpfApi.dll"
        if ($entry.Existed) {
            Copy-Item -Path $entry.BackupPath -Destination $destination -Force
        } else {
            Remove-Item -Path $destination -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-ActiveState
{
    if (-not (Test-Path -Path $activeStatePath -PathType Leaf)) {
        return $null
    }
    return Get-Content -Path $activeStatePath -Raw | ConvertFrom-Json
}

function Enable-PrivateStack
{
    if ([string]::IsNullOrWhiteSpace($ArtifactDirectory)) {
        throw "ArtifactDirectory is required for the Enable action."
    }
    if ([string]::IsNullOrWhiteSpace($PrivateDirectory)) {
        throw "PrivateDirectory is required for the Enable action."
    }
    if ($null -ne (Get-ActiveState)) {
        throw "A private eBPF stack is already active. Restore it before enabling another build."
    }

    if (-not $PSCmdlet.ShouldProcess("inbox eBPF stack", "Enable private eBPF stack")) {
        return
    }

    New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    if ($DeveloperScenario -and
        $null -ne (Get-Service -Name $sampleExtensionServiceName -ErrorAction SilentlyContinue)) {
        throw "Service '$sampleExtensionServiceName' already exists. Nothing was changed."
    }

    $privatePath = Copy-PrivateStack `
        -Source $ArtifactDirectory `
        -Destination $PrivateDirectory `
        -IncludeDeveloperScenario ([bool]$DeveloperScenario)
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath =
        if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
            Join-Path $stateRoot "backup-$timestamp"
        } else {
            $BackupDirectory
        }
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    $backupPath = (Resolve-Path -Path $backupPath).Path

    $serviceConfigurations = @()
    foreach ($name in $serviceNames) {
        $serviceConfigurations += Get-ServiceConfiguration -Name $name
        Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\reg.exe" `
            -ArgumentList @(
                "export",
                "HKLM\SYSTEM\CurrentControlSet\Services\$name",
                (Join-Path $backupPath "$name.reg"),
                "/y")
    }

    $hklmStoreExisted = Export-RegistryKey `
        -RegistryPath "HKLM\Software\eBPF" `
        -DestinationPath (Join-Path $backupPath "ebpf-store-hklm.reg")
    $hkcuStoreExisted = Export-RegistryKey `
        -RegistryPath "HKCU\Software\eBPF" `
        -DestinationPath (Join-Path $backupPath "ebpf-store-hkcu.reg")

    [string[]]$testApplicationDirectories =
        @(Expand-TestApplicationDirectories -Directories $TestApplicationDirectory)
    $appDlls = Backup-TestApplicationDlls `
        -Directories $testApplicationDirectories `
        -BackupPath $backupPath `
        -PrivateEbpfApiPath (Join-Path $privatePath "EbpfApi.dll")

    $state = [PSCustomObject]@{
        Version = 2
        Created = (Get-Date).ToString("o")
        PrivateDirectory = $privatePath
        BackupDirectory = $backupPath
        DeveloperScenario = [bool]$DeveloperScenario
        Services = $serviceConfigurations
        HklmStoreExisted = $hklmStoreExisted
        HkcuStoreExisted = $hkcuStoreExisted
        TestApplicationDlls = $appDlls
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $backupPath "state.json") -Encoding UTF8
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path $activeStatePath -Encoding UTF8

    Stop-EbpfStack

    Set-ServiceConfiguration `
        -Name "EbpfCore" `
        -ImagePath (Join-Path $privatePath "EbpfCore.sys") `
        -Start 3
    Set-ServiceConfiguration `
        -Name "NetEbpfExt" `
        -ImagePath (Join-Path $privatePath "NetEbpfExt.sys") `
        -Start 3
    Set-ServiceConfiguration `
        -Name "eBPFSvc" `
        -ImagePath ('"' + (Join-Path $privatePath "EbpfSvc.exe") + '"') `
        -Start 3
    if ($DeveloperScenario) {
        Install-SampleExtension -DriverPath (Join-Path $privatePath "sample_ebpf_ext.sys")
    }

    Push-Location $privatePath
    try {
        Invoke-NativeCommand -FilePath (Join-Path $privatePath "export_program_info.exe") -ArgumentList @("--clear")
        Invoke-NativeCommand -FilePath (Join-Path $privatePath "export_program_info.exe") -ArgumentList @()
        if ($DeveloperScenario) {
            Invoke-NativeCommand `
                -FilePath (Join-Path $privatePath "export_program_info_sample.exe") `
                -ArgumentList @("--clear")
            Invoke-NativeCommand `
                -FilePath (Join-Path $privatePath "export_program_info_sample.exe") `
                -ArgumentList @()
        }
    } finally {
        Pop-Location
    }

    Start-EbpfStack -IncludeDeveloperScenario ([bool]$DeveloperScenario)
    Write-Host "Private eBPF stack enabled from '$privatePath'."
    Write-Host "Restore data is in '$backupPath'."
}

function Restore-InboxStack
{
    $state =
        if (-not [string]::IsNullOrWhiteSpace($BackupDirectory)) {
            $statePath = Join-Path $BackupDirectory "state.json"
            if (-not (Test-Path -Path $statePath -PathType Leaf)) {
                throw "Backup state file '$statePath' was not found."
            }
            Get-Content -Path $statePath -Raw | ConvertFrom-Json
        } else {
            Get-ActiveState
        }
    if ($null -eq $state) {
        throw "No active private eBPF stack or BackupDirectory was found."
    }

    if (-not $PSCmdlet.ShouldProcess("inbox eBPF stack", "Restore inbox eBPF stack")) {
        return
    }

    $developerScenarioEnabled =
        $null -ne $state.PSObject.Properties["DeveloperScenario"] -and
        [bool]$state.DeveloperScenario

    Stop-EbpfStack -IncludeDeveloperScenario $developerScenarioEnabled

    if ($developerScenarioEnabled) {
        $sampleExporter = Join-Path $state.PrivateDirectory "export_program_info_sample.exe"
        if (Test-Path -Path $sampleExporter -PathType Leaf) {
            Push-Location $state.PrivateDirectory
            try {
                Invoke-NativeCommand -FilePath $sampleExporter -ArgumentList @("--clear")
            } finally {
                Pop-Location
            }
        }
        Remove-SampleExtension
    }

    foreach ($service in $state.Services) {
        Set-ServiceConfiguration `
            -Name $service.Name `
            -ImagePath $service.ImagePath `
            -Start ([int]$service.Start)

        $delayedAutoStartPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        if ($null -eq $service.DelayedAutoStart) {
            Remove-ItemProperty `
                -Path $delayedAutoStartPath `
                -Name "DelayedAutoStart" `
                -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty `
                -Path $delayedAutoStartPath `
                -Name "DelayedAutoStart" `
                -Value ([int]$service.DelayedAutoStart)
        }
    }

    Remove-RegistryTreeIfPresent -RegistryPath "HKLM\Software\eBPF"
    Remove-RegistryTreeIfPresent -RegistryPath "HKCU\Software\eBPF"
    if ($state.HklmStoreExisted) {
        Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\reg.exe" `
            -ArgumentList @("import", (Join-Path $state.BackupDirectory "ebpf-store-hklm.reg"))
    }
    if ($state.HkcuStoreExisted) {
        Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\reg.exe" `
            -ArgumentList @("import", (Join-Path $state.BackupDirectory "ebpf-store-hkcu.reg"))
    }

    Restore-TestApplicationDlls -Entries @($state.TestApplicationDlls)
    foreach ($name in @("EbpfCore", "NetEbpfExt", "eBPFSvc")) {
        $service = $state.Services | Where-Object { $_.Name -eq $name }
        if ($service.WasRunning) {
            Write-Host "Starting $name..."
            Start-Service -Name $name
            (Get-Service -Name $name).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
        }
    }

    if (Test-Path -Path $activeStatePath -PathType Leaf) {
        Remove-Item -Path $activeStatePath -Force
    }
    Write-Host "Inbox eBPF stack restored."
    Write-Host "Reboot the VM before treating the restoration as complete."
}

function Show-StackStatus
{
    $state = Get-ActiveState
    if ($null -eq $state) {
        Write-Host "Private stack state: inactive"
    } else {
        Write-Host "Private stack state: active"
        Write-Host "Private directory: $($state.PrivateDirectory)"
        Write-Host "Backup directory:  $($state.BackupDirectory)"
        $developerScenarioEnabled =
            $null -ne $state.PSObject.Properties["DeveloperScenario"] -and
            [bool]$state.DeveloperScenario
        Write-Host "Developer scenario: $developerScenarioEnabled"
    }

    foreach ($name in $serviceNames) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Host "${name}: not installed"
            continue
        }
        $configuration = Get-ServiceConfiguration -Name $name
        Write-Host "${name}: $($service.Status), ImagePath=$($configuration.ImagePath), Start=$($configuration.Start)"
    }

    $sampleService = Get-Service -Name $sampleExtensionServiceName -ErrorAction SilentlyContinue
    if ($null -eq $sampleService) {
        Write-Host "${sampleExtensionServiceName}: not installed"
    } else {
        $sampleConfiguration = Get-ServiceConfiguration -Name $sampleExtensionServiceName
        Write-Host (
            "${sampleExtensionServiceName}: $($sampleService.Status), " +
            "ImagePath=$($sampleConfiguration.ImagePath), Start=$($sampleConfiguration.Start)")
    }
}

Assert-Administrator
switch ($Action) {
    "Enable" { Enable-PrivateStack }
    "Restore" { Restore-InboxStack }
    "Status" { Show-StackStatus }
}
