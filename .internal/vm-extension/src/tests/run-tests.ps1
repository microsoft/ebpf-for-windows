# Change the working directory to the root of the test environment, so to simulate the actual env that will be set up by the VM Agent.
Set-Variable -Name "testRootFolder" -Value "C:\_ebpf\vm_ext\tests"
$currentDirectory = Get-Location
Set-Location "$testRootFolder"

# Dot source the utility script
. ..\scripts\common.ps1

$testPass = $true

function DownloadAndUnpackEbpfRedistPackage {
    param (
        [string]$packageVersion,
        [string]$targetDirectory
    )

    Write-Log -level $LogLevelInfo -message "DownloadAndUnpackEbpfRedistPackage($packageVersion, $targetDirectory)"

    # Download the eBPF redist package from the MS CodeHub feed, and unpack just the eBPF package to the target directory
    Start-Process nuget.exe  -ArgumentList "install eBPF-for-Windows-Redist -version $packageVersion -Source https://mscodehub.pkgs.visualstudio.com/eBPFForWindows/_packaging/eBPFForWindows/nuget/v3/index.json -OutputDirectory $targetDirectory" -Wait
    Rename-Item -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\eBPF-for-Windows-Redist.$packageVersion.nupkg" -NewName "eBPF-for-Windows-Redist.$packageVersion.nupkg.zip"
    Expand-Archive -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\eBPF-for-Windows-Redist.$packageVersion.nupkg.zip" -DestinationPath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\temp"
    Copy-Directory -sourcePath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\temp\package\bin" -destinationPath "$targetDirectory\v$packageVersion"
    Delete-Directory -destinationPath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion"
}

function Setup-Test-Package {
    param (
        [string]$packageVersion,
        [string]$testRedistTargetDirectory
    )

    Write-Log -level $LogLevelInfo -message "Setup-Test-Package($packageVersion, $testRedistTargetDirectory)"

    $res = $true
    if ((Delete-Directory -destinationPath "$EbpfPackagePath") -ne $true) {
        $res = $false
    }    
    if ((Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath") -ne $true) {
        $res = $false
    }

    return $res
}

# Load test-environment (current working folder is the root folder in which the entire ZIP in unzipped).
if (Get-HandlerEnvironment -handlerEnvironmentFullPath "$DefaultHandlerEnvironmentFilePath" -eq $true) {

    # Test cases
    #######################################################
    # Raw environment cleanup.
    Write-Log -level $LogLevelInfo -message "= Cleaning up environment =================================================================================================="        
    $null = net stop eBPFCore 2>&1
    $null = sc.exe delete eBPFCore 2>&1
    $null = net stop NetEbpfExt 2>&1
    $null = sc.exe delete NetEbpfExt 2>&1
    $null = netsh delete helper ebpfnetsh.dll 2>&1
    $null = Remove-DirectoryFromSystemPath "$EbpfDefaultInstallPath" 2>&1
    $null = Remove-Item -Path "$EbpfDefaultInstallPath" -Recurse -Force 2>&1
    $null = Remove-Item -Path "$global:LogFilePath" -Recurse -Force 2>&1

    # Clean-up and set up the test environment with two versions of the eBPF redist package.
    $testRedistTargetDirectory = ".\_ebpf-redist"
    Delete-Directory -destinationPath $testRedistTargetDirectory | Out-Null
    $res = DownloadAndUnpackEbpfRedistPackage -packageVersion "0.9.0" -targetDirectory $testRedistTargetDirectory
    if ($res -ne $true) {    
        $testPass = $false
    }
    $res = DownloadAndUnpackEbpfRedistPackage -packageVersion "0.9.1" -targetDirectory $testRedistTargetDirectory
    if ($res -ne $true) {    
        $testPass = $false
    }

    # Spcific test cases regarding eBPF-only updates.
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.10.0"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 1) {
        $testPass = $false
    }
    $currProductVersion = "0.10.0"
    $newProductVersion = "0.10.0"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 0) {
        $testPass = $false
    }
    $currProductVersion = "0.10.0"
    $newProductVersion = "0.9.0"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne -1) {
        $testPass = $false
    }
    
    # Spcific test cases regarding hanler-only updates.
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.9.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 2) {
        $testPass = $false
    }
    $currProductVersion = "0.10.0"
    $newProductVersion = "0.9.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne -1) {
        $testPass = $false
    }
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.10.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 1) {
        $testPass = $false
    }

    # Test that the status file name has the right sequence number ($EbpfExtensionName.1002.settings is artificially set to the one modified last).
    Create-StatusFile -name $StatusName -operation "test" -status $StatusTransitioning -statusCode 0 -$statusMessage "Dummy status"
    $statusFileName = Get-ChildItem -Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)" -Filter "*.status" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($statusFileName.Name -ne "$EbpfExtensionName.1002.status") {
        $testPass = $false
        Write-Log -level $LogLevelError -message "Status file name is not correct: $statusFileName"
    } else {
        Write-Log -level $LogLevelInfo -message "Status file name is correct: $statusFileName"
    }

    # Install an old version, i.e. Add a new handler on the VM (Install and Enable)
    Write-Log -level $LogLevelInfo -message "= Install an old version =================================================================================================="
    if ((Setup-Test-Package -packageVersion "0.9.0" -testRedistTargetDirectory $testRedistTargetDirectory) -ne $true) {
        $testPass = $false
    }
    if ((Set-EnvironmentVariable -variableName $VmAgentEnvVar_VERSION -variableValue "0.9.0.0") -ne $true) {
        $testPass = $false
    }
    if ((Install-eBPF-Handler) -ne 0) {
        $testPass = $false
    } 
    if ((Enable-eBPF-Handler) -ne 0) { # The VM Agent will then call 'Enable' on the handler
        $testPass = $false     
    }
        
    # Simulate a handler-only update, by changing the handler's new target version in the VERSION environment variable.
    Write-Log -level $LogLevelInfo -message "= Simulate a handler-only update =========================================================================================="
    if ((Set-EnvironmentVariable -variableName $VmAgentEnvVar_VERSION -variableValue "0.9.0.1") -ne $true) {
        $testPass = $false
    }
    if ((Disable-eBPF-Handler) -ne 0) { # The VM Agent will first call 'Disable' on the handler
        $testPass = $false
    }
    if ((Update-eBPF-Handler) -ne 0) {
        $testPass = $false
    }

    # Update to a newer version, i.e. handler's update is called (Disable and Update).
    Write-Log -level $LogLevelInfo -message "= Update to newer version ================================================================================================="
    if ((Setup-Test-Package -packageVersion "0.9.1" -testRedistTargetDirectory $testRedistTargetDirectory) -ne $true) {
        $testPass = $false
    }
    if ((Set-EnvironmentVariable -variableName $VmAgentEnvVar_VERSION -variableValue "0.9.1.0") -ne $true) {
        $testPass = $false
    }
    if ((Disable-eBPF-Handler) -ne 0) { # The VM Agent will first call 'Disable' on the handler
        $testPass = $false
    }    
    if ((Update-eBPF-Handler) -ne 0) {
        $testPass = $false
    }
    
    # Attempt to update back to an older version
    Write-Log -level $LogLevelInfo -message "= Attempt to update back to an older version =============================================================================="
    if ((Setup-Test-Package -packageVersion "0.9.0" -testRedistTargetDirectory $testRedistTargetDirectory) -ne $true) {
        $testPass = $false
    }
    if ((Set-EnvironmentVariable -variableName $VmAgentEnvVar_VERSION -variableValue "0.9.0.0") -ne $true) {
        $testPass = $false
    }
    if ((Disable-eBPF-Handler) -ne 0) { # The VM Agent will first call 'Disable' on the handler
        $testPass = $false
    }    
    if ((Update-eBPF-Handler) -eq 0) {
        $testPass = $false
    }
    
    # Uninstall, i.e. Remove a handler from the VM (Disable and Uninstall): https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#222-remove-a-handler-from-the-vm-disable-and-uninstall
    Write-Log -level $LogLevelInfo -message "= Uninstall ==============================================================================================================="
    if ((Disable-eBPF-Handler) -ne 0) { # The VM Agent will first call 'Disable' on the handler
        $testPass = $false
    }  
    if ((Uninstall-eBPF-Handler) -ne 0) {
        $testPass = $false
    }
} else {
    $testPass = $false
    Write-Log -level $LogLevelError -message "Failed to load '$DefaultHandlerEnvironmentFilePath'."
}

Set-Location $currentDirectory

if ($testPass -eq $true) {
    Write-Log -level $LogLevelInfo -message "Tests succesfully PASSED."
} else {
    Write-Log -level $LogLevelError -message "Tests FAILED."
}

return $testPass
