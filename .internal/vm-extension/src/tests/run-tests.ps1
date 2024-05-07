# Change the working directory to the root of the test environment, so to simulate the actual env that will be set up by the VM Agent.
Set-Variable -Name "testRootFolder" -Value "C:\work\eBPFForWindows\.internal\vm-extension\src\tests"
$currentDirectory = Get-Location
Set-Location "$testRootFolder"

# Dot source the utility script
. ..\scripts\common.ps1

$testPass = 0
$versionV1 = "0.9.0"
$versionV2 = "0.11.0"
$versionV2Handler = "0.11.0.2"

function Exit-Tests {
    param (
        [int]$testPass
    )

    Set-Location $currentDirectory

    if ($testPass -eq 0) {
        Write-Log -level $LogLevelInfo -message "Tests successfully PASSED."
    } else {
        Write-Log -level $LogLevelError -message "Tests FAILED."
    }

    exit $testPass
}

# Test command: nuget install eBPF-for-Windows-Redist -version 0.9.0 -Source https://mscodehub.pkgs.visualstudio.com/eBPFForWindows/_packaging/eBPFForWindows/nuget/v3/index.json -OutputDirectory .\_ebpf-redist
function DownloadAndUnpackEbpfRedistPackage {
    param (
        [string]$packageVersion,
        [string]$targetDirectory
    )

    Write-Log -level $LogLevelInfo -message "DownloadAndUnpackEbpfRedistPackage($packageVersion, $targetDirectory)"

    $res = 0
    try {
        # Download the eBPF redist package from the MS CodeHub feed, and unpack just the eBPF package to the target directory
        $nugetArgs = @{
            FilePath = 'nuget.exe'
            ArgumentList = "install eBPF-for-Windows-Redist -version $packageVersion -Source https://mscodehub.pkgs.visualstudio.com/eBPFForWindows/_packaging/eBPFForWindows/nuget/v3/index.json -OutputDirectory $targetDirectory"
            Wait = $true
        }
        Start-Process @nugetArgs | Out-Null

        # Unpack the eBPF package to the target directory
        Rename-Item -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\eBPF-for-Windows-Redist.$packageVersion.nupkg" -NewName "eBPF-for-Windows-Redist.$packageVersion.nupkg.zip" | Out-Null
        Expand-Archive -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\eBPF-for-Windows-Redist.$packageVersion.nupkg.zip" -DestinationPath "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\temp" | Out-Null

        # Copy the eBPF package to the target directory (in a "bin" subfolder), and remove the temp folder.
        Copy-Item -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion\temp\package\bin" -Destination "$targetDirectory\v$packageVersion" -Recurse -Force | Out-Null
        Remove-Item -Path "$targetDirectory\eBPF-for-Windows-Redist.$packageVersion" -Recurse -Force | Out-Null
    }
    catch {
        $res = 1
        Write-Log -level $LogLevelError -message "An error occurred: $_"
    }

    return $res
}

function Setup-Test-Package {
    param (
        [string]$packageVersion,
        [string]$testRedistTargetDirectory
    )

    Write-Log -level $LogLevelInfo -message "Setup-Test-Package($packageVersion, $testRedistTargetDirectory)"

    $res = 0
    if ((Delete-Directory -destinationPath "$EbpfPackagePath") -ne 0) {
        $res = 1
    }    
    if ((Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath") -ne 0) {
        $res = 1
    }

    return $res
}

# Load test-environment (current working folder is the root folder in which the entire ZIP in unzipped).
if ((Get-HandlerEnvironment -handlerEnvironmentFullPath "$DefaultHandlerEnvironmentFilePath") -eq 0) {
    
    # Override the default package path.
    $EbpfPackagePath = ".\package"

    # Mock the VM-Agent provisioning the SequenceNumber environment variable.
    Set-Item -Path Env:\$VmAgentEnvVar_SEQUENCE_NO -Value "1" | Out-Null

    #######################################################
    # Test cases
    #######################################################

    # Raw environment cleanup.
    Write-Log -level $LogLevelInfo -message "= Cleaning up environment =================================================================================================="
    $null = Remove-Item -Path "$global:LogFilePath" -Recurse -Force 2>&1    
    Get-HandlerEnvironment -handlerEnvironmentFullPath "$DefaultHandlerEnvironmentFilePath" # Re-run just to log the HandlerEnvironment contents (in path not available before reading it)
    $null = net stop eBPFCore 2>&1
    $null = sc.exe delete eBPFCore 2>&1
    $null = net stop NetEbpfExt 2>&1
    $null = sc.exe delete NetEbpfExt 2>&1
    $null = netsh delete helper ebpfnetsh.dll 2>&1
    $null = Remove-DirectoryFromSystemPath "$EbpfDefaultInstallPath" 2>&1
    $null = Remove-Item -Path "$EbpfDefaultInstallPath" -Recurse -Force 2>&1

    # Log the environment compatibility.
    Write-Log -level $LogLevelInfo -message "= Test the environment compatibility ========================================================================================="
    Is-InstallOrUpdate-Supported

    # Download the required versions of the eBPF redist package, directly from MsCodeHub.
    Write-Log -level $LogLevelInfo -message "= Downloading the required versions of the eBPF redist package, directly from MsCodeHub ===================================="
    $testRedistTargetDirectory = ".\_ebpf-redist"
    Delete-Directory -destinationPath $testRedistTargetDirectory | Out-Null
    $res = DownloadAndUnpackEbpfRedistPackage -packageVersion $versionV1 -targetDirectory $testRedistTargetDirectory
    if ($res -ne 0) {
        Exit-Tests -testPass 1
    }
    $res = DownloadAndUnpackEbpfRedistPackage -packageVersion $versionV2 -targetDirectory $testRedistTargetDirectory
    if ($res -ne 0) { 
        Exit-Tests -testPass 1
    }
    $res = DownloadAndUnpackEbpfRedistPackage -packageVersion $versionV2Handler -targetDirectory $testRedistTargetDirectory
    if ($res -ne 0) { 
        Exit-Tests -testPass 1
    }

    # Specific test cases regarding version comparing.
    Write-Log -level $LogLevelInfo -message "= Specific test cases regarding version comparing =========================================================================="
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.10.0"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne -1) {
        Exit-Tests -testPass 1
    }
    $currProductVersion = "0.10.0"
    $newProductVersion = "0.10.0"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 0) {
        Exit-Tests -testPass 1
    }
    $currProductVersion = "0.10.0"
    $newProductVersion = "0.9.0"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 1) {
        Exit-Tests -testPass 1
    }
    
    # Specific test cases regarding version comparing for hanler-only updates.
    Write-Log -level $LogLevelInfo -message "= Specific test cases regarding version comparing for  handler-only updates ================================================"
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.9.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 2) {
        Exit-Tests -testPass 1
    }
    $currProductVersion = "0.10.0"
    $newProductVersion = "0.9.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne 1) {
        Exit-Tests -testPass 1
    }
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.10.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    Write-Log -level $LogLevelInfo -message "(v$currProductVersion) Vs (v$newProductVersion) -> $comparison"
    if ($comparison -ne -1) {
        Exit-Tests -testPass 1
    }

    # Test that the status file name has the right sequence number ($EbpfExtensionName.1002.settings is artificially set to the one modified last).
    Write-Log -level $LogLevelInfo -message "= Test status file sequencing =============================================================================================="
    Report-Status -name $StatusName -operation "test" -status $StatusTransitioning -statusCode 0 -$statusMessage "Dummy status"
    $statusFileName = Get-ChildItem -Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)" -Filter "*.status" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($statusFileName.Name -ne "1.status") {
        Exit-Tests -testPass 1
        Write-Log -level $LogLevelError -message "Status file name is not correct: $statusFileName"
    } else {
        Write-Log -level $LogLevelInfo -message "Status file name is correct: $statusFileName"
    }

    # Install an old version, i.e. Add a new handler on the VM (Install and Enable)
    Write-Log -level $LogLevelInfo -message "= Install version V1 ======================================================================================================="
    if ((Setup-Test-Package -packageVersion $versionV1 -testRedistTargetDirectory $testRedistTargetDirectory) -ne 0) {
        Exit-Tests -testPass 1
    }
    if ((Install-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    } 
    if ((Enable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }

    # Attempt to update to a newer version
    Write-Log -level $LogLevelInfo -message "= Update to version V2 ====================================================================================================="
    if ((Setup-Test-Package -packageVersion $versionV2 -testRedistTargetDirectory $testRedistTargetDirectory) -ne 0) {
        Exit-Tests -testPass 1
    }
    if ((Disable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    if ((Update-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    if ((Uninstall-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {  # NOP on update
        Exit-Tests -testPass 1
    }
    if ((Enable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {  # NOP on update
        Exit-Tests -testPass 1
    }

    # Simulate a handler-only update (update is distinguished by the fourth digit in the version number).
    Write-Log -level $LogLevelInfo -message "= Simulate a V2 handler-only update ========================================================================================"
    if ((Setup-Test-Package -packageVersion $versionV2Handler -testRedistTargetDirectory $testRedistTargetDirectory) -ne 0) {
        Exit-Tests -testPass 1
    }
    if ((Disable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    if ((Update-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    if ((Uninstall-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {  # NOP on update
        Exit-Tests -testPass 1
    }
    if ((Enable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {  # NOP on update
        Exit-Tests -testPass 1
    }
    
    # Attempt to update to an older version (downgrade is not allowed)
    Write-Log -level $LogLevelInfo -message "= Attempt to update to older version V1 ===================================================================================="
    if ((Setup-Test-Package -packageVersion $versionV1 -testRedistTargetDirectory $testRedistTargetDirectory) -ne 0) {
        Exit-Tests -testPass 1
    }
    if ((Disable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    if ((Update-eBPF-Handler) -eq $EbpfStatusCode_SUCCESS) { # Downgrade is not allowed
        Exit-Tests -testPass 1
    }
    # If the update failed, the VM Agent will not call any other handler operation.

    # Rollback tests
    Write-Log -level $LogLevelInfo -message "= Rollback tests ==========================================================================================================="
    Write-Log -level $LogLevelInfo -message "= Uninstall all ============================================================================================================"
    if ((Disable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) { # The VM Agent will first call 'Disable' on the handler
        Exit-Tests -testPass 1
    }  
    if ((Uninstall-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    Write-Log -level $LogLevelInfo -message "= Install version V1 ======================================================================================================="
    if ((Setup-Test-Package -packageVersion $versionV1 -testRedistTargetDirectory $testRedistTargetDirectory) -ne 0) {
        Exit-Tests -testPass 1
    }
    if ((Install-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    } 
    if ((Enable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }

    # Attempt to update to an newer version, with a corrupted package (i.e. bad eBPF driver), so to test the rollback.
    Write-Log -level $LogLevelInfo -message "= Update to version V2 with injected package corruption and rollback ======================================================="
    if ((Setup-Test-Package -packageVersion $versionV2 -testRedistTargetDirectory $testRedistTargetDirectory) -ne 0) {
        Exit-Tests -testPass 1
    }
    # Alter the package to simulate a corrupted package. 
    Move-Item $EbpfPackagePath\drivers\eBPFCore.sys $EbpfPackagePath\drivers\eBPFCore.sys.bak -Force | Out-Null
    if ((Disable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
    if ((Update-eBPF-Handler) -eq $EbpfStatusCode_SUCCESS) { # Update will fail and rollback the previous installation
        Exit-Tests -testPass 1
    }
    # If the update failed, the VM Agent will not call any other handler operation.
    
    # Uninstall eBPF
    Write-Log -level $LogLevelInfo -message "= Uninstall all ============================================================================================================"
    if ((Disable-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) { # The VM Agent will first call 'Disable' on the handler
        Exit-Tests -testPass 1
    }  
    if ((Uninstall-eBPF-Handler) -ne $EbpfStatusCode_SUCCESS) {
        Exit-Tests -testPass 1
    }
} else {
    Exit-Tests -testPass 1
    Write-Log -level $LogLevelError -message "Failed to load '$DefaultHandlerEnvironmentFilePath'."
}

Exit-Tests -testPass 0
