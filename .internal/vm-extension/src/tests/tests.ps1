# Change the working directory to the root of the test environment, so to simulate the actual env that will be set up by the VM Agent.
Set-Variable -Name "testRootFolder" -Value "C:\_ebpf\vm_ext\tests"
$currentDirectory = Get-Location
Set-Location "$testRootFolder"

# Dot source the utility script
. ..\scripts\common.ps1

# Load test-environment (current working folder is the root folder in which the entire ZIP in unzipped).
if (Get-HandlerEnvironment -handlerEnvironmentFullPath "$DefaultHandlerEnvironmentFilePath" -eq $true) {

    # Test cases
    #######################################################
    # Raw environment cleanup
    Write-Log -level $LogLevelInfo -message "= Cleaning up environment =================================================================================================="        
    $null = net stop eBPFCore 2>&1
    $null = sc.exe delete eBPFCore 2>&1
    $null = net stop NetEbpfExt 2>&1
    $null = sc.exe delete NetEbpfExt 2>&1
    $null = netsh delete helper ebpfnetsh.dll 2>&1
    $null = Remove-DirectoryFromSystemPath "$EbpfDefaultInstallPath" 2>&1
    $null = Remove-Item -Path "$EbpfDefaultInstallPath" -Recurse -Force 2>&1
    $null = Remove-Item -Path "$global:LogFilePath" -Recurse -Force 2>&1

    # Clean-up and set up the test environment with two versions of the eBPF redist package
    $testRedistTargetDirectory = ".\_ebpf-redist"
    Delete-Directory -destinationPath $testRedistTargetDirectory | Out-Null
    DownloadAndUnpackEbpfRedistPackage -packageVersion "0.9.0" -targetDirectory $testRedistTargetDirectory | Out-Null
    DownloadAndUnpackEbpfRedistPackage -packageVersion "0.9.1" -targetDirectory $testRedistTargetDirectory | Out-Null 

    # Do some version comparison tests
    $currProductVersion = "0.9.0"
    $newProductVersion = "0.9.0.1"
    $comparison = Compare-VersionNumbers -version1 $currProductVersion -version2 $newProductVersion
    if ($comparison -eq 2) {
        Write-Log -level $LogLevelInfo -message "(v$currProductVersion) == v$newProductVersion) -> handler-only update!"
    } elseif ($comparison -lt 0) {
        Write-Log -level $LogLevelInfo -message "(v$currProductVersion) < v$newProductVersion)"
    } elseif ($comparison -gt 0) {
        Write-Log -level $LogLevelInfo -message "(v$currProductVersion) == v$newProductVersion)"
    } else {
        Write-Log -level $LogLevelInfo -message "(v$currProductVersion) > v$newProductVersion)"
    }

    # Install an old version
    # Add a new handler on the VM (Install and Enable)
    $packageVersion = "0.9.0"
    Write-Log -level $LogLevelInfo -message "= Install an old version =================================================================================================="
    Delete-Directory -destinationPath "$EbpfPackagePath" | Out-Null
    Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath" | Out-Null 
    $statusCode = InstallOrUpdate-eBPF -operationName $OperationNameInstall -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
    # The VM Agent will then call 'Enable' on the handler
    Enable-eBPF -operationName $OperationNameInstall -statusCode $statusCode | Out-Null

    # Test that the status file name has the right sequence number ($EbpfExtensionName.1002.settings is the one modified last)
    $statusFileName = Get-ChildItem -Path "$($global:eBPFHandlerEnvObj.handlerEnvironment.statusFolder)" -Filter "*.status" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($statusFileName.Name -ne "$EbpfExtensionName.1002.status") {
        Write-Log -level $LogLevelError -message "Status file name is not correct: $statusFileName"
    } else {
        Write-Log -level $LogLevelInfo -message "Status file name is correct: $statusFileName"
    }
    
    # Simulate a handler-only update, by changing the handler's new target version in the VERSION environment variable
    Write-Log -level $LogLevelInfo -message "= Simulate a handler-only update ============================================================================================"
    [Environment]::SetEnvironmentVariable($VmAgentEnvVar_VERSION, "0.9.0.1", [System.EnvironmentVariableTarget]::Machine)
    $statusCode = InstallOrUpdate-eBPF -operationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath"
    # The VM Agent will then call 'Enable' on the handler
    Enable-eBPF -operationName $OperationNameInstall -statusCode $statusCode | Out-Null
    [Environment]::SetEnvironmentVariable($VmAgentEnvVar_VERSION, $null, [System.EnvironmentVariableTarget]::Machine)

    # Update to a newer version
    # Update a handler to different version (Disable and Update)        
    $packageVersion = "0.9.1"
    Write-Log -level $LogLevelInfo -message "= Update to newer version =================================================================================================="
    Disable-eBPF | Out-Null
    Delete-Directory -destinationPath "$EbpfPackagePath" | Out-Null 
    Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath" | Out-Null 
    Create-StatusFile -name $StatusName -operation $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
    InstallOrUpdate-eBPF -operationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath" | Out-Null 
    
    # Update back to an older version
    $packageVersion = "0.9.0"
    Write-Log -level $LogLevelInfo -message "= Update to older version =================================================================================================="
    Delete-Directory -destinationPath "$EbpfPackagePath" | Out-Null 
    Copy-Directory -sourcePath "$testRedistTargetDirectory\v$packageVersion" -destinationPath "$EbpfPackagePath" | Out-Null 
    Create-StatusFile -name $StatusName -operation $OperationNameUpdate -status $StatusTransitioning -statusCode 0 -$statusMessage "Starting eBPF update"
    InstallOrUpdate-eBPF -operationName $OperationNameUpdate -sourcePath "$EbpfPackagePath" -destinationPath "$EbpfDefaultInstallPath" | Out-Null 

    # Uninstall
    # Remove a handler from the VM (Disable and Uninstall): https://github.com/Azure/azure-vmextension-publishing/wiki/2.0-Partner-Guide-Handler-Design-Details#222-remove-a-handler-from-the-vm-disable-and-uninstall
    Write-Log -level $LogLevelInfo -message "= Uninstall =================================================================================================="
    $statusCode = Uninstall-eBPF $EbpfDefaultInstallPath
    if ($statusCode -eq 0) {
        $statusString = $StatusSuccess
        $statusMessage = "eBPF for Windows was successfully uninstalled"
    }
    else {
        $statusString = $StatusError
        $statusMessage = "eBPF for Windows was not uninstalled"
    }
    Create-StatusFile -name $StatusName -operation $OperationNameUninstall -status $statusString -statusCode $statusCode -statusMessage $statusMessage
} else {
    Write-Log -level $LogLevelError -message "Failed to load '$DefaultHandlerEnvironmentFilePath'."
}

Set-Location $currentDirectory