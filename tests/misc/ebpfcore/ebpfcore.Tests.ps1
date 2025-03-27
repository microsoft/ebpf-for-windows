# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
#
#   This 'pester' test module contains misc. ebpfcore.sys specific tests that are not part of the
#   main test suite.
#
#   Pester info: https://pester.dev/docs/quick-start
#

Set-StrictMode -Version Latest

# Display all verbose messages, continuing execution of the script
$VerbosePreference = "Continue"

Describe "Verify native program behavior after EbpfCore stop-and-restart" {

    #
    # This blocks describes a basic test that ebpfcore.sys can be unloaded cleanly while programs
    # are pinned.
    #
    # NOTE: ebpfcore.sys cannot be unloaded in the presense of a running user-mode program that
    # links with EbpfApi.dll as this dll opens a handle to ebpfcore.sys in the context of
    # DLL_PROCESS_ATTACH notification.  We get around this limitation by loading and pinning a
    # sample program using the 'netsh.exe' utility and a command available in the 'netsh ebpf'
    # context.  netsh.exe itself terminates after loading and pinning the specified program, thus
    # closing its own handle to ebpfcore.sys.
    #
    # So long as there are no other user-mode applications (that link with EbpfApi.dll) running, we
    # _should_ be able to stop and subsequently re-start ebpfcore.sys without any issues.
    #
    # On stopping ebpfcore.sys, all loaded and/or pinned ebpf_objects such as programs/maps are
    # removed from memory for good.  These objects will need to be re-loaded and/or pinned after
    # ebpfcore.sys is restarted.

    # This test verifies the above by performing the following steps:
    #   1.  Ensure ebpfcore.sys is installed and Running
    #   2.  Load and pin a sample ebpf program (test_sample_ebpf.sys) using netsh.exe.
    #   3.  Verify that the ebpf program is loaded and pinned with the expected path
    #       using netsh.exe.
    #   4.  Stop ebpfcore.sys.
    #   5.  Verify that the sample ebpf program loaded and pinned in step 2 above has been removed.
    #   6.  Restart ebpfcore.sys
    #   7.  Verify that ebpfcore.sys has been restarted successfully.

    Function script:Add-eBPFProgram
    {
        param (
            [Parameter(Mandatory=$true)] [string] $ProgramName,
            [Parameter(Mandatory=$false)] [string] $PinPath = $null
        )

        $NetshArgs = "ebpf add program $ProgramName"
        if ($PinPath -ne $null) {
            $NetshArgs += " pinpath= $PinPath"
        }

        Write-Output "***** netsh $NetshArgs"
        $Result = Start-Process -FilePath 'netsh' -ArgumentList $NetshArgs -Wait -PassThru
        if ($Result.ExitCode -ne 0) {
            "*** FATAL ERROR *** Failed to load and pin program $ProgramName" | Out-Host
        }
        $Result.ExitCode | Should -Be 0
    }

    # NOTE: The opening brace for _all_ pester specific blocks ('describe/context/It...' etc.) must
    # be on the same line as the block declaration. Else, pester is unable to recoginize the block.
    #
    # Pester does not support variables local to the 'Describe' block such that they are
    # acccessible to all the 'It' blocks inside that 'Describe' block, as each 'It' block runs in
    # its own scope. The only options are global/script variables or duplicating them inside each
    # 'it' block.
    # We therefore use a work-around where:
    #   1. we define an instance of a hash-table containing all the required variables.
    #   2. We then use the '-TestCases' clause to pass a single instance of this hash-table to an
    #      'It' block.
    #
    # The 'It' block is executed once for each hash-table instance in the array passed to
    # '-TestCases' clause. This allows us to pass the required variables to the 'It' block while
    # ensuring that each 'It' block is executed only once.

    $TestVariables = @{
        ProgramName = '.\test_sample_ebpf.sys';
        ProgramPinPath = "\ebpf\samples\test_sample_ebpf";
        TestApp = ".\test_sample_ebpf.exe";
        TestAppArgs = "utility_helpers_test_native"
    }

    It "Check if ebpfcore.sys is installed and running" {

        "Checking ebpfcore.sys status..." | Out-Host
        $service = Get-Service -Name ebpfcore
        if ($service -eq $null) {
            "ebpfcore.sys is not installed." | Out-Host
        }
        $service | Should -Not -Be $null

        $service = Get-Service -Name ebpfcore
        if ($service.Status -ne "Running") {
            "ebpfcore.sys not running" | Out-Host
        }
        $service.Status | Should -Be "Running"
        "ebpfcore.sys installed and running." | Out-Host
        $Message | Out-Host
    }

    it "Add and pin eBPF program" -TestCases @($TestVariables) {
        param(
            [string] $ProgramName,
            [string] $ProgramPinPath,
            [string] $TestApp,
            [string] $TestAppArgs
        )

        # load and pin the native program
        "Adding and pinning eBPF program. Program:$ProgramName, PinPath:$ProgramPinPath" | Out-Host
        Add-eBPFProgram -ProgramName $ProgramName -PinPath $ProgramPinPath

        # Check if the program was pinned successfully
        "Checking if $ProgramName is pinned at $ProgramPinPath..." | Out-Host
        $NetshArgs = " ebpf show pins"
        $Result = Start-Process -FilePath 'netsh' -ArgumentList $NetshArgs -Wait -PassThru
        if ($Result.ExitCode -ne 0) {
            "*** FATAL ERROR *** Failed to show pins" | Out-Host
        }
        $Result.ExitCode | Should -Be 0
        $Result.StandardOutput | Out-Host
        if ($Result.StandardOutput -notcontains $PinPath) {
            "*** FATAL ERROR *** $ProgramName not pinned at $PinPath" | Out-Host
        }
        $Result.StandardOutput | Should -Contain $PinPath
        "$ProgramName successfully pinned at $ProgramPinPath" | Out-Host
    }

    It "Stop and restart ebpfcore.sys" {

        $MaxRetries = 5
        $RetryIntervalSeconds = 5
        $EbpfService = "EbpfCore"

        # stop ebpfcore.sys  and check if it has stopped
        foreach($CurRetry in 1..$MaxRetries) {
            "Stopping $EbpfService.sys (Attempt $CurRetry/$MaxRetries)..." | Out-Host
            Stop-Service -Name $EbpfService
            # delay for a bit and get the service status
            Start-Sleep -Seconds $RetryIntervalSeconds
            $Service = Get-Service -Name $EbpfService
            if ($Service.Status -eq "Stopped") {
                break
            }
            "$EbpfCore.sys still running. Retrying in $RetryIntervalSeconds..." | Out-Host
            Start-Sleep -Seconds $RetryIntervalSeconds
        }
        if ($Service.Status -ne "Stopped") {
            "*** FATAL ERROR *** Unable to stop $EbpfCore.sys" | Out-Host
        }
        $Service.Status | Should -Be "Stopped"
        "ebpfcore.sys successfully stopped." | Out-Host

        # restart ebpfcore.sys and ensure it is running
        foreach($CurRetry in 0..$MaxRetries) {
            "Re-starting $EbpfCore.sys (Attempt $CurRetry/$MaxRetries)..." | Out-Host
            Start-Service -Name $EbpfCore
            $Service = Get-Service -Name ebpfcore
            if ($Service.Status -eq "Running") {
                break
            }
            "$EbpfCore.sys not running. Retrying in $RetryIntervalSeconds..." | Out-Host
            Start-Sleep -Seconds 5
        }
        if ($Service.Status -ne "Running") {
            "*** FATAL ERROR *** Unable to start $EbpfCore.sys" | Out-Host
        }
        $Service.Status | Should -Be "Running"
    }
}