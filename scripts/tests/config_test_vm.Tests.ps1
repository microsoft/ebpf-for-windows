# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

$scriptsDirectory = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $scriptsDirectory 'config_test_vm.psm1') `
    -ArgumentList $scriptsDirectory, 'vm-reboot-tests.log' -Force -ErrorAction Stop

InModuleScope config_test_vm {
    Describe 'VM reboot synchronization' {
        BeforeEach {
            $script:commandCount = 0
            $script:testCredential = New-Object PSCredential (
                'Administrator', (ConvertTo-SecureString 'test-password' -AsPlainText -Force))
            Mock Write-Log {}
            Mock Start-Sleep {}
            Mock Get-VMCredential { $script:testCredential }
        }

        It 'does not accept a responsive old boot as ready' {
            Mock Invoke-CommandOnVM {
                $script:commandCount++
                if ($script:commandCount -lt 3) { return [long]100 }
                return [long]101
            }

            Wait-AllVMsReadyForCommands -VMList @(@{ Name = 'runner_vm' }) `
                -TestCredential $script:testCredential -PreviousBootTimes @{ runner_vm = [long]100 }

            Assert-MockCalled Invoke-CommandOnVM -Times 3 -Exactly -Scope It
            Assert-MockCalled Start-Sleep -Times 2 -Exactly -Scope It
        }

        It 'preserves ordinary readiness checks when no reboot is expected' {
            Mock Invoke-CommandOnVM { $true }

            Wait-AllVMsReadyForCommands -VMList @(@{ Name = 'runner_vm' }) `
                -TestCredential $script:testCredential

            Assert-MockCalled Invoke-CommandOnVM -Times 1 -Exactly -Scope It
            Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
        }

        It 'retries transient PowerShell Direct failures during reboot' {
            Mock Invoke-CommandOnVM {
                $script:commandCount++
                if ($script:commandCount -eq 1) { throw 'The credential is invalid.' }
                return [long]101
            }

            Wait-AllVMsReadyForCommands -VMList @(@{ Name = 'runner_vm' }) `
                -TestCredential $script:testCredential -PreviousBootTimes @{ runner_vm = [long]100 }

            Assert-MockCalled Invoke-CommandOnVM -Times 2 -Exactly -Scope It
        }

        It 'surfaces unexpected boot-query errors rather than accepting readiness' {
            Mock Invoke-CommandOnVM { throw 'Boot query access denied.' }

            {
                Wait-AllVMsReadyForCommands -VMList @(@{ Name = 'runner_vm' }) `
                    -TestCredential $script:testCredential -PreviousBootTimes @{ runner_vm = [long]100 }
            } | Should Throw 'Boot query access denied.'

            Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
        }

        It 'retries transient WinRM transport failures during remote reboot' {
            Mock Invoke-CommandOnVM {
                $script:commandCount++
                if ($script:commandCount -eq 1) {
                    throw (New-Object System.Management.Automation.Remoting.PSRemotingTransportException)
                }
                return [long]101
            }

            Wait-AllVMsReadyForCommands -VMList @(@{ Name = 'remote_vm' }) `
                -TestCredential $script:testCredential -VMIsRemote $true `
                -PreviousBootTimes @{ remote_vm = [long]100 }

            Assert-MockCalled Invoke-CommandOnVM -Times 2 -Exactly -Scope It
        }

        It 'rejects an empty boot-query result' {
            Mock Invoke-CommandOnVM {}

            {
                Wait-AllVMsReadyForCommands -VMList @(@{ Name = 'runner_vm' }) `
                    -TestCredential $script:testCredential -PreviousBootTimes @{ runner_vm = [long]100 }
            } | Should Throw 'Could not read the boot time'
        }

        It 'passes the pre-restart boot time to local initialization without a fixed sleep' {
            Mock Invoke-CommandOnVM {
                $script:commandCount++
                if ($script:commandCount -eq 1) { return [long]100 }
            }
            Mock Wait-AllVMsToInitialize {}

            Restart-VMAndWait -VmName 'runner_vm'

            Assert-MockCalled Invoke-CommandOnVM -Times 2 -Exactly -Scope It
            Assert-MockCalled Wait-AllVMsToInitialize -Times 1 -Exactly -Scope It `
                -ParameterFilter { $PreviousBootTimes['runner_vm'] -eq [long]100 }
            Assert-MockCalled Start-Sleep -Times 0 -Exactly -Scope It
        }

        It 'passes the pre-restart boot time to remote readiness' {
            Mock Invoke-CommandOnVM {
                $script:commandCount++
                if ($script:commandCount -eq 1) { return [long]100 }
            }
            Mock Wait-AllVMsReadyForCommands {}

            Restart-VMAndWait -VmName 'remote_vm' -VMIsRemote $true

            Assert-MockCalled Wait-AllVMsReadyForCommands -Times 1 -Exactly -Scope It `
                -ParameterFilter { $VMIsRemote -and $PreviousBootTimes['remote_vm'] -eq [long]100 }
        }

        It 'does not request a restart when the original boot time cannot be read' {
            Mock Invoke-CommandOnVM {}
            Mock Wait-AllVMsToInitialize {}

            { Restart-VMAndWait -VmName 'runner_vm' } |
                Should Throw 'Could not read the boot time'

            Assert-MockCalled Invoke-CommandOnVM -Times 1 -Exactly -Scope It
            Assert-MockCalled Wait-AllVMsToInitialize -Times 0 -Exactly -Scope It
        }
    }
}
