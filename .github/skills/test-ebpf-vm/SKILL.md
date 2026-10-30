---
name: test-ebpf-vm
description: >
  Deploy private eBPF for Windows binaries to a local Hyper-V VM, copy tests and
  sample programs, provision DuoNIC when required, run selected driver tests,
  and investigate failures using ETW.
  Use when asked to test a feature on a VM, run API or socket tests on a VM,
  refresh a private VM deployment, or iterate on driver-test failures.
---

# Test eBPF for Windows on a Local VM

Use PowerShell Direct to deploy and test inside a user-selected Hyper-V guest.
Build and edit on the development machine; run driver tests only in the guest.
This skill provides a procedure using existing tools, not a standalone test runner.
See [usage examples and setup](README.md) for user-facing instructions.

## Execution Boundaries

**Mandatory guardrail: driver tests must execute only on the selected test VM,
never on the development machine.** This applies to full suites, individual
tests, smoke tests, reproductions, and diagnostic reruns.

- Before every driver-test launch, verify that the remoting session is open and
  bound to the selected Hyper-V VM ID, and record the guest identity from inside
  that session. Launch the test only inside that verified session.
- If the VM/session identity cannot be verified or the connection is unavailable,
  stop and report the blocker. Never substitute local execution, a localhost
  session, or a runner's host-execution mode.
- Treat an unclassified test as VM-only until its implementation or repository
  documentation establishes that it is a host-safe unit test.
- Never install, activate, stop, or replace the development machine's eBPF stack.
- Never install DuoNIC or reconfigure test network adapters on the development machine.
- Never run driver tests on the development machine, even if guest access fails.
  This includes `api_test.exe`, `socket_tests.exe`, `sample_ext_app.exe`, and kernel
  stress, network, and integration tests. A user-mode executable can still exercise drivers.
- Unit tests such as `unit_tests.exe`, `netebpfext_unit.exe`, and `bpf2c_tests.exe`
  may run locally. Consult `docs\AutomatedTests.md` when classification is unclear.
- Run all guest deployment, service, test, tracing, and boot-configuration commands
  inside `Invoke-Command -Session $session` or an equivalent verified VM session.
  There is no host fallback.
- Run only requested suites and filters. Do not silently add stress tests,
  fault injection, system-account tests, exclusions, or broader regression suites.
- Do not reset checkpoints, reboot, change signing policy, or deliberately crash
  the guest without the user's approval. Reuse an existing approval within its scope.
- Preserve unrelated host and guest files, services, tracing sessions, and source changes.

## Collect Inputs

Use values already supplied in the current task; ask for missing information together:

| Input | Handling |
|-------|----------|
| VM name | Require an explicit target; never select an arbitrary running VM. |
| Starting state | Ask whether to use the VM as-is or restore a checkpoint. Choosing restoration requires a separate checkpoint selection unless the user already specified one. |
| Credentials | Use a supplied credential reference or a secure local credential prompt. |
| Build output | Use the requested configuration and architecture; for the Release deployment workflow, default to `x64\Release`. |
| Deployment script | Prefer `scripts\Use-PrivateEbpfStack.ps1` if available; otherwise ask for its location. |
| Suites and filters | Map the request to actual executables and test names; ask if scope is unspecified. |
| Operation | Distinguish deploy-only, test an existing deployment, and investigate/fix/retest. |
| Restart policy | Establish whether test-signing changes, restarts, and checkpoints are permitted. |

Do not ask the user to paste a password into chat. Have the user provision a
`PSCredential` through a secure local PowerShell prompt or an existing credential
store. One option, run by the user outside the agent's noninteractive tool session:

```powershell
Get-Credential | Export-Clixml -LiteralPath "$env:LOCALAPPDATA\ebpf-vm-credential.xml"
```

On Windows, the exported credential uses DPAPI and must be imported under the
same Windows account on the same machine. Keep it outside the repository with
access restricted to its owner. Import it without displaying its contents.
Never put credentials in the skill, source files, command-line literals, manifests,
transcripts, reports, or memory. Reuse the credential reference during iteration.

## Existing Resources

- `scripts\Use-PrivateEbpfStack.ps1`, or the user's explicitly selected copy:
  replaces an existing installed eBPF stack and supports `Enable`, `Status`, and
  `Restore`. It is not a fresh installer. Read the actual script before using it.
- `scripts\vm_run_tests.psm1`: existing host/VM helpers. Read before reuse;
  never select its host-execution mode for driver tests.
- `scripts\run_driver_tests.psm1`: test execution, timeouts, tracing, and dump helpers.
  Its suite entry points may add tests or exclusions; inspect before invoking.
- `Get-CoreNetTools` in `scripts\common.psm1` and `Initialize-NetworkInterfaces`
  in `scripts\config_test_vm.psm1`: DuoNIC download and guest network setup.
  The latter also has a host mode; never use that mode.
- `scripts\tracing_utils.psm1` and `scripts\ebpfforwindows.wprp`: WPR tracing support.
  The tracing helper calls `wpr -cancel`; do not use it to cancel someone else's trace.
- `docs\AutomatedTests.md` and the tracing section in `docs\GettingStarted.md`.
- Use `build-ebpf` for builds and `debug-crash-dump` when analyzing crash dumps.

## 1. Preflight the Host and Guest

Check the current host process's administrator token before any Hyper-V or guest
operations, including test-only requests. Administrator group membership alone
is not sufficient; the CLI must be running elevated:

```powershell
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Copilot CLI is not running as administrator. Restart it from a terminal opened with Run as administrator."
}
Write-Output "Host administrator elevation check: passed."
```

If the check fails, explicitly tell the user: **"Copilot CLI is not running as
administrator. Restart it from a terminal opened with Run as administrator,
then retry this skill."** Stop the workflow; do not merely show a generic
Hyper-V permission error or continue with guest commands. If elevation cannot
be determined, report that blocker and stop rather than assume it is sufficient.
After the check passes, verify Hyper-V access. Guest administrator credentials
do not grant host elevation or Hyper-V permissions.
Before changing the guest, ask the user to choose its starting state:

- **Use current state:** proceed without restoring a checkpoint.
- **Restore checkpoint:** enter the required checkpoint-selection gate below.
  This choice alone does not identify a checkpoint or authorize an arbitrary restore.

### Required Checkpoint-Selection Gate

When the user chooses restoration, do not connect to the guest, deploy, or run
tests until checkpoint selection and restoration are resolved.

1. Enumerate checkpoints only for the selected VM and display their names,
   creation times, and IDs:

   ```powershell
   $checkpoints = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop)
   $checkpoints | Select-Object Name, CreationTime, Id
   ```

2. If the user has not already specified a particular checkpoint, use the
   interactive question tool (`ask_user` when available) to ask **"Which checkpoint
   should I restore?"** Present the actual available checkpoints as choices,
   labeled with name, creation time, and ID, and wait for an explicit answer.
   Ask even when only one checkpoint exists. Never pick the newest, first, or
   only checkpoint automatically, and never proceed using a preselected default
   without the user's response.

3. Validate that the selected checkpoint belongs to this VM and resolves to
   exactly one enumerated ID. If the user supplied a checkpoint name in the
   original request, verify it; ask for disambiguation if multiple entries match.
   A missing checkpoint or failed enumeration is a blocker, not permission to
   choose a replacement.

4. Explain that restoration discards subsequent guest changes and obtain approval
   for that specific checkpoint unless already explicitly approved. Restore only
   the selected checkpoint object/ID, never an unfiltered checkpoint collection.

If there are no checkpoints, report that and ask whether to use the current
state instead. If the user cancels or declines checkpoint selection, stop;
do not silently continue with the current state. Do not substitute checkpoint
creation for restoration. Record the starting-state choice and checkpoint name/ID
in the run results. Reuse that decision during the current fix/test loop; do not
restore again between iterations unless requested.

After any restoration, discard stale remoting sessions, start the VM if needed,
wait for PowerShell Direct readiness, and repeat guest preflight. Previously
installed binaries, credentials, signing settings, and DuoNIC may have changed.
Check the selected VM is running, then establish PowerShell Direct:

```powershell
$credential = Import-Clixml -LiteralPath $CredentialPath
$vm = Get-VM -Name $VMName -ErrorAction Stop
$session = New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
Invoke-Command -Session $session -ScriptBlock {
    hostname.exe
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, OSArchitecture, LastBootUpTime
    Get-Service -Name EbpfCore, NetEbpfExt, eBPFSvc -ErrorAction Stop
    Get-PSDrive C
    bcdedit.exe /enum '{current}'
}
```

Record both the Hyper-V VM identity and the guest computer name; they may differ.
Check guest administrator privileges, architecture, free space, driver signatures,
and active private-stack state under
`C:\ProgramData\eBPF-for-Windows\PrivateStack\active.json`.
If inbox services are absent, stop and resolve installation prerequisites rather
than treating the private-stack script as an installer.

For test-signed drivers, check whether test-signing is enabled. If a change and
restart are needed, obtain approval, run `bcdedit.exe /set testsigning on` in the
guest, check its exit code, restart only the selected VM, reconnect, and verify
the new boot time and boot configuration. Do not disable Secure Boot automatically.

## 2. Prepare and Copy a Coherent Build

If a build is needed, use `build-ebpf` with the selected configuration and platform.
Do not rebuild when the user requested testing an existing deployment.

Create a unique run ID and separate guest directories, for example:

```text
C:\ebpf-private\<run-id>\Release
C:\ebpf-private\<run-id>\Results
C:\Program Files\eBPF-for-Windows-Private\<run-id>
```

Copy the deployment script and a consistent build snapshot using `Copy-Item
-ToSession`. Preserve relative paths. For the initial deployment, prefer the
complete build-output tree over an extension-only filter: tests also need fixtures,
configuration, and generated files. Include all test executables and dependencies,
all sample `.o`, `.sys`, and `.dll` files (including subdirectories), PDBs,
certificates/catalogs, exporters, and tracing profiles/provider metadata.
Avoid mixing configurations or replacing individual DLLs from another build.

Record configuration, architecture, commit and dirty-worktree state, source paths,
script hash, and a relative-path SHA-256 manifest. Verify the copied files in the
guest before activation. Do not claim a dirty build represents only the recorded commit.
Keep local packaging files outside the repository and clean up only files this run created.

For PowerShell 5.1 compatibility, assign a parsed JSON array directly:
`$manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json`.
Do not wrap that pipeline in `@(...)` and assume it was flattened.
Prefer script blocks and argument lists over nested native command strings;
use an encoded command when a separate PowerShell process needs complex quoting.

## 3. Provision DuoNIC When Required

Determine whether the selected tests require DuoNIC by reading their setup code
and the existing test-runner configuration. Do not assume every test needs it.
If required, inspect `Get-NetAdapter -IncludeHidden`, driver/device status, and
the existing DuoNIC adapter configuration inside the guest. Reuse a healthy
installation with the required pairs rather than reinstalling on every iteration.

The repository's download flow is `Get-CoreNetTools -Architecture $Architecture`
in `scripts\common.psm1`. It obtains the payload from
`https://github.com/microsoft/corenet-ci`, under `vm-setup\duonic` for x64 and
`vm-setup\duonic\arm64` for ARM64. Read the helper and downloaded `duonic.ps1`
before use. Run the download helper in a new, isolated tools-staging directory,
not the repository root or an existing deployment: it copies files into the current
directory and also downloads diagnostic tools. Downloading on the host is allowed;
installing or executing downloaded drivers there is not.

Copy the complete architecture-matched DuoNIC payload, including `duonic.ps1`,
INF, SYS, CAT, and other installer dependencies, into the guest run's tools
directory. If the guest has no network access, download on the host and use
`Copy-Item -ToSession`. Record the source URL/revision when available and SHA-256
hashes; the current helper downloads mutable `main`, not a pinned release.
Verify transfer hashes and applicable driver-signing prerequisites.

Follow `Initialize-NetworkInterfaces` for the expected setup. These commands
must run inside the guest session from the copied DuoNIC tools directory:

```powershell
.\duonic.ps1 -Install -NumNicPairs 2
if ($LASTEXITCODE -ne 0) {
    throw "DuoNIC installation failed with exit code $LASTEXITCODE."
}
Set-NetAdapterAdvancedProperty -Name 'duo?' -DisplayName Checksum -RegistryValue 0 -ErrorAction Stop
Get-NetAdapter -Name 'duo*' -IncludeHidden -ErrorAction Stop
```

The existing setup uses two pairs and disables checksum offload. Verify that the
selected tests expect this topology and that the expected adapters are present,
healthy, and correctly configured after installation. Check
`Get-NetAdapterAdvancedProperty` to confirm checksum configuration. Inspect test
requirements for any IP addresses, routes, or additional adapter settings; do not
invent them or change the VM's management adapter. Do not remove unrelated adapters
to make installation succeed. Obtain approval for a required restart, reconnect,
and verify readiness again. Report failed or incomplete provisioning as an
environment blocker instead of skipping tests or falling back to host execution.

## 4. Enable the Private Stack in the Guest

Check `Status` first. If another private deployment is active, preserve its state
and use `Restore` before enabling a different build. Follow the script's reboot
guidance and the agreed restart policy; never overwrite loaded driver binaries.
For test-only requests, verify and reuse the intended active deployment instead.

Execute the following shape only inside the guest session, using guest paths:

```powershell
& $DeploymentScript Enable `
    -ArtifactDirectory $GuestArtifacts `
    -PrivateDirectory $GuestPrivateDirectory `
    -DeveloperScenario `
    -TestApplicationDirectory $GuestTestDirectories `
    -Confirm:$false
& $DeploymentScript Status
```

Use `-DeveloperScenario` for suites needing the sample extension; ensure its
driver and exporter exist. Otherwise omit it. Pass every relevant test executable
directory to `-TestApplicationDirectory` so its app-local `EbpfApi.dll` matches.
The deployment script copies selected stack components, not the complete test tree;
the artifact transfer in step 2 is still required.

If an unsigned script is blocked, use a process-only execution-policy override in
the guest if permitted; never change machine-wide policy or bypass enforced policy.
Capture deployment output and backup paths. Verify service status and image paths,
sample-extension registration when requested, and runtime/test DLL hashes.
If activation fails, preserve diagnostics and use saved restore state as appropriate;
do not report successful deployment based solely on copied files.

## 5. Run Only the Selected Tests

| Requested suite | Guest executable |
|-----------------|------------------|
| API / api_tests | `api_test.exe` (singular) |
| Socket | `socket_tests.exe` |
| Sample extension | `sample_ext_app.exe` |
| Other driver suite | Resolve from `docs\AutomatedTests.md` and existing runner code. |

Run from the guest artifact directory so relative sample paths resolve. For Catch2
executables, inspect `--help` and `--list-tests` on the deployed binary. Validate
filters against that list; zero matches is a failed selection, not success.
Do not assume shell wildcard semantics: multiple interior `*` patterns may not
match as expected. Check quoting of names containing spaces, quotes, or commas.

Examples below are guest commands, never host commands:

```powershell
.\api_test.exe -d yes
.\socket_tests.exe -d yes
.\api_test.exe 'perf_buffer_sync_callback_block' -d yes
```

Default to continuing after test failures: do not add `-a` or `--abort` unless
requested. "All tests" means the executable's default suite unless hidden tests
are explicitly requested; report any hidden, skipped, or excluded cases.
Check suite-specific networking, privileges, external fixtures, and signing
requirements. Missing proof-of-verification signed fixtures must be reported,
not silently excluded or replaced with test-signed artifacts.

Capture stdout, stderr, exact arguments, start/end times, execution host, and
the executable's actual exit code. Save the exit code immediately, before other
native commands. Do not mistake successful remoting for successful tests or let
stderr handling abort the command before its results are collected.
Where supported, also produce a machine-readable test report without losing
console output. Use a bounded timeout (the existing runner uses 600 seconds for
API and 1800 for socket tests); on timeout, identify the exact guest process,
collect available diagnostics, and stop only its PID if appropriate.

Always save complete logs under the guest run's `Results` directory and copy them
back with `Copy-Item -FromSession` to a session-artifact directory, not source files.
If backgrounded, report running status honestly and await completion before claiming
a final result. For an abort, crash, or timeout, state that the full suite did not finish.

## 6. Investigate with ETW

For a test-only request, report failures; do not modify code without authorization.
For an investigation/fix request, distinguish deployment/environment/fixture issues
from product failures before editing. Inspect the failed assertion and relevant code.
Reproduce the smallest failing test or required sequence; preserve the original run.

When tracing is requested or needed, verify WPR availability and copy the matching
`scripts\ebpfforwindows.wprp` to the guest. Inspect `wpr.exe -status` first; do not
cancel or stop a pre-existing recording. These commands run inside the guest:

```powershell
wpr.exe -start "$GuestArtifacts\ebpfforwindows.wprp!EbpfForWindows-Networking-File" -filemode
# Check the start exit code, then reproduce only the selected test/sequence.
wpr.exe -stop "$GuestResults\repro.etl"
netsh.exe trace convert "$GuestResults\repro.etl" "$GuestResults\repro.csv" csv
```

Use `EbpfForWindowsProvider-File` when networking events are unnecessary. Stop the
recording in `finally` only if this run successfully started it. Check each native
exit code and that the ETL was produced; surface collection/decoding failures.
Preserve failed-run traces. For realtime `bpf_printk` or provider-specific tracing,
follow `docs\GettingStarted.md` with `tracelog.exe`, `tracefmt.exe`, matching GUID
files, and a unique session name; stop only that session afterward.

Collect ETL, decoded events, test logs, relevant event-log records, and exact-build
PDBs/provider metadata. Decode on the host if tools are missing in the guest;
offline analysis is allowed on the development machine, driver execution is not.
Correlate timestamps, process/thread IDs, error codes, and service/module identity.
Do not infer a root cause from a return code alone. Use `debug-crash-dump` for dumps;
do not deliberately crash the VM as a routine collection step.

## 7. Fix, Redeploy, and Report

When authorized to fix, make surgical source changes locally and run relevant local
unit tests. Use `build-ebpf` to rebuild affected components and dependencies, create
a new coherent deployment, restore/switch stacks safely, and rerun the failing tests
inside the VM. Then run the requested regression scope; ask before expanding it.
Preserve before/after results. Do not weaken assertions, hide failures, or retry
indefinitely; stop with evidence when blocked or when an agreed iteration limit is reached.

Close remoting sessions and stop tracing/processes owned by this run. Remove only
known temporary packaging/test artifacts, retaining logs, manifests, symbols, and
restore data. Leave the stack active unless restoration was requested or agreed,
and report the resulting state and how to restore using the supplied script.

The final report must include the VM and guest identity, deployed build and paths,
service status, exact test commands and exit codes, test/assertion counts, failures
and incomplete coverage, diagnostic locations, changes made, and remaining blockers.
Include DuoNIC provisioning/version and adapter state when relevant. Explicitly
distinguish guest driver tests from any local unit tests.
