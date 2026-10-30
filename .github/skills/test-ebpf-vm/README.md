# Using the Local VM Testing Skill

The [test-ebpf-vm skill](SKILL.md) guides Copilot through private eBPF deployment,
selected driver tests, DuoNIC setup when needed, and ETW-assisted investigation
on a local Hyper-V test VM. It is an agent workflow, not a standalone test runner.

**Driver tests run only inside the selected test VM, never on the development
machine.** Builds, source edits, host-safe unit tests, and offline log analysis
may run on the development machine.

## Prerequisites

- Start Copilot CLI elevated from the repository containing this skill.
- Have access to a local Hyper-V test VM and guest administrator credentials.
- For deployment, provide a matching build-output directory, such as `x64\Release`.
  The VM must already have the eBPF services installed:
  `scripts\Use-PrivateEbpfStack.ps1` replaces an installed stack, not a fresh installation.
- Be ready to choose between the VM's current state and a specific checkpoint.
  Restoring a checkpoint discards subsequent guest changes.

## Load the Skill

In the interactive Copilot CLI session:

```text
/skills reload
/skills info test-ebpf-vm
```

Confirm that the reported location is this repository's
`.github\skills\test-ebpf-vm\SKILL.md`. No plugin installation or commit is needed.
If the commands are unavailable in your CLI version, start a new session in the
repository and check `/skills`.

Invoke it by name in a prompt, for example: `Use the /test-ebpf-vm skill ...`.
The examples below are prompts to submit, not commands to run automatically.
Replace `vpn_server` and the example paths/checkpoint name with your own values.

## Supply Credentials Securely

In a separate interactive PowerShell window, under the same Windows account
that runs Copilot:

```powershell
Get-Credential | Export-Clixml -LiteralPath "$env:LOCALAPPDATA\ebpf-vm-credential.xml"
```

Enter the guest administrator credentials in the secure prompt. Then tell Copilot
to use the credential file at `%LOCALAPPDATA%\ebpf-vm-credential.xml`; it should
expand that environment variable when resolving the path.

On Windows, the password is protected with DPAPI and can be decrypted only by the
same Windows account on the same machine. Keep the file outside the repository,
restrict access to its owner, and do not display or paste its contents into chat.
An existing local credential-store reference can be used instead.

## Example Requests

### Start Small: One Test, Existing Deployment

```text
Use the /test-ebpf-vm skill to run only the API test perf_buffer_cpu_target
on vpn_server using its existing deployment. Ask whether to restore a
checkpoint or use the current VM state. Use the credential file at
%LOCALAPPDATA%\ebpf-vm-credential.xml. Do not rebuild, redeploy, or modify code.
```

If you choose a checkpoint, the agent must recheck the restored deployment before
testing; it must not assume the previous deployment survived the restore.

### Run the Default API Suite Without Aborting on Failure

```text
Use the /test-ebpf-vm skill on vpn_server. Use its current state and existing
deployment. Run api_test.exe -d yes without -a, so tests continue after failures.
Use the credential file at %LOCALAPPDATA%\ebpf-vm-credential.xml.
Report all failures and log paths. Do not modify code or run other suites.
```

The executable is `api_test.exe`, not `api_tests.exe`. The default suite does not
necessarily include hidden tests; request those explicitly if needed.

### Deploy Release Artifacts and Run Socket Tests

```text
Use the /test-ebpf-vm skill to deploy x64\Release to vpn_server with
scripts\Use-PrivateEbpfStack.ps1, then run only socket_tests.exe -d yes.
Copy the test dependencies, fixtures, and all sample .o, .sys, and .dll files.
Check whether DuoNIC is required; download and install it inside the VM if needed.
Use the credential file at %LOCALAPPDATA%\ebpf-vm-credential.xml.
Ask whether to restore a checkpoint first. Ask before any reboot or signing change.
Do not modify source code.
```

The agent should reuse a healthy DuoNIC installation. It must not install DuoNIC
or alter test network adapters on the development machine.

### Restore a Named Checkpoint Before Deployment

```text
Use the /test-ebpf-vm skill on vpn_server. Restore the checkpoint named
"clean-ebpf-baseline" before starting; I approve discarding subsequent VM changes.
Then deploy x64\Release and run only the API suite without abort-on-failure.
Use the credential file at %LOCALAPPDATA%\ebpf-vm-credential.xml.
Do not modify source code. Ask before any additional restart.
```

If you choose "Restore checkpoint" without naming one, the agent must list the
selected VM's checkpoints with names, creation times, and IDs, then ask
**"Which checkpoint should I restore?"** and wait for your answer. This is required
even if there is only one checkpoint; the agent must not choose one automatically.
If you cancel checkpoint selection, the workflow stops rather than using the
current state without approval.

When you already supply a checkpoint name as above, the agent must verify it
uniquely identifies a checkpoint on that VM. It must recheck guest access,
services, signing settings, and DuoNIC after restoring.

### Collect ETW for a Failing Test Without Fixing Code

```text
Use the /test-ebpf-vm skill to investigate perf_buffer_sync_callback_block
on vpn_server using its current state and existing deployment.
Use the credential file at %LOCALAPPDATA%\ebpf-vm-credential.xml.
Reproduce only that API test with ETW enabled. Collect the test output, ETL,
decoded events, and matching symbols. Report evidence and likely causes.
Do not modify code, redeploy, or cancel an existing tracing session.
```

### Fix and Retest a Feature

```text
Use the /test-ebpf-vm skill to validate my current feature on vpn_server.
Ask whether to use its current state or restore a checkpoint.
Use the credential file at %LOCALAPPDATA%\ebpf-vm-credential.xml.
Build Release, deploy matching binaries, and run only API and socket tests.
Investigate failures with ETW as needed, fix confirmed product bugs locally,
run relevant unit tests locally, rebuild, and rerun affected tests on the VM.
Finish with both requested suites. Stop after three fix/retest iterations
and report any remaining blockers. Ask before restarting or changing signing.
```

## Expected Behavior and Results

The agent should ask for missing VM details, credential references, test scope,
and starting-state choices rather than guess. It should verify the selected VM
session before every driver-test launch and stop if it cannot establish that
execution will occur inside the guest.

Results should identify the Hyper-V VM and guest computer, build/deployment paths,
exact test commands and exit codes, pass/fail counts, incomplete coverage, and
guest/local diagnostic locations. Failures must not be hidden with unrequested
exclusions. Missing fixtures, failed DuoNIC setup, and tracing failures should be
reported distinctly from product bugs.

For a quick check of input collection, request a test without supplying a VM name
or starting-state choice. The agent should ask for them before changing a guest.
For a VM-access failure, it should report a blocker, never run the test locally.

The guardrail is an instruction to the agent, not an operating-system execution
restriction. Review the reported execution host and command boundaries when
validating the workflow.
