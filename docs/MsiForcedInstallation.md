# MSI forced installation and restoration

## MSI behavior

For a new installation, if the registry search detects an existing eBPFCore service `ImagePath`,
the MSI stops unless `FORCE=1` is supplied.

With `FORCE=1` and an existing eBPFCore registration, the MSI:

1. Saves the current configuration and running state of eBPFCore, NetEbpfExt, and eBPFSvc.
2. Stops NetEbpfExt, eBPFSvc, and then eBPFCore.
3. Preserves the existing Windows binaries through backup hard links and replaces their canonical
   Windows paths with hard links to the new MSI binaries.
4. Saves the HKLM and installing user's HKCU eBPF stores, then replaces their metadata with the MSI's version.
5. Configures and starts the drivers, and configures and requests startup of eBPFSvc.

The MSI saves one original backup set for both failed-install recovery and final uninstall.
Uninstall and repair create additional, temporary recovery snapshots.

On final uninstall, the saved original service state, binary hard links, and HKLM store are used
to restore the machine-wide eBPF stack to its pre-MSI state. HKCU restoration is best effort by identity:
only the saved installing user restores their HKCU store. Another user or SYSTEM skips that restoration
with a warning, leaves the caller's HKCU unchanged, and retains the original HKCU backup. If no saved
HKCU identity exists, the caller's store is also left unchanged. Other restoration errors remain fatal.
The same ownership check gates HKCU backup, clear, and population during installation: a different user
does not change their HKCU store while another user's backup area is retained.

For an ordinary installation with no original store snapshot, uninstall uses
`export_program_info.exe --clear --hive HKLM` and, for the recorded installing user, `--hive HKCU`.
These commands remove the tool's known program, section, and global-helper entries, not the entire
eBPF registry tree. Unrelated extension metadata is retained, and each command modifies only its
selected hive. The existing `--clear` command without `--hive` continues to process both hives.
Temporary uninstall snapshots still allow rollback of this selective cleanup.

### One original backup, plus temporary maintenance undo

One original backup restores the pre-MSI stack after failed installation or final uninstall;
successful installation retains it. Temporary uninstall and repair snapshots recover the MSI stack
if maintenance fails, without replacing the originals. After `InstallFiles`, repair recreates missing
eBPFSvc registration and reconnects forced-install canonical links to the current payload; existing
registrations remain unchanged. Failed repair restores prior links and removes any service it created;
successful repair deletes only its temporary snapshots. Backup actions reject stale data, clean up
their own partial work, and register rollback only after success. Interrupted recovery requires
administrator investigation before retrying.

### Requirements and recovery details

Version changes require uninstalling first; in-place upgrades are disallowed. New installations reject
NetEbpfExt or eBPFSvc registrations without eBPFCore, even with `FORCE=1`; maintenance remains allowed.
Forced replacement requires six canonical binaries and an `INSTALLFOLDER` on the Windows volume with
NTFS hard-link support. It captures running states before stopping services and stages replacements
before changing canonical paths. Original file ACLs are restored; replacement files retain MSI ACLs.
Service restoration preserves dependencies and defaults an absent `ServiceSidType` to `none`.
Forced repair stops the stack before relinking and restarts previously running services; standard MSI
actions handle eBPFSvc stop/start. Binary rollback attempts every mapping even if one fails.
Success-only cleanup errors are logged without triggering rollback.

### Backup filenames

Machine metadata lives in native `%ProgramFiles%\ebpf-for-windows\MsiBackup`, regardless of
`INSTALLFOLDER`; HKCU metadata lives in `UserStore` beneath it. Store snapshots use
`ebpf-store-<scope>.json` and `.reg` (`hklm` or `hkcu`), with `.uninstall` inserted before the extension
for uninstall undo. Service snapshots use `ebpf-services.original.json` or
`ebpf-services.uninstall-rollback.json`, paired with `<service>.original.reg` or
`<service>.uninstall-rollback.reg`; repair uses `ebpf-repair.json` and `<service>.repair.reg`.
Registry exports exist only for keys that were present. Beside canonical Windows binaries,
`.ebpf-msi-backup` preserves originals, `.ebpf-msi-new` stages replacements, and `.ebpf-msi-repair`
holds repair undo links. Incomplete original binary backup sets are rejected.

### Backup directory protection

Machine backups inherit Program Files permissions: ordinary users can read but not modify them.
Only `UserStore` and its protected owner marker receive custom ACLs. The installing user can create,
modify, and delete backup files, but cannot rename, delete, or change permissions on `UserStore` itself
or create subdirectories. SYSTEM stages the owner marker, grants user access, then finalizes
`hkcu-owner.sid`. HKCU actions run as that user; other identities skip them without loading another
profile. Metadata access validates ownership, permissions, paths, and imports, rejecting reparse points
and hard-linked metadata files. Machine-directory checks stop below native Program Files and close
handles after validation; explicit `-StateRoot` overrides outside it retain full ancestor checks.
Only `UserStore` retains action-duration directory locking. Untrusted state requires investigation,
not deleting backups to bypass checks. A protected `ForceEbpfStack.cleanup.ps1` supports
uninstall commit after payload removal. HKCU cleanup stays impersonated; skipped backups remain,
and SYSTEM removes `UserStore` and its owner marker only when empty.

## 1. Install execution flow

This chart follows the successful **new-install** path, using the current compiled MSI's execution
order. It includes ordinary installation and forced stack replacement.
Action boxes contain only action names. An `R: <action>` line identifies rollback work newly registered
before that step in sequence order, since the previous executed step.


```mermaid
flowchart TD
    Prep["Immediate preparation"]
    Allowed{"Launch conditions pass?"}
    Reject["Launch-condition failure"]
    Prep --> Allowed
    Allowed -->|No| Reject

        Stop{"Forced stack replacement?"}
        StandardStop["StopServices"]
        Files["CreateFolders<br/>InstallFiles"]
        UserAccess["Prepare_eBPF_user_store"]
        Forced{"Existing eBPFCore and FORCE=1?"}
        Backup["Force_eBPF_services_backup"]
        NetStop["Force_NetEbpfExt_Driver_stop<br/>R: Force_eBPF_services_rollback"]
        SvcStop["Force_eBPFSvc_stop"]
        CoreStop["Force_eBPFCore_Driver_stop"]
        BinaryBackup["Force_eBPF_binaries_backup"]
        Links["Force_eBPF_binaries_hardlink<br/>R: Force_eBPF_binaries_restore"]
        MachineBackup["Force_eBPF_store_backup_HKLM"]
        UserBackup["Force_eBPF_store_backup_HKCU<br/>R: Force_eBPF_store_rollback_HKLM"]
        ClearMachine["Clear_eBPF_store_HKLM<br/>R: Force_eBPF_store_rollback_HKCU [forced replacement]"]
        SetupMachine["Setup_eBPF_store_HKLM"]
        ClearUser["Clear_eBPF_store_HKCU"]
        SetupUser["Setup_eBPF_store_HKCU"]
        NetshDelete["eBPF_netsh_helper_uninstall_rollback"]
        NetshAdd["eBPF_netsh_helper_install"]
        CoreExists{"eBPFCore existed before install?"}
        CoreCreate["eBPFCore_Driver_install<br/>R: eBPFCore_Driver_uninstall_rollback"]
        CoreConfigure["Force_eBPFCore_Driver_configure"]
        CoreStart["eBPFCore_Driver_start<br/>R: eBPFCore_Driver_stop_rollback"]
        NetExists{"NetEbpfExt existed before install?"}
        NetConfigure["Force_NetEbpfExt_Driver_configure"]
        NetForced{"Forced stack replacement?"}
        NetCreate["NetEbpfExt_Driver_install<br/>R: NetEbpfExt_Driver_uninstall_rollback"]
        NetForceCreate["Force_NetEbpfExt_Driver_install<br/>R: NetEbpfExt_Driver_uninstall_rollback"]
        NetStart["NetEbpfExt_Driver_start<br/>R: NetEbpfExt_Driver_stop_rollback"]
        Environment["WriteEnvironmentStrings"]
        SvcConfigure["Force_eBPFSvc_configure<br/>R: eBPFSvc_uninstall_rollback [eBPFSvc absent]<br/>R: Force_eBPFSvc_stop_rollback [forced stack replacement]"]
        SvcStart["StartServices"]
        Publish["RegisterUser<br/>RegisterProduct<br/>PublishFeatures<br/>PublishProduct"]
        NormalSuccess["Normal installation succeeded"]

        Stop -->|No| StandardStop --> Files
        Stop -->|Yes: standard StopServices skipped| Files
        Files --> UserAccess --> Forced
        Forced -->|Yes| Backup --> NetStop --> SvcStop --> CoreStop
        CoreStop --> BinaryBackup --> Links --> MachineBackup --> UserBackup --> ClearMachine
        Forced -->|No| ClearMachine
        ClearMachine --> SetupMachine --> ClearUser --> SetupUser
        SetupUser --> NetshDelete --> NetshAdd --> CoreExists
        CoreExists -->|No| CoreCreate --> CoreStart
        CoreExists -->|Yes: FORCE=1 required| CoreConfigure --> CoreStart
        CoreStart --> NetExists
        NetExists -->|Yes: FORCE=1 and core required| NetConfigure --> NetStart
        NetExists -->|No| NetForced
        NetForced -->|No| NetCreate --> NetStart
        NetForced -->|Yes| NetForceCreate --> NetStart
        NetStart --> Environment --> SvcConfigure --> SvcStart --> Publish --> NormalSuccess
    Allowed -->|Yes| Stop

    NormalSuccess --> Finished["InstallFinalize completes successfully"]
    Finished --> Done["Installation complete"]
```

If normal work reports a fatal error, MSI runs the rollback work accumulated so far, using the
original backups. No success-only install cleanup is needed: successful installation keeps those
backups for uninstall.

## 2. Uninstall execution only: when the work actually happens

This chart follows supported final removal (`REMOVE="ALL"` and `NOT UPGRADINGPRODUCTCODE`).
Rollback annotations use the same `R: <action>` convention as section 1.


```mermaid
flowchart TD
    Prep["Immediate preparation"]

        UserAccess["Prepare_eBPF_user_store_uninstall"]
        ServiceSnapshot["Force_eBPF_services_uninstall_prepare"]
        MachineSnapshot["Force_eBPF_store_uninstall_prepare_HKLM<br/>R: Force_eBPF_services_uninstall_rollback"]
        UserSnapshot["Force_eBPF_store_uninstall_prepare_HKCU<br/>R: Force_eBPF_store_uninstall_rollback_HKLM"]
        Netsh["eBPF_netsh_helper_uninstall<br/>R: Force_eBPF_store_uninstall_rollback_HKCU"]
        CoreStop["eBPFCore_Driver_stop"]
        NetStop["NetEbpfExt_Driver_stop"]
        ServiceRemove["Force_eBPF_services_uninstall_remove"]
        Components["ProcessComponents<br/>UnpublishFeatures"]
        StandardStop["StopServices"]
        Environment["RemoveEnvironmentStrings"]
        MachineRestore["Force_eBPF_store_restore_HKLM<br/>R: Force_eBPF_binaries_uninstall_rollback"]
        UserRestore["Force_eBPF_store_restore_HKCU"]
        BinaryRestore["Force_eBPF_binaries_uninstall_restore"]
        ServiceRestore["Force_eBPF_services_uninstall_restore<br/>R: Force_eBPF_services_uninstall_stop_rollback"]
        Files["RemoveFiles"]
        Folders["RemoveFolders"]
        NormalSuccess["Normal uninstall succeeded"]

        UserAccess --> ServiceSnapshot --> MachineSnapshot --> UserSnapshot --> Netsh
        Netsh --> NetStop --> CoreStop --> ServiceRemove --> Components
        Components --> StandardStop --> Environment --> MachineRestore
        MachineRestore --> UserRestore --> BinaryRestore --> ServiceRestore --> Files
        Files --> Folders --> NormalSuccess
    Prep --> UserAccess

    subgraph Commit["Success-only commit actions"]
        UserCleanup["Force_eBPF_store_uninstall_commit_HKCU"]
        ServiceCleanup["Force_eBPF_services_uninstall_commit"]
        Finished["InstallFinalize completes successfully"]
        UserCleanup --> ServiceCleanup --> Finished
    end

    NormalSuccess --> UserCleanup
    Finished --> Query["eBPFCore_Driver_uninstall_flush"]
    Query --> Done["Uninstall sequence finishes"]
```

If normal uninstall work reports a fatal error, MSI follows recovery rather than the success-only
cleanup path. Recovery is not expanded here; it restores the pre-uninstall state using the rollback work
accumulated so far.

The impersonated HKCU commit runs before the SYSTEM service/HKLM commit, only after normal removal
succeeds. It deletes restored original-state backups and temporary uninstall recovery files;
skipped HKCU backups remain.

## 3. Repair execution flow

Repair actions run only for an installed product with `REINSTALL` set and no `REMOVE` property.
The installed helper is available before repair preparation, even if it was initially missing.

```mermaid
flowchart TD
    Stop["StopServices"] --> Files["InstallFiles"]
    Files --> Prepare["Prepare_eBPF_repair"]
    Prepare --> Repair["Repair_eBPF_stack<br/>R: Rollback_eBPF_repair"]
    Repair --> Start["StartServices"]
    Start --> Publish["Standard MSI registration and publication"]
    Publish --> Commit["Commit_eBPF_repair<br/>Success only"]
    Commit --> Finish["InstallFinalize completes"]
```