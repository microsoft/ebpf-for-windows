// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <synchapi.h>
#include <winnt.h>

#if defined(__cplusplus)
extern "C"
{
#endif

// Defines
#define EX_DEFAULT_PUSH_LOCK_FLAGS 0
#define ExAcquirePushLockExclusive(Lock) ExAcquirePushLockExclusiveEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExAcquirePushLockShared(Lock) ExAcquirePushLockSharedEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExReleasePushLockExclusive(Lock) ExReleasePushLockExclusiveEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExReleasePushLockShared(Lock) ExReleasePushLockSharedEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExAcquireSpinLockExclusive(Lock) ExAcquireSpinLockExclusiveEx(Lock)
#define ExAcquireSpinLockShared(Lock) ExAcquireSpinLockSharedEx(Lock)
#define ExAcquireSpinLockExclusiveAtDpcLevel(Lock) ExAcquireSpinLockExclusiveAtDpcLevelEx(Lock)
#define ExReleaseSpinLockExclusive(Lock, Irql) ExReleaseSpinLockExclusiveEx(Lock, Irql)
#define ExReleaseSpinLockShared(Lock, Irql) ExReleaseSpinLockSharedEx(Lock, Irql)
#define ExReleaseSpinLockExclusiveFromDpcLevel(Lock) ExReleaseSpinLockExclusiveFromDpcLevelEx(Lock)
#define KdPrintEx(_x_) DbgPrintEx _x_
#define KeAcquireSpinLock(spin_lock, OldIrql) *(OldIrql) = KeAcquireSpinLockRaiseToDpc(spin_lock)
#define KeQueryInterruptTime QueryInterruptTimeEx
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define PAGED_CODE()

#define STATUS_SUCCESS 0
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2

    // Typedefs

    typedef struct _SE_EXPORTS
    {
        // Privilege values
        LUID SeCreateTokenPrivilege;
        LUID SeAssignPrimaryTokenPrivilege;
        LUID SeLockMemoryPrivilege;
        LUID SeIncreaseQuotaPrivilege;
        LUID SeUnsolicitedInputPrivilege;
        LUID SeTcbPrivilege;
        LUID SeSecurityPrivilege;
        LUID SeTakeOwnershipPrivilege;
        LUID SeLoadDriverPrivilege;
        LUID SeCreatePagefilePrivilege;
        LUID SeIncreaseBasePriorityPrivilege;
        LUID SeSystemProfilePrivilege;
        LUID SeSystemtimePrivilege;
        LUID SeProfileSingleProcessPrivilege;
        LUID SeCreatePermanentPrivilege;
        LUID SeBackupPrivilege;
        LUID SeRestorePrivilege;
        LUID SeShutdownPrivilege;
        LUID SeDebugPrivilege;
        LUID SeAuditPrivilege;
        LUID SeSystemEnvironmentPrivilege;
        LUID SeChangeNotifyPrivilege;
        LUID SeRemoteShutdownPrivilege;

        // Universally defined Sids
        PSID SeNullSid;
        PSID SeWorldSid;
        PSID SeLocalSid;
        PSID SeCreatorOwnerSid;
        PSID SeCreatorGroupSid;

        // Nt defined Sids
        PSID SeNtAuthoritySid;
        PSID SeDialupSid;
        PSID SeNetworkSid;
        PSID SeBatchSid;
        PSID SeInteractiveSid;
        PSID SeLocalSystemSid;
        PSID SeAliasAdminsSid;
        PSID SeAliasUsersSid;
        PSID SeAliasGuestsSid;
        PSID SeAliasPowerUsersSid;
        PSID SeAliasAccountOpsSid;
        PSID SeAliasSystemOpsSid;
        PSID SeAliasPrintOpsSid;
        PSID SeAliasBackupOpsSid;

        // New Sids defined for NT5
        PSID SeAuthenticatedUsersSid;

        PSID SeRestrictedSid;
        PSID SeAnonymousLogonSid;

        // New Privileges defined for NT5
        LUID SeUndockPrivilege;
        LUID SeSyncAgentPrivilege;
        LUID SeEnableDelegationPrivilege;

        // New Sids defined for post-Windows 2000
        PSID SeLocalServiceSid;
        PSID SeNetworkServiceSid;

        // New Privileges defined for post-Windows 2000
        LUID SeManageVolumePrivilege;
        LUID SeImpersonatePrivilege;
        LUID SeCreateGlobalPrivilege;

        // New Privileges defined for post Windows Server 2003
        LUID SeTrustedCredManAccessPrivilege;
        LUID SeRelabelPrivilege;
        LUID SeIncreaseWorkingSetPrivilege;

        LUID SeTimeZonePrivilege;
        LUID SeCreateSymbolicLinkPrivilege;

        // New Sids defined for post Windows Server 2003
        PSID SeIUserSid;

        // Mandatory Sids, ordered lowest to highest.
        PSID SeUntrustedMandatorySid;
        PSID SeLowMandatorySid;
        PSID SeMediumMandatorySid;
        PSID SeHighMandatorySid;
        PSID SeSystemMandatorySid;

        PSID SeOwnerRightsSid;

        // Package/Capability Sids.
        PSID SeAllAppPackagesSid;
        PSID SeUserModeDriversSid;

        // Process Trust Sids.
        PSID SeProcTrustWinTcbSid;

        // Trusted Installer SID.
        PSID SeTrustedInstallerSid;

        // New Privileges defined for Windows 10
        LUID SeDelegateSessionUserImpersonatePrivilege;

        // App Silo SID
        PSID SeAppSiloSid;

        // App Silo Volume Root Minimal Capability SID
        PSID SeAppSiloVolumeRootMinimalCapabilitySid;

        // App Silo Users Minimal Capability SID
        PSID SeAppSiloProfilesRootMinimalCapabilitySid;
    } SE_EXPORTS, *PSE_EXPORTS;

    extern PSE_EXPORTS SeExports;

    typedef CCHAR KPROCESSOR_MODE;

    typedef enum _MODE
    {
        KernelMode,
        UserMode,
        MaximumMode
    } MODE;

    typedef struct _DEVICE_OBJECT DEVICE_OBJECT;

    typedef struct _DRIVER_OBJECT DRIVER_OBJECT;

    typedef struct _EX_PUSH_LOCK
    {
        SRWLOCK lock;
    } EX_PUSH_LOCK;
    typedef struct _EX_SPIN_LOCK
    {
        SRWLOCK lock;
    } EX_SPIN_LOCK;
    typedef struct _EX_RUNDOWN_REF
    {
        void* reserved;
    } EX_RUNDOWN_REF;
    typedef struct _IO_WORKITEM IO_WORKITEM, *PIO_WORKITEM;
    typedef void
    IO_WORKITEM_ROUTINE(_In_ DEVICE_OBJECT* device_object, _In_opt_ void* context);

    //
    // Pool Allocation routines (in pool.c)
    //
    typedef _Enum_is_bitflag_ enum _POOL_TYPE {
        NonPagedPool,
        NonPagedPoolExecute = NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed = NonPagedPool + 2,
        DontUseThisType,
        NonPagedPoolCacheAligned = NonPagedPool + 4,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
        MaxPoolType,

        //
        // Define base types for NonPaged (versus Paged) pool, for use in cracking
        // the underlying pool type.
        //

        NonPagedPoolBase = 0,
        NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
        NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
        NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,

        //
        // Note these per session types are carefully chosen so that the appropriate
        // masking still applies as well as MaxPoolType above.
        //

        NonPagedPoolSession = 32,
        PagedPoolSession = NonPagedPoolSession + 1,
        NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
        DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
        NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
        PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
        NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,

        NonPagedPoolNx = 512,
        NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
        NonPagedPoolSessionNx = NonPagedPoolNx + 32,

    } _Enum_is_bitflag_ POOL_TYPE;

    typedef _Enum_is_bitflag_ enum _WORK_QUEUE_TYPE {
        CriticalWorkQueue,
        DelayedWorkQueue,
        HyperCriticalWorkQueue,
        NormalWorkQueue,
        BackgroundWorkQueue,
        RealTimeWorkQueue,
        SuperCriticalWorkQueue,
        MaximumWorkQueue,
        CustomPriorityWorkQueue = 32
    } WORK_QUEUE_TYPE;

    typedef uint8_t KIRQL;

    typedef KIRQL* PKIRQL;

    typedef struct _MDL
    {
        struct _MDL* next;
        size_t size;
        uint64_t flags;
        void* start_va;
        unsigned long byte_offset;
        unsigned long byte_count;
    } MDL, *PMDL;

    typedef struct _IRP IRP;

    typedef enum _MM_PAGE_PRIORITY
    {
        LowPagePriority,
        NormalPagePriority = 16,
        HighPagePriority = 32
    } MM_PAGE_PRIORITY;

    // Functions

    unsigned long __cdecl DbgPrintEx(
        _In_ unsigned long component_id, _In_ unsigned long level, _In_z_ _Printf_format_string_ PCSTR format, ...);

    void
    ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* rundown_ref);

    void
    ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* rundown_ref);

    BOOLEAN
    ExAcquireRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref);

    void
    ExReleaseRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref);

    _Acquires_exclusive_lock_(push_lock->lock) void ExAcquirePushLockExclusiveEx(
        _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
        _In_ unsigned long flags);

    _Acquires_shared_lock_(push_lock->lock) void ExAcquirePushLockSharedEx(
        _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
        _In_ unsigned long flags);

    _Releases_exclusive_lock_(push_lock->lock) void ExReleasePushLockExclusiveEx(
        _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
        _In_ unsigned long flags);

    _Releases_shared_lock_(push_lock->lock) void ExReleasePushLockSharedEx(
        _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
        _In_ unsigned long flags);

    _Acquires_exclusive_lock_(spin_lock->lock) KIRQL
        ExAcquireSpinLockExclusiveEx(_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
                                         EX_SPIN_LOCK* spin_lock);

    _Acquires_exclusive_lock_(spin_lock->lock) void ExAcquireSpinLockExclusiveAtDpcLevelEx(
        _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock);

    _Acquires_shared_lock_(spin_lock->lock) KIRQL
        ExAcquireSpinLockSharedEx(_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
                                      EX_SPIN_LOCK* spin_lock);

    _Releases_exclusive_lock_(spin_lock->lock) void ExReleaseSpinLockExclusiveEx(
        _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock, KIRQL old_irql);

    _Releases_shared_lock_(spin_lock->lock) void ExReleaseSpinLockSharedEx(
        _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock, KIRQL old_irql);

    _Releases_exclusive_lock_(spin_lock->lock) void ExReleaseSpinLockExclusiveFromDpcLevelEx(
        _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock);

    void*
    ExAllocatePoolUninitialized(_In_ POOL_TYPE pool_type, _In_ size_t number_of_bytes, _In_ unsigned long tag);

    ULONGLONG
    QueryInterruptTimeEx();

    void
    ExFreePool(void* p);

    void
    ExInitializePushLock(_Out_ EX_PUSH_LOCK* push_lock);

    void
    FatalListEntryError(_In_ void* p1, _In_ void* p2, _In_ void* p3);

    MDL*
    IoAllocateMdl(
        _In_opt_ __drv_aliasesMem void* virtual_address,
        _In_ unsigned long length,
        _In_ BOOLEAN secondary_buffer,
        _In_ BOOLEAN charge_quota,
        _Inout_opt_ IRP* irp);

    PIO_WORKITEM
    IoAllocateWorkItem(_In_ DEVICE_OBJECT* device_object);

    void
    IoQueueWorkItem(
        _Inout_ __drv_aliasesMem IO_WORKITEM* io_work_item,
        _In_ IO_WORKITEM_ROUTINE* worker_routine,
        _In_ WORK_QUEUE_TYPE queue_type,
        _In_opt_ __drv_aliasesMem void* context);

    void
    IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM io_work_item);

    void
    IoFreeMdl(MDL* mdl);

    void
    KeEnterCriticalRegion(void);

    void
    KeLeaveCriticalRegion(void);

    void
    KeInitializeSpinLock(_Out_ PKSPIN_LOCK spin_lock);

    _Requires_lock_not_held_(*spin_lock) _Acquires_lock_(*spin_lock) _IRQL_requires_max_(DISPATCH_LEVEL) KIRQL
        KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK spin_lock);

    _Requires_lock_held_(*spin_lock) _Releases_lock_(*spin_lock) _IRQL_requires_(DISPATCH_LEVEL) void KeReleaseSpinLock(
        _Inout_ PKSPIN_LOCK spin_lock, _In_ _IRQL_restores_ KIRQL new_irql);

    void
    MmBuildMdlForNonPagedPool(_Inout_ MDL* memory_descriptor_list);

    unsigned long
    MmGetMdlByteCount(_In_ MDL* mdl);

    void*
    MmGetSystemAddressForMdlSafe(
        _Inout_ MDL* mdl,
        _In_ unsigned long page_priority // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
    );

    NTSTATUS
    RtlULongAdd(
        _In_ unsigned long augend,
        _In_ unsigned long addend,
        _Out_ _Deref_out_range_(==, augend + addend) unsigned long* result);

    // Inline functions
    _Must_inspect_result_ BOOLEAN CFORCEINLINE
    IsListEmpty(_In_ const LIST_ENTRY* list_head)
    {
        return (BOOLEAN)(list_head->Flink == list_head);
    }

    FORCEINLINE
    void
    InsertTailList(_Inout_ LIST_ENTRY* list_head, _Out_ __drv_aliasesMem LIST_ENTRY* entry)
    {
        LIST_ENTRY* PrevEntry;
        PrevEntry = list_head->Blink;
        if (PrevEntry->Flink != list_head) {
            FatalListEntryError((void*)PrevEntry, (void*)list_head, (void*)PrevEntry->Flink);
        }

        entry->Flink = list_head;
        entry->Blink = PrevEntry;
        PrevEntry->Flink = entry;
        list_head->Blink = entry;
        return;
    }

    FORCEINLINE
    void
    InsertHeadList(_Inout_ LIST_ENTRY* list_head, _Out_ __drv_aliasesMem LIST_ENTRY* entry)
    {
        LIST_ENTRY* NextEntry;
        NextEntry = list_head->Flink;
        if (NextEntry->Blink != list_head) {
            FatalListEntryError((void*)NextEntry, (void*)list_head, (void*)NextEntry->Blink);
        }

        entry->Flink = NextEntry;
        entry->Blink = list_head;
        NextEntry->Blink = entry;
        list_head->Flink = entry;
        return;
    }

    FORCEINLINE
    BOOLEAN
    RemoveEntryList(_In_ LIST_ENTRY* entry)
    {
        LIST_ENTRY* PrevEntry;
        LIST_ENTRY* NextEntry;

        NextEntry = entry->Flink;
        PrevEntry = entry->Blink;
        if ((NextEntry->Blink != entry) || (PrevEntry->Flink != entry)) {
            FatalListEntryError((void*)PrevEntry, (void*)entry, (void*)NextEntry);
        }

        PrevEntry->Flink = NextEntry;
        NextEntry->Blink = PrevEntry;
        return (BOOLEAN)(PrevEntry == NextEntry);
    }

    FORCEINLINE
    void
    InitializeListHead(_Out_ LIST_ENTRY* list_head)
    {
        list_head->Flink = list_head->Blink = list_head;
        return;
    }

    FORCEINLINE
    LIST_ENTRY*
    RemoveHeadList(_Inout_ LIST_ENTRY* list_head)
    {
        LIST_ENTRY* entry;
        LIST_ENTRY* NextEntry;

        entry = list_head->Flink;

        NextEntry = entry->Flink;
        if ((entry->Blink != list_head) || (NextEntry->Blink != entry)) {
            FatalListEntryError((void*)list_head, (void*)entry, (void*)NextEntry);
        }

        list_head->Flink = NextEntry;
        NextEntry->Blink = list_head;

        return entry;
    }

    PGENERIC_MAPPING
    IoGetFileObjectGenericMapping();

    NTSTATUS
    RtlCreateAcl(_Out_ PACL Acl, ULONG AclLength, ULONG AclRevision);

    VOID
    RtlMapGenericMask(_Inout_ PACCESS_MASK AccessMask, _In_ const GENERIC_MAPPING* GenericMapping);

    ULONG
    RtlLengthSid(_In_ PSID Sid);

    NTSTATUS
    NTAPI
    RtlAddAccessAllowedAce(_Inout_ PACL Acl, _In_ ULONG AceRevision, _In_ ACCESS_MASK AccessMask, _In_ PSID Sid);

    BOOLEAN
    SeAccessCheckFromState(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PTOKEN_ACCESS_INFORMATION PrimaryTokenInformation,
        _In_opt_ PTOKEN_ACCESS_INFORMATION ClientTokenInformation,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ ACCESS_MASK PreviouslyGrantedAccess,
        _Outptr_opt_result_maybenull_ PPRIVILEGE_SET* Privileges,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_ KPROCESSOR_MODE AccessMode,
        _Out_ PACCESS_MASK GrantedAccess,
        _Out_ NTSTATUS* AccessStatus);

    NTSTATUS
    NTAPI
    RtlCreateSecurityDescriptor(_Out_ PSECURITY_DESCRIPTOR SecurityDescriptor, _In_ ULONG Revision);

    NTSTATUS
    NTAPI
    RtlSetDaclSecurityDescriptor(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ BOOLEAN DaclPresent,
        _In_opt_ PACL Dacl,
        _In_ BOOLEAN DaclDefaulted);

    KIRQL
    KeGetCurrentIrql();

    KIRQL
    KeRaiseIrqlToDpcLevel();

    VOID
    KeLowerIrql(_In_ KIRQL Irql);

    HANDLE
    PsGetCurrentProcessId();

    HANDLE
    PsGetCurrentThreadId();

#if defined(__cplusplus)
}
#endif
