// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <synchapi.h>
#include <winnt.h>

// Defines
#define EX_DEFAULT_PUSH_LOCK_FLAGS 0
#define ExAcquirePushLockExclusive(Lock) ExAcquirePushLockExclusiveEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExAcquirePushLockShared(Lock) ExAcquirePushLockSharedEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExReleasePushLockExclusive(Lock) ExReleasePushLockExclusiveEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExReleasePushLockShared(Lock) ExReleasePushLockSharedEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define KdPrintEx(_x_) DbgPrintEx _x_
#define KeAcquireSpinLock(spin_lock, OldIrql) *(OldIrql) = KeAcquireSpinLockRaiseToDpc(spin_lock)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define PAGED_CODE()
#define STATUS_SUCCESS 0
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

// Typedefs
typedef struct _DEVICE_OBJECT DEVICE_OBJECT;

typedef struct _DRIVER_OBJECT DRIVER_OBJECT;

typedef struct _EX_PUSH_LOCK
{
    SRWLOCK lock;
} EX_PUSH_LOCK;
typedef struct _EX_RUNDOWN_REF
{
    struct _mock_rundown_ref* inner;
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

typedef struct _MDL MDL;
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
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags);

_Releases_shared_lock_(push_lock->lock) void ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags);

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE pool_type, _In_ size_t number_of_bytes, _In_ unsigned long tag);

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
