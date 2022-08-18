// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Defines
#define EX_DEFAULT_PUSH_LOCK_FLAGS 0
#define ExAcquirePushLockExclusive(Lock) ExAcquirePushLockExclusiveEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExAcquirePushLockShared(Lock) ExAcquirePushLockSharedEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExReleasePushLockExclusive(Lock) ExReleasePushLockExclusiveEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define ExReleasePushLockShared(Lock) ExReleasePushLockSharedEx(Lock, EX_DEFAULT_PUSH_LOCK_FLAGS)
#define KdPrintEx(_x_) DbgPrintEx _x_
#define KeAcquireSpinLock(SpinLock, OldIrql) *(OldIrql) = KeAcquireSpinLockRaiseToDpc(SpinLock)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define PAGED_CODE()
#define STATUS_SUCCESS 0
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)

// Typedefs
typedef void* DEVICE_OBJECT;
typedef void* DRIVER_OBJECT;

typedef struct _EX_PUSH_LOCK
{
    char padding;
} EX_PUSH_LOCK;
typedef struct _EX_RUNDOWN_REF
{
    char padding;
} EX_RUNDOWN_REF;
typedef struct _IO_WORKITEM IO_WORKITEM, *PIO_WORKITEM;
typedef void
IO_WORKITEM_ROUTINE(_In_ DEVICE_OBJECT* DeviceObject, _In_opt_ void* Context);

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

typedef UCHAR KIRQL;

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

ULONG
__cdecl DbgPrintEx(_In_ ULONG ComponentId, _In_ ULONG Level, _In_z_ _Printf_format_string_ PCSTR Format, ...);

void
ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* RunRef);

void
ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* RunRef);

BOOLEAN
ExAcquireRundownProtection(_Inout_ EX_RUNDOWN_REF* RunRef);

void
ExReleaseRundownProtection(_Inout_ EX_RUNDOWN_REF* RunRef);

void
ExAcquirePushLockExclusiveEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags);

void
ExAcquirePushLockSharedEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags);

void
ExReleasePushLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags);

void
ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags);

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);

void
ExFreePool(void* P);

void
ExInitializePushLock(_Out_ EX_PUSH_LOCK* PushLock);

void
FatalListEntryError(_In_ void* p1, _In_ void* p2, _In_ void* p3);

MDL*
IoAllocateMdl(
    _In_opt_ __drv_aliasesMem void* VirtualAddress,
    _In_ ULONG Length,
    _In_ BOOLEAN SecondaryBuffer,
    _In_ BOOLEAN ChargeQuota,
    _Inout_opt_ IRP* Irp);

PIO_WORKITEM
IoAllocateWorkItem(_In_ DEVICE_OBJECT* DeviceObject);

void
IoQueueWorkItem(
    _Inout_ __drv_aliasesMem IO_WORKITEM* IoWorkItem,
    _In_ IO_WORKITEM_ROUTINE* WorkerRoutine,
    _In_ WORK_QUEUE_TYPE QueueType,
    _In_opt_ __drv_aliasesMem void* Context);

void
IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM IoWorkItem);

void
IoFreeMdl(MDL* Mdl);

void
KeEnterCriticalRegion(void);

void
KeLeaveCriticalRegion(void);

void
KeInitializeSpinLock(_Out_ PKSPIN_LOCK SpinLock);

KIRQL
KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK SpinLock);

void
KeReleaseSpinLock(_Inout_ PKSPIN_LOCK SpinLock, _In_ _IRQL_restores_ KIRQL NewIrql);

void
MmBuildMdlForNonPagedPool(_Inout_ MDL* MemoryDescriptorList);

void*
MmGetSystemAddressForMdlSafe(
    _Inout_ MDL* Mdl,
    _In_ ULONG Priority // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
);

NTSTATUS
RtlULongAdd(
    _In_ ULONG ulAugend, _In_ ULONG ulAddend, _Out_ _Deref_out_range_(==, ulAugend + ulAddend) ULONG* pulResult);

// Inline functions
_Must_inspect_result_ BOOLEAN CFORCEINLINE
IsListEmpty(_In_ const LIST_ENTRY* ListHead)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
void
InsertTailList(_Inout_ PLIST_ENTRY ListHead, _Out_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY PrevEntry;
    PrevEntry = ListHead->Blink;
    if (PrevEntry->Flink != ListHead) {
        FatalListEntryError((void*)PrevEntry, (void*)ListHead, (void*)PrevEntry->Flink);
    }

    Entry->Flink = ListHead;
    Entry->Blink = PrevEntry;
    PrevEntry->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}

FORCEINLINE
BOOLEAN
RemoveEntryList(_In_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY PrevEntry;
    PLIST_ENTRY NextEntry;

    NextEntry = Entry->Flink;
    PrevEntry = Entry->Blink;
    if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {
        FatalListEntryError((void*)PrevEntry, (void*)Entry, (void*)NextEntry);
    }

    PrevEntry->Flink = NextEntry;
    NextEntry->Blink = PrevEntry;
    return (BOOLEAN)(PrevEntry == NextEntry);
}

FORCEINLINE
void
InitializeListHead(_Out_ PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(_Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;

    Entry = ListHead->Flink;

    NextEntry = Entry->Flink;
    if ((Entry->Blink != ListHead) || (NextEntry->Blink != Entry)) {
        FatalListEntryError((void*)ListHead, (void*)Entry, (void*)NextEntry);
    }

    ListHead->Flink = NextEntry;
    NextEntry->Blink = ListHead;

    return Entry;
}
