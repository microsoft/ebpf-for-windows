// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "kernel_thunk.h"

ULONG
__cdecl DbgPrintEx(_In_ ULONG ComponentId, _In_ ULONG Level, _In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    return -1;
}

void
ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* RunRef)
{
    return;
}

void
ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* RunRef)
{
    return;
}

BOOLEAN
ExAcquireRundownProtection(_Inout_ EX_RUNDOWN_REF* RunRef) { return FALSE; }

void
ExReleaseRundownProtection(_Inout_ EX_RUNDOWN_REF* RunRef)
{
    return;
}

void
ExAcquirePushLockExclusiveEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags)
{
    return;
}

void
ExAcquirePushLockSharedEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags)
{
    return;
}

void
ExReleasePushLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags)
{
    return;
}

void
ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* PushLock, _In_ ULONG Flags)
{
    return;
}

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    return NULL;
}

void
ExFreePool(void* P)
{
    return;
}

void
ExInitializePushLock(_Out_ EX_PUSH_LOCK* PushLock)
{
    return;
}

void
FatalListEntryError(_In_ void* p1, _In_ void* p2, _In_ void* p3)
{
    return;
}

MDL*
IoAllocateMdl(
    _In_opt_ __drv_aliasesMem void* VirtualAddress,
    _In_ ULONG Length,
    _In_ BOOLEAN SecondaryBuffer,
    _In_ BOOLEAN ChargeQuota,
    _Inout_opt_ IRP* Irp)
{
    return NULL;
}

PIO_WORKITEM
IoAllocateWorkItem(_In_ DEVICE_OBJECT* DeviceObject) { return NULL; }

void
IoQueueWorkItem(
    _Inout_ __drv_aliasesMem IO_WORKITEM* IoWorkItem,
    _In_ IO_WORKITEM_ROUTINE* WorkerRoutine,
    _In_ WORK_QUEUE_TYPE QueueType,
    _In_opt_ __drv_aliasesMem void* Context)
{
    return;
}

void
IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM IoWorkItem)
{
    return;
}

void
IoFreeMdl(MDL* Mdl)
{
    return;
}

void
KeEnterCriticalRegion(void)
{
    return;
}

void
KeLeaveCriticalRegion(void)
{
    return;
}

void
KeInitializeSpinLock(_Out_ PKSPIN_LOCK SpinLock)
{
    return;
}

KIRQL
KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK SpinLock) { return 0; }

void
KeReleaseSpinLock(_Inout_ PKSPIN_LOCK SpinLock, _In_ _IRQL_restores_ KIRQL NewIrql)
{
    return;
}

void
MmBuildMdlForNonPagedPool(_Inout_ MDL* MemoryDescriptorList)
{
    return;
}

void*
MmGetSystemAddressForMdlSafe(
    _Inout_ MDL* Mdl,
    _In_ ULONG Priority // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
)
{
    return NULL;
}

NTSTATUS
RtlULongAdd(_In_ ULONG ulAugend, _In_ ULONG ulAddend, _Out_ _Deref_out_range_(==, ulAugend + ulAddend) ULONG* pulResult)
{
    return STATUS_NO_MEMORY;
}
