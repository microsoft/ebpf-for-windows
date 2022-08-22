// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpfext_platform.h"
#include "kernel_thunk.h"

unsigned long __cdecl DbgPrintEx(
    _In_ unsigned long component_id, _In_ unsigned long level, _In_z_ _Printf_format_string_ PCSTR format, ...)
{
    return -1;
}

void
ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* rundown_ref)
{
    return;
}

void
ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    return;
}

BOOLEAN
ExAcquireRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref) { return FALSE; }

void
ExReleaseRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    return;
}

void
ExAcquirePushLockExclusiveEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    return;
}

void
ExAcquirePushLockSharedEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    return;
}

void
ExReleasePushLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    return;
}

void
ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    return;
}

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE pool_type, _In_ size_t number_of_bytes, _In_ unsigned long tag)
{
    return NULL;
}

void
ExFreePool(void* P)
{
    return;
}

void
ExInitializePushLock(_Out_ EX_PUSH_LOCK* push_lock)
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
    _In_opt_ __drv_aliasesMem void* virtual_address,
    _In_ unsigned long length,
    _In_ BOOLEAN secondary_buffer,
    _In_ BOOLEAN charge_quota,
    _Inout_opt_ IRP* irp)
{
    return NULL;
}

PIO_WORKITEM
IoAllocateWorkItem(_In_ DEVICE_OBJECT* device_object) { return NULL; }

void
IoQueueWorkItem(
    _Inout_ __drv_aliasesMem IO_WORKITEM* io_workitem,
    _In_ IO_WORKITEM_ROUTINE* worker_routine,
    _In_ WORK_QUEUE_TYPE queue_type,
    _In_opt_ __drv_aliasesMem void* context)
{
    return;
}

void
IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM io_workitem)
{
    return;
}

void
IoFreeMdl(MDL* mdl)
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
KeInitializeSpinLock(_Out_ PKSPIN_LOCK spin_lock)
{
    return;
}

KIRQL
KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK spin_lock) { return 0; }

void
KeReleaseSpinLock(_Inout_ PKSPIN_LOCK spin_lock, _In_ _IRQL_restores_ KIRQL new_irql)
{
    return;
}

void
MmBuildMdlForNonPagedPool(_Inout_ MDL* memory_descriptor_list)
{
    return;
}

void*
MmGetSystemAddressForMdlSafe(
    _Inout_ MDL* mdl,
    _In_ unsigned long page_priority // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
)
{
    return NULL;
}

NTSTATUS
RtlULongAdd(
    _In_ unsigned long augend,
    _In_ unsigned long addend,
    _Out_ _Deref_out_range_(==, augend + addend) unsigned long* result)
{
    return STATUS_NO_MEMORY;
}
