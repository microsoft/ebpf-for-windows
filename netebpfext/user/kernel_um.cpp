// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <condition_variable>
#include <mutex>

#include "netebpfext_platform.h"

#include "kernel_um.h"

typedef struct _mock_rundown_ref
{
    std::mutex lock;
    std::condition_variable cv;
    size_t count = 0;
    bool rundown_in_progress = false;
} mock_rundown_ref;

typedef struct _MDL
{
    MDL* next;
    size_t size;
    uint64_t flags;
    void* start_va;
    unsigned long byte_offset;
    unsigned long byte_count;
} MDL, *PMDL;

typedef struct _IO_WORKITEM
{
    DEVICE_OBJECT* device;
    PTP_WORK work_item;
    IO_WORKITEM_ROUTINE* routine;
    void* context;
} IO_WORKITEM;

typedef ULONG PFN_NUMBER;
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12L

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define BYTE_OFFSET(Va) ((ULONG)((LONG_PTR)(Va) & (PAGE_SIZE - 1)))
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va, size)                                                        \
    (((((size)-1) >> PAGE_SHIFT) +                                                                      \
      (((((ULONG)(size - 1) & (PAGE_SIZE - 1)) + (PtrToUlong(Va) & (PAGE_SIZE - 1)))) >> PAGE_SHIFT)) + \
     1L)

unsigned long
MmGetMdlByteCount(_In_ MDL* mdl)
{
    return mdl->byte_count;
}

#define MmGetMdlByteOffset(mdl) ((mdl)->byte_offset)
#define MmGetMdlBaseVa(mdl) ((mdl)->start_va)
#define MmGetMdlVirtualAddress(mdl) ((PVOID)((PCHAR)((mdl)->start_va) + (mdl)->byte_offset))
#define MmInitializeMdl(mdl, base_va, length)                                                                     \
    {                                                                                                             \
        (mdl)->next = (PMDL)NULL;                                                                                 \
        (mdl)->size =                                                                                             \
            (uint16_t)(sizeof(MDL) + (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES((base_va), (length)))); \
        (mdl)->flags = 0;                                                                                         \
        (mdl)->start_va = (PVOID)PAGE_ALIGN((base_va));                                                           \
        (mdl)->byte_offset = BYTE_OFFSET((base_va));                                                              \
        (mdl)->byte_count = (ULONG)(length);                                                                      \
    }

unsigned long __cdecl DbgPrintEx(
    _In_ unsigned long component_id, _In_ unsigned long level, _In_z_ _Printf_format_string_ PCSTR format, ...)
{
    UNREFERENCED_PARAMETER(component_id);
    UNREFERENCED_PARAMETER(level);
    UNREFERENCED_PARAMETER(format);
    return MAXULONG32;
}

void
ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* rundown_ref)
{
    rundown_ref->inner = new mock_rundown_ref();
}

void
ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    auto& rundown = *rundown_ref->inner;
    std::unique_lock<std::mutex> l(rundown.lock);
    rundown.rundown_in_progress = true;
    rundown_ref->inner->cv.wait(l, [&] { return rundown.count == 0; });
}

BOOLEAN
ExAcquireRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    auto& rundown = *rundown_ref->inner;
    std::unique_lock<std::mutex> l(rundown.lock);
    if (rundown.rundown_in_progress) {
        return FALSE;
    } else {
        rundown.count++;
        return TRUE;
    }
}

void
ExReleaseRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    auto& rundown = *rundown_ref->inner;
    std::unique_lock<std::mutex> l(rundown.lock);
    assert(rundown.count > 0);
    rundown.count--;
    rundown.cv.notify_all();
}

_Acquires_exclusive_lock_(push_lock->lock) void ExAcquirePushLockExclusiveEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    AcquireSRWLockExclusive(&push_lock->lock);
}

_Acquires_shared_lock_(push_lock->lock) void ExAcquirePushLockSharedEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    AcquireSRWLockShared(&push_lock->lock);
}

_Releases_exclusive_lock_(push_lock->lock) void ExReleasePushLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    ReleaseSRWLockExclusive(&push_lock->lock);
}

_Releases_shared_lock_(push_lock->lock) void ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    ReleaseSRWLockShared(&push_lock->lock);
}

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE pool_type, _In_ size_t number_of_bytes, _In_ unsigned long tag)
{
    UNREFERENCED_PARAMETER(pool_type);
    UNREFERENCED_PARAMETER(tag);
    return malloc(number_of_bytes);
}

void
ExFreePool(void* p)
{
    free(p);
}

void
ExInitializePushLock(_Out_ EX_PUSH_LOCK* push_lock)
{
    push_lock->lock = SRWLOCK_INIT;
}

void
FatalListEntryError(_In_ void* p1, _In_ void* p2, _In_ void* p3)
{
    UNREFERENCED_PARAMETER(p1);
    UNREFERENCED_PARAMETER(p2);
    UNREFERENCED_PARAMETER(p3);
    throw std::runtime_error("FatalListEntryError");
}

MDL*
IoAllocateMdl(
    _In_opt_ __drv_aliasesMem void* virtual_address,
    _In_ unsigned long length,
    _In_ BOOLEAN secondary_buffer,
    _In_ BOOLEAN charge_quota,
    _Inout_opt_ IRP* irp)
{
    PMDL mdl;

    UNREFERENCED_PARAMETER(secondary_buffer);
    UNREFERENCED_PARAMETER(charge_quota);
    UNREFERENCED_PARAMETER(irp);

    mdl = reinterpret_cast<MDL*>(malloc(sizeof(MDL)));
    if (mdl == NULL) {
        return mdl;
    }
#pragma warning(push)
#pragma warning(disable : 26451)
    MmInitializeMdl(mdl, virtual_address, length);
#pragma warning(pop)

    return mdl;
}

void NTAPI
io_work_item_wrapper(_Inout_ PTP_CALLBACK_INSTANCE instance, _Inout_opt_ PVOID context, _Inout_ PTP_WORK work)
{
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(work);
    auto work_item = reinterpret_cast<const IO_WORKITEM*>(context);
    if (work_item) {
        work_item->routine(work_item->device, work_item->context);
    }
}

PIO_WORKITEM
IoAllocateWorkItem(_In_ DEVICE_OBJECT* device_object)
{
    auto work_item = reinterpret_cast<IO_WORKITEM*>(malloc(sizeof(IO_WORKITEM)));
    if (!work_item) {
        return nullptr;
    }
    work_item->device = device_object;
    work_item->work_item = CreateThreadpoolWork(io_work_item_wrapper, work_item, nullptr);
    if (work_item->work_item == nullptr) {
        free(work_item);
        work_item = nullptr;
    }
    return work_item;
}

void
IoQueueWorkItem(
    _Inout_ __drv_aliasesMem IO_WORKITEM* io_workitem,
    _In_ IO_WORKITEM_ROUTINE* worker_routine,
    _In_ WORK_QUEUE_TYPE queue_type,
    _In_opt_ __drv_aliasesMem void* context)
{
    UNREFERENCED_PARAMETER(queue_type);
    io_workitem->routine = worker_routine;
    io_workitem->context = context;
    SubmitThreadpoolWork(io_workitem->work_item);
}

void
IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM io_workitem)
{
    if (io_workitem) {
        CloseThreadpoolWork(io_workitem->work_item);
        free(io_workitem);
    }
}

void
IoFreeMdl(MDL* mdl)
{
    free(mdl);
}

void
KeEnterCriticalRegion(void)
{}

void
KeLeaveCriticalRegion(void)
{}

void
KeInitializeSpinLock(_Out_ PKSPIN_LOCK spin_lock)
{
    auto lock = reinterpret_cast<SRWLOCK*>(spin_lock);
    *lock = SRWLOCK_INIT;
}

_Requires_lock_not_held_(*spin_lock) _Acquires_lock_(*spin_lock) _IRQL_requires_max_(DISPATCH_LEVEL) KIRQL
    KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK spin_lock)
{
    auto lock = reinterpret_cast<SRWLOCK*>(spin_lock);
    AcquireSRWLockExclusive(lock);
    return 0;
}

_Requires_lock_held_(*spin_lock) _Releases_lock_(*spin_lock) _IRQL_requires_(DISPATCH_LEVEL) void KeReleaseSpinLock(
    _Inout_ PKSPIN_LOCK spin_lock, _In_ _IRQL_restores_ KIRQL new_irql)
{
    UNREFERENCED_PARAMETER(new_irql);
    auto lock = reinterpret_cast<SRWLOCK*>(spin_lock);
    ReleaseSRWLockExclusive(lock);
}

void
MmBuildMdlForNonPagedPool(_Inout_ MDL* memory_descriptor_list)
{
    UNREFERENCED_PARAMETER(memory_descriptor_list);
}

void*
MmGetSystemAddressForMdlSafe(
    _Inout_ MDL* mdl,
    _In_ unsigned long page_priority // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
)
{
    UNREFERENCED_PARAMETER(page_priority);
    return ((PVOID)((PUCHAR)(mdl)->start_va + (mdl)->byte_offset));
}

NTSTATUS
RtlULongAdd(
    _In_ unsigned long augend,
    _In_ unsigned long addend,
    _Out_ _Deref_out_range_(==, augend + addend) unsigned long* result)
{
    *result = augend + addend;
    return STATUS_SUCCESS;
}
