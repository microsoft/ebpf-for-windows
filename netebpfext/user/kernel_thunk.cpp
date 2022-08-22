// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <condition_variable>
#include <mutex>

#include "netebpfext_platform.h"
#include "kernel_thunk.h"

typedef struct _ebpf_rundown_ref
{
    std::mutex lock;
    std::condition_variable cv;
    size_t count = 0;
    bool rundown_in_progress = false;
} ebpf_rundown_ref;

typedef struct _MDL
{
    MDL* next;
    size_t size;
    uint64_t flags;
    void* start_va;
    size_t byte_offset;
    size_t byte_count;
} MDL, *PMDL;

typedef struct _IO_WORKITEM
{
    DEVICE_OBJECT* device;
    ebpf_preemptible_work_item_t* work_item;
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
#define MmGetMdlByteCount(mdl) ((mdl)->byte_count)
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
    return -1;
}

void
ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* rundown_ref)
{
    rundown_ref->inner = new ebpf_rundown_ref();
    return;
}

void
ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    auto& rundown = *rundown_ref->inner;
    std::unique_lock<std::mutex> l(rundown.lock);
    rundown.rundown_in_progress = true;
    rundown_ref->inner->cv.wait(l, [&] { return rundown.count == 0; });
    return;
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
    ebpf_assert(rundown.count > 0);
    rundown.count--;
    rundown.cv.notify_all();
}

_Acquires_exclusive_lock_(push_lock->lock) void ExAcquirePushLockExclusiveEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    AcquireSRWLockExclusive(&push_lock->lock);
    return;
}

_Acquires_shared_lock_(push_lock->lock) void ExAcquirePushLockSharedEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    AcquireSRWLockShared(&push_lock->lock);
    return;
}

_Releases_exclusive_lock_(push_lock->lock) void ExReleasePushLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    ReleaseSRWLockExclusive(&push_lock->lock);
    return;
}

_Releases_shared_lock_(push_lock->lock) void ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    ReleaseSRWLockShared(&push_lock->lock);
    return;
}

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE pool_type, _In_ size_t number_of_bytes, _In_ unsigned long tag)
{
    return ebpf_allocate(number_of_bytes);
}

void
ExFreePool(void* p)
{
    ebpf_free(p);
}

void
ExInitializePushLock(_Out_ EX_PUSH_LOCK* push_lock)
{
    push_lock->lock = SRWLOCK_INIT;
}

void
FatalListEntryError(_In_ void* p1, _In_ void* p2, _In_ void* p3)
{
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

    mdl = reinterpret_cast<MDL*>(ebpf_allocate(sizeof(MDL)));
    if (mdl == NULL) {
        return mdl;
    }
#pragma warning(push)
#pragma warning(disable : 26451)
    MmInitializeMdl(mdl, virtual_address, length);
#pragma warning(pop)

    return mdl;
}

void
io_work_item_wrapper(_In_opt_ const void* work_item_context)
{
    auto work_item = reinterpret_cast<const IO_WORKITEM*>(work_item_context);
    if (work_item) {
        work_item->routine(work_item->device, work_item->context);
    }
}

PIO_WORKITEM
IoAllocateWorkItem(_In_ DEVICE_OBJECT* device_object)
{
    auto work_item = reinterpret_cast<IO_WORKITEM*>(ebpf_allocate(sizeof(IO_WORKITEM)));
    if (!work_item) {
        return nullptr;
    }
    work_item->device = device_object;
    ebpf_result_t result = ebpf_allocate_preemptible_work_item(&work_item->work_item, io_work_item_wrapper, work_item);
    if (result != EBPF_SUCCESS) {
        ebpf_free(work_item);
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
    io_workitem->routine = worker_routine;
    io_workitem->context = context;
    ebpf_queue_preemptible_work_item(io_workitem->work_item);
    return;
}

void
IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM io_workitem)
{
    if (io_workitem) {
        ebpf_free_preemptible_work_item(io_workitem->work_item);
        ebpf_free(io_workitem);
    }
    return;
}

void
IoFreeMdl(MDL* mdl)
{
    ebpf_free(mdl);
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
    auto lock = reinterpret_cast<ebpf_lock_t*>(spin_lock);
    ebpf_lock_create(lock);
}

_Requires_lock_not_held_(*spin_lock) _Acquires_lock_(*spin_lock) _IRQL_requires_max_(DISPATCH_LEVEL) KIRQL
    KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK spin_lock)
{
    auto lock = reinterpret_cast<ebpf_lock_t*>(spin_lock);
    return ebpf_lock_lock(lock);
}

_Requires_lock_held_(*spin_lock) _Releases_lock_(*spin_lock) _IRQL_requires_(DISPATCH_LEVEL) void KeReleaseSpinLock(
    _Inout_ PKSPIN_LOCK spin_lock, _In_ _IRQL_restores_ KIRQL new_irql)
{
    auto lock = reinterpret_cast<ebpf_lock_t*>(spin_lock);
    ebpf_lock_unlock(lock, new_irql);
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
    return ((PVOID)((PUCHAR)(mdl)->start_va + (mdl)->byte_offset));
}

NTSTATUS
RtlULongAdd(
    _In_ unsigned long augend,
    _In_ unsigned long addend,
    _Out_ _Deref_out_range_(==, augend + addend) unsigned long* result)
{
    return STATUS_NO_MEMORY;
}
