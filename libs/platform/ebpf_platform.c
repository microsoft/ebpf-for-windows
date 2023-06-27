// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

bool ebpf_fuzzing_enabled = false;

typedef struct _ebpf_process_state
{
    KAPC_STATE state;
} ebpf_process_state_t;

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_with_tag(size_t size, uint32_t tag)
{
    ebpf_assert(size);
    void* p = ExAllocatePoolUninitialized(NonPagedPoolNx, size, tag);
    if (p) {
        memset(p, 0, size);
    }
    return p;
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size)
{
    return ebpf_allocate_with_tag(size, EBPF_POOL_TAG_DEFAULT);
}

void
ebpf_free(_Frees_ptr_opt_ void* memory)
{
    if (memory) {
        ExFreePool(memory);
    }
}

void
ebpf_lock_create(_Out_ ebpf_lock_t* lock)
{
    KeInitializeSpinLock((PKSPIN_LOCK)lock);
}

void
ebpf_lock_destroy(_In_ _Post_invalid_ ebpf_lock_t* lock)
{
    UNREFERENCED_PARAMETER(lock);
}

_Requires_lock_not_held_(*lock) _Acquires_lock_(*lock) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) ebpf_lock_state_t ebpf_lock_lock(_Inout_ ebpf_lock_t* lock)
{
    return KeAcquireSpinLockRaiseToDpc(lock);
}

_Requires_lock_held_(*lock) _Releases_lock_(*lock) _IRQL_requires_(DISPATCH_LEVEL) void ebpf_lock_unlock(
    _Inout_ ebpf_lock_t* lock, _IRQL_restores_ ebpf_lock_state_t state)
{
    KeReleaseSpinLock(lock, state);
}

void
ebpf_restore_current_thread_affinity(uintptr_t old_thread_affinity_mask)
{
    KeRevertToUserAffinityThreadEx(old_thread_affinity_mask);
}

bool
ebpf_is_preemptible()
{
    KIRQL irql = KeGetCurrentIrql();
    return irql < DISPATCH_LEVEL;
}

bool
ebpf_is_non_preemptible_work_item_supported()
{
    return true;
}

uint32_t
ebpf_get_current_cpu()
{
    return KeGetCurrentProcessorNumberEx(NULL);
}

uint64_t
ebpf_get_current_thread_id()
{
    return (uint64_t)KeGetCurrentThread();
}

_Must_inspect_result_ ebpf_result_t
ebpf_guid_create(_Out_ GUID* new_guid)
{
    if (NT_SUCCESS(ExUuidCreate(new_guid))) {
        return EBPF_SUCCESS;
    } else {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
}

uint32_t
ebpf_platform_process_id()
{
    return (uint32_t)(uintptr_t)PsGetCurrentProcessId();
}

uint32_t
ebpf_platform_thread_id()
{
    return (uint32_t)(uintptr_t)PsGetCurrentThreadId();
}

_IRQL_requires_max_(HIGH_LEVEL) _IRQL_raises_(new_irql) _IRQL_saves_ uint8_t ebpf_raise_irql(uint8_t new_irql)
{
    KIRQL old_irql;
    KeRaiseIrql(new_irql, &old_irql);
    return old_irql;
}

_IRQL_requires_max_(HIGH_LEVEL) void ebpf_lower_irql(_In_ _Notliteral_ _IRQL_restores_ uint8_t old_irql)
{
    KeLowerIrql(old_irql);
}

bool
ebpf_should_yield_processor()
{
    // Don't yield if we are at passive level as the scheduler can preempt us.
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        return false;
    }

    // KeShouldYieldProcessor returns TRUE if the current thread should yield the processor.
    return KeShouldYieldProcessor() != FALSE;
}

void
ebpf_get_execution_context_state(_Out_ ebpf_execution_context_state_t* state)
{
    state->current_irql = KeGetCurrentIrql();
    if (state->current_irql == DISPATCH_LEVEL) {
        state->id.cpu = ebpf_get_current_cpu();
    } else {
        state->id.thread = ebpf_get_current_thread_id();
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_semaphore_create(_Outptr_ ebpf_semaphore_t** semaphore, int initial_count, int maximum_count)
{
    *semaphore = (ebpf_semaphore_t*)ebpf_allocate(sizeof(ebpf_semaphore_t));
    if (*semaphore == NULL) {
        return EBPF_NO_MEMORY;
    }

    KeInitializeSemaphore(*semaphore, initial_count, maximum_count);
    return EBPF_SUCCESS;
}

void
ebpf_semaphore_wait(_In_ ebpf_semaphore_t* semaphore)
{
    KeWaitForSingleObject(semaphore, Executive, KernelMode, FALSE, NULL);
}

void
ebpf_semaphore_release(_In_ ebpf_semaphore_t* semaphore)
{
    KeReleaseSemaphore(semaphore, 0, 1, FALSE);
}

void
ebpf_enter_critical_region()
{
    KeEnterCriticalRegion();
}

void
ebpf_leave_critical_region()
{
    KeLeaveCriticalRegion();
}

intptr_t
ebpf_platform_reference_process()
{
    PEPROCESS process = PsGetCurrentProcess();
    ObReferenceObject(process);
    return (intptr_t)process;
}

void
ebpf_platform_dereference_process(intptr_t process_handle)
{
    ObDereferenceObject((PEPROCESS)process_handle);
}

void
ebpf_platform_attach_process(intptr_t process_handle, _Inout_ ebpf_process_state_t* state)
{
    KeStackAttachProcess((PEPROCESS)process_handle, &state->state);
}

void
ebpf_platform_detach_process(_In_ ebpf_process_state_t* state)
{
    KeUnstackDetachProcess(&state->state);
}

_Ret_maybenull_ ebpf_process_state_t*
ebpf_allocate_process_state()
{
    // Skipping fault injection as call to ebpf_allocate() covers it.
    ebpf_process_state_t* state = (ebpf_process_state_t*)ebpf_allocate(sizeof(ebpf_process_state_t));
    return state;
}

uint64_t
ebpf_query_time_since_boot(bool include_suspended_time)
{
    uint64_t qpc_time;
    if (include_suspended_time) {
        // KeQueryUnbiasedInterruptTimePrecise returns the current interrupt-time count in 100-nanosecond units.
        // Unbiased Interrupt time is the total time since boot including time spent suspended.
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryunbiasedinterrupttimeprecise
        return KeQueryUnbiasedInterruptTimePrecise(&qpc_time);
    } else {
        // KeQueryInterruptTimePrecise returns the current interrupt-time count in 100-nanosecond units.
        // (Biased) Interrupt time is the total time since boot excluding time spent suspended.        //
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise
        return KeQueryInterruptTimePrecise(&qpc_time);
    }
}