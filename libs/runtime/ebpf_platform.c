// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

_Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object();

static uint32_t _ebpf_platform_maximum_processor_count = 0;

static bool _ebpf_platform_is_cxplat_initialized = false;

_Ret_range_(>, 0) uint32_t ebpf_get_cpu_count() { return _ebpf_platform_maximum_processor_count; }

void
ebpf_initialize_cpu_count()
{
    _ebpf_platform_maximum_processor_count = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

typedef struct _ebpf_process_state
{
    KAPC_STATE state;
} ebpf_process_state_t;

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

#pragma region semaphores

_Must_inspect_result_ ebpf_result_t
ebpf_semaphore_create(_Outptr_ KSEMAPHORE** semaphore, int initial_count, int maximum_count)
{
    *semaphore = (KSEMAPHORE*)ebpf_allocate(sizeof(KSEMAPHORE));
    if (*semaphore == NULL) {
        return EBPF_NO_MEMORY;
    }

    KeInitializeSemaphore(*semaphore, initial_count, maximum_count);
    return EBPF_SUCCESS;
}

void
ebpf_semaphore_wait(_In_ KSEMAPHORE* semaphore)
{
    KeWaitForSingleObject(semaphore, Executive, KernelMode, FALSE, NULL);
}

void
ebpf_semaphore_release(_In_ KSEMAPHORE* semaphore)
{
    KeReleaseSemaphore(semaphore, 0, 1, FALSE);
}

void
ebpf_semaphore_destroy(_Frees_ptr_opt_ KSEMAPHORE* semaphore)
{
    ebpf_free(semaphore);
}

#pragma endregion semaphores

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

MDL*
ebpf_map_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    MDL* memory_descriptor_list = NULL;
    PHYSICAL_ADDRESS start_address;
    PHYSICAL_ADDRESS end_address;
    PHYSICAL_ADDRESS page_size;
    start_address.QuadPart = 0;
    end_address.QuadPart = -1;
    page_size.QuadPart = PAGE_SIZE;
    memory_descriptor_list =
        MmAllocatePagesForMdlEx(start_address, end_address, page_size, length, MmCached, MM_ALLOCATE_FULLY_REQUIRED);

    if (memory_descriptor_list) {
        void* address =
            MmMapLockedPagesSpecifyCache(memory_descriptor_list, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (!address) {
            EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapLockedPagesSpecifyCache, STATUS_NO_MEMORY);
            MmFreePagesFromMdl(memory_descriptor_list);
            ExFreePool(memory_descriptor_list);
            memory_descriptor_list = NULL;
        }
    } else {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmAllocatePagesForMdlEx, STATUS_NO_MEMORY);
    }
    EBPF_RETURN_POINTER(MDL*, memory_descriptor_list);
}

void
ebpf_unmap_memory(_Frees_ptr_opt_ MDL* memory_descriptor)
{
    EBPF_LOG_ENTRY();
    if (!memory_descriptor) {
        EBPF_RETURN_VOID();
    }

    MmUnmapLockedPages(ebpf_memory_descriptor_get_base_address(memory_descriptor), memory_descriptor);
    MmFreePagesFromMdl(memory_descriptor);
    ExFreePool(memory_descriptor);
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_protect_memory(_In_ MDL* memory_descriptor, ebpf_page_protection_t protection)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    unsigned long mm_protection_state = 0;
    switch (protection) {
    case EBPF_PAGE_PROTECT_READ_ONLY:
        mm_protection_state = PAGE_READONLY;
        break;
    case EBPF_PAGE_PROTECT_READ_WRITE:
        mm_protection_state = PAGE_READWRITE;
        break;
    case EBPF_PAGE_PROTECT_READ_EXECUTE:
        mm_protection_state = PAGE_EXECUTE_READ;
        break;
    default:
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    status = MmProtectMdlSystemAddress(memory_descriptor, mm_protection_state);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmProtectMdlSystemAddress, status);
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

void*
ebpf_memory_descriptor_get_base_address(MDL* memory_descriptor)
{
    void* address = MmGetSystemAddressForMdlSafe(memory_descriptor, NormalPagePriority);
    if (!address) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmGetSystemAddressForMdlSafe, STATUS_NO_MEMORY);
    }
    return address;
}

ebpf_result_t
ebpf_utf8_string_to_unicode(_In_ const cxplat_utf8_string_t* input, _Outptr_ wchar_t** output)
{
    wchar_t* unicode_string = NULL;
    unsigned long unicode_byte_count = 0;
    ebpf_result_t retval;

    // Compute the size needed to hold the unicode string.
    NTSTATUS status =
        RtlUTF8ToUnicodeN(NULL, 0, &unicode_byte_count, (const char*)input->value, (unsigned long)input->length);
    if (!NT_SUCCESS(status)) {
        return EBPF_INVALID_ARGUMENT;
    }

    unicode_string = (wchar_t*)ebpf_allocate(unicode_byte_count + sizeof(wchar_t));
    if (unicode_string == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    status = RtlUTF8ToUnicodeN(
        unicode_string,
        unicode_byte_count,
        &unicode_byte_count,
        (const char*)input->value,
        (unsigned long)input->length);

    if (!NT_SUCCESS(status)) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    *output = unicode_string;
    unicode_string = NULL;
    retval = EBPF_SUCCESS;

Done:
    ebpf_free(unicode_string);
    return retval;
}

// Pick an arbitrary limit on string size roughly based on the size of the eBPF stack.
// This is enough space for a format string that takes up all the eBPF stack space,
// plus room to expand three 64-bit integer arguments from 2-character format specifiers.
#define MAX_PRINTK_STRING_SIZE 554

long
ebpf_platform_printk(_In_z_ const char* format, va_list arg_list)
{
    char* output = (char*)ebpf_allocate(MAX_PRINTK_STRING_SIZE);
    if (output == NULL) {
        return -1;
    }

    long bytes_written = -1;
    if (RtlStringCchVPrintfA(output, MAX_PRINTK_STRING_SIZE, format, arg_list) == 0) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_PRINTK, output);
        bytes_written = (long)strlen(output);
    }

    ebpf_free(output);
    return bytes_written;
}

int32_t
ebpf_log_function(_In_ void* context, _In_z_ const char* format_string, ...)
{
    UNREFERENCED_PARAMETER(context);

    NTSTATUS status;
    char buffer[80];
    va_list arg_start;
    va_start(arg_start, format_string);

    status = RtlStringCchVPrintfA(buffer, sizeof(buffer), format_string, arg_start);
    if (NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, buffer);
    }

    va_end(arg_start);
    return 0;
}

_Must_inspect_result_ ebpf_result_t
ebpf_set_current_thread_affinity(uintptr_t new_thread_affinity_mask, _Out_ uintptr_t* old_thread_affinity_mask)
{
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    KAFFINITY old_affinity = KeSetSystemAffinityThreadEx(new_thread_affinity_mask);
    *old_thread_affinity_mask = old_affinity;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_non_preemptible_work_item(
    _Outptr_ KDPC** dpc,
    uint32_t cpu_id,
    _In_ PKDEFERRED_ROUTINE work_item_routine,
    _Inout_opt_ void* work_item_context)
{
    *dpc = ebpf_allocate(sizeof(KDPC));
    if (*dpc == NULL) {
        return EBPF_NO_MEMORY;
    }

    KeInitializeDpc(*dpc, work_item_routine, work_item_context);
    KeSetTargetProcessorDpc(*dpc, (uint8_t)cpu_id);
    return EBPF_SUCCESS;
}

void
ebpf_free_non_preemptible_work_item(_In_opt_ _Frees_ptr_opt_ KDPC* dpc)
{
    if (!dpc) {
        return;
    }

    KeRemoveQueueDpc(dpc);
    ebpf_free(dpc);
}

typedef struct _ebpf_timer_work_item
{
    KDPC deferred_procedure_call;
    KTIMER timer;
    void (*work_item_routine)(_Inout_opt_ void* work_item_context);
    void* work_item_context;
} ebpf_timer_work_item_t;

_Function_class_(KDEFERRED_ROUTINE) static void _ebpf_timer_routine(
    _In_ KDPC* deferred_procedure_call,
    _In_opt_ void* deferred_context,
    _In_opt_ void* system_argument_1,
    _In_opt_ void* system_argument_2)
{
    ebpf_timer_work_item_t* timer_work_item = (ebpf_timer_work_item_t*)deferred_procedure_call;
    UNREFERENCED_PARAMETER(system_argument_1);
    UNREFERENCED_PARAMETER(system_argument_2);
    timer_work_item->work_item_routine(deferred_context);
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_timer_work_item(
    _Outptr_ ebpf_timer_work_item_t** timer_work_item,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
    _Inout_opt_ void* work_item_context)
{
    *timer_work_item = (ebpf_timer_work_item_t*)ebpf_allocate(sizeof(ebpf_timer_work_item_t));
    if (*timer_work_item == NULL) {
        return EBPF_NO_MEMORY;
    }

    (*timer_work_item)->work_item_routine = work_item_routine;
    (*timer_work_item)->work_item_context = work_item_context;

    KeInitializeTimer(&(*timer_work_item)->timer);
    KeInitializeDpc(&(*timer_work_item)->deferred_procedure_call, _ebpf_timer_routine, work_item_context);

    return EBPF_SUCCESS;
}

#define MICROSECONDS_PER_TICK 10
#define MICROSECONDS_PER_MILLISECOND 1000

void
ebpf_schedule_timer_work_item(_Inout_ ebpf_timer_work_item_t* work_item, uint32_t elapsed_microseconds)
{
    LARGE_INTEGER due_time;
    due_time.QuadPart = -((int64_t)elapsed_microseconds * MICROSECONDS_PER_TICK);

    KeSetTimer(&work_item->timer, due_time, &work_item->deferred_procedure_call);
}

void
ebpf_free_timer_work_item(_Frees_ptr_opt_ ebpf_timer_work_item_t* work_item)
{
    if (!work_item) {
        return;
    }

    KeCancelTimer(&work_item->timer);
    KeRemoveQueueDpc(&work_item->deferred_procedure_call);
    KeFlushQueuedDpcs();
    ebpf_free(work_item);
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_preemptible_work_item(
    _Outptr_ cxplat_preemptible_work_item_t** work_item,
    _In_ cxplat_work_item_routine_t work_item_routine,
    _In_opt_ void* work_item_context)
{
    cxplat_status_t status = cxplat_allocate_preemptible_work_item(
        ebpf_driver_get_device_object(),
        (cxplat_preemptible_work_item_t**)work_item,
        work_item_routine,
        work_item_context);
    return ebpf_result_from_cxplat_status(status);
}

_Must_inspect_result_ ebpf_result_t
ebpf_platform_initiate()
{
    ebpf_result_t result = ebpf_result_from_cxplat_status(cxplat_initialize());
    _ebpf_platform_is_cxplat_initialized = (result == EBPF_SUCCESS);
    ebpf_initialize_cpu_count();
    return result;
}

void
ebpf_platform_terminate()
{
    KeFlushQueuedDpcs();
    if (_ebpf_platform_is_cxplat_initialized) {
        cxplat_cleanup();
        _ebpf_platform_is_cxplat_initialized = false;
    }
}
