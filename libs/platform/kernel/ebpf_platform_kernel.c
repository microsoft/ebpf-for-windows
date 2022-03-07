// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// ntifs.h needs to be included ahead of other headers to satisfy the Windows
// build system.
#include <ntifs.h>

#include "ebpf_platform.h"

#include <ntstrsafe.h>

typedef struct _ebpf_memory_descriptor
{
    MDL memory_descriptor_list;
} ebpf_memory_descriptor_t;

struct _ebpf_ring_descriptor
{
    MDL* memory_descriptor_list;
    ebpf_memory_descriptor_t* memory;
    void* base_address;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

typedef enum _ebpf_pool_tag
{
    EBPF_POOL_TAG = 'fpbe'
} ebpf_pool_tag_t;

static KDEFERRED_ROUTINE _ebpf_deferred_routine;
static KDEFERRED_ROUTINE _ebpf_timer_routine;

ebpf_result_t
ebpf_platform_initiate()
{
    return EBPF_SUCCESS;
}

void
ebpf_platform_terminate()
{
    KeFlushQueuedDpcs();
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(size) void* ebpf_allocate(size_t size)
{
    void* p = ExAllocatePoolUninitialized(NonPagedPoolNx, size, EBPF_POOL_TAG);
    if (p)
        memset(p, 0, size);
    return p;
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(new_size) void* ebpf_reallocate(_In_ void* memory, size_t old_size, size_t new_size)
{
    void* p = ebpf_allocate(new_size);
    if (p) {
        memcpy(p, memory, min(old_size, new_size));
        if (new_size > old_size)
            memset(((char*)p) + old_size, 0, new_size - old_size);
        ebpf_free(memory);
    }
    return p;
}

void
ebpf_free(_Frees_ptr_opt_ void* memory)
{
    if (memory)
        ExFreePool(memory);
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(size) void* ebpf_allocate_cache_aligned(size_t size)
{
    void* p = ExAllocatePoolUninitialized(NonPagedPoolNxCacheAligned, size, EBPF_POOL_TAG);
    if (p)
        memset(p, 0, size);
    return p;
}

void
ebpf_free_cache_aligned(_Frees_ptr_opt_ void* memory)
{
    if (memory)
        ExFreePool(memory);
}

ebpf_memory_descriptor_t*
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
    EBPF_RETURN_POINTER(ebpf_memory_descriptor_t*, memory_descriptor_list);
}

void
ebpf_unmap_memory(_Frees_ptr_opt_ ebpf_memory_descriptor_t* memory_descriptor)
{
    EBPF_LOG_ENTRY();
    if (!memory_descriptor)
        EBPF_RETURN_VOID();

    MmUnmapLockedPages(
        ebpf_memory_descriptor_get_base_address(memory_descriptor), &memory_descriptor->memory_descriptor_list);
    MmFreePagesFromMdl(&memory_descriptor->memory_descriptor_list);
    ExFreePool(memory_descriptor);
    EBPF_RETURN_VOID();
}

ebpf_result_t
ebpf_protect_memory(_In_ const ebpf_memory_descriptor_t* memory_descriptor, ebpf_page_protection_t protection)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    ULONG mm_protection_state = 0;
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

    status = MmProtectMdlSystemAddress((MDL*)&memory_descriptor->memory_descriptor_list, mm_protection_state);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmProtectMdlSystemAddress, status);
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

void*
ebpf_memory_descriptor_get_base_address(ebpf_memory_descriptor_t* memory_descriptor)
{
    void* address = MmGetSystemAddressForMdlSafe(&memory_descriptor->memory_descriptor_list, NormalPagePriority);
    if (!address) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmGetSystemAddressForMdlSafe, STATUS_NO_MEMORY);
    }
    return address;
}

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    size_t requested_page_count = length / PAGE_SIZE;

    ebpf_ring_descriptor_t* ring_descriptor = ebpf_allocate(sizeof(ebpf_ring_descriptor_t));
    MDL* source_mdl = NULL;
    MDL* new_mdl = NULL;

    if (!ring_descriptor) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    if (length % PAGE_SIZE != 0 || length > MAXUINT32 / 2) {
        status = STATUS_NO_MEMORY;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        goto Done;
    }

    // Allocate pages using ebpf_map_memory.
    ring_descriptor->memory = ebpf_map_memory(requested_page_count * PAGE_SIZE);
    if (!ring_descriptor->memory) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    source_mdl = &ring_descriptor->memory->memory_descriptor_list;

    // Create a MDL big enough to double map the pages.
    ring_descriptor->memory_descriptor_list =
        IoAllocateMdl(NULL, (uint32_t)(requested_page_count * 2 * PAGE_SIZE), FALSE, FALSE, NULL);
    if (!ring_descriptor->memory_descriptor_list) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    new_mdl = ring_descriptor->memory_descriptor_list;

    memcpy(MmGetMdlPfnArray(new_mdl), MmGetMdlPfnArray(source_mdl), sizeof(PFN_NUMBER) * requested_page_count);

    memcpy(
        MmGetMdlPfnArray(new_mdl) + requested_page_count,
        MmGetMdlPfnArray(source_mdl),
        sizeof(PFN_NUMBER) * requested_page_count);

#pragma warning(push)
#pragma warning(disable : 28145) /* The opaque MDL structure should not be modified by a driver except for \
                                    MDL_PAGES_LOCKED and MDL_MAPPING_CAN_FAIL. */
    new_mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

    ring_descriptor->base_address = MmMapLockedPagesSpecifyCache(
        new_mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute);
    if (!ring_descriptor->base_address) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapLockedPagesSpecifyCache, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    status = STATUS_SUCCESS;

Done:
    if (!NT_SUCCESS(status)) {
        if (ring_descriptor) {
            if (ring_descriptor->memory_descriptor_list) {
                IoFreeMdl(ring_descriptor->memory_descriptor_list);
            }
            if (ring_descriptor->memory) {
                ebpf_unmap_memory(ring_descriptor->memory);
            }
            ebpf_free(ring_descriptor);
            ring_descriptor = NULL;
        }
    }

    EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, ring_descriptor);
}

void
ebpf_free_ring_buffer_memory(_Frees_ptr_opt_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    if (!ring) {
        EBPF_RETURN_VOID();
    }

    MmUnmapLockedPages(ring->base_address, ring->memory_descriptor_list);

    IoFreeMdl(ring->memory_descriptor_list);
    ebpf_unmap_memory(ring->memory);
    ebpf_free(ring);
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_base_address(_In_ ebpf_ring_descriptor_t* memory_descriptor)
{
    return memory_descriptor->base_address;
}

_Ret_maybenull_ void*
ebpf_ring_map_readonly_user(_In_ ebpf_ring_descriptor_t* ring)
{
    __try {
        return MmMapLockedPagesSpecifyCache(
            ring->memory_descriptor_list, UserMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoWrite);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapLockedPagesSpecifyCache, STATUS_NO_MEMORY);
        return NULL;
    }
}
// There isn't an official API to query this information from kernel.
// Use NtQuerySystemInformation with struct + header from winternl.h.

// Begin code pulled from winternl.h.
#define SystemCodeIntegrityInformation 103
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
NTSTATUS
NtQuerySystemInformation(
    uint32_t system_information_class,
    void* system_information,
    uint32_t system_information_length,
    uint32_t* return_length);
// End code pulled from winternl.h.

ebpf_result_t
ebpf_get_code_integrity_state(_Out_ ebpf_code_integrity_state_t* state)
{
    NTSTATUS status;
    SYSTEM_CODEINTEGRITY_INFORMATION code_integrity_information = {sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0};
    uint32_t system_information_length = sizeof(code_integrity_information);
    uint32_t returned_length = 0;
    status = NtQuerySystemInformation(
        SystemCodeIntegrityInformation, &code_integrity_information, system_information_length, &returned_length);
    if (NT_SUCCESS(status)) {
        if ((code_integrity_information.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0) {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity enabled");
            *state = EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE;
        } else {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity disabled");
            *state = EBPF_CODE_INTEGRITY_DEFAULT;
        }
        return EBPF_SUCCESS;
    } else {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NtQuerySystemInformation, status);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_multiply(
    size_t multiplicand, size_t multiplier, _Out_ _Deref_out_range_(==, multiplicand* multiplier) size_t* result)
{
    return RtlSizeTMult(multiplicand, multiplier, result) == STATUS_SUCCESS ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_add(size_t augend, size_t addend, _Out_ _Deref_out_range_(==, augend + addend) size_t* result)
{
    return RtlSizeTAdd(augend, addend, result) == STATUS_SUCCESS ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_subtract(
    size_t minuend, size_t subtrahend, _Out_ _Deref_out_range_(==, minuend - subtrahend) size_t* result)
{
    return RtlSizeTSub(minuend, subtrahend, result) == STATUS_SUCCESS ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

void
ebpf_lock_create(_Out_ ebpf_lock_t* lock)
{
    KeInitializeSpinLock((PKSPIN_LOCK)lock);
}

void
ebpf_lock_destroy(_In_ ebpf_lock_t* lock)
{
    UNREFERENCED_PARAMETER(lock);
}

_Requires_lock_not_held_(*lock) _Acquires_lock_(*lock) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) ebpf_lock_state_t ebpf_lock_lock(_In_ ebpf_lock_t* lock)
{
    return KeAcquireSpinLockRaiseToDpc(lock);
}

_Requires_lock_held_(*lock) _Releases_lock_(*lock) _IRQL_requires_(DISPATCH_LEVEL) void ebpf_lock_unlock(
    _In_ ebpf_lock_t* lock, _IRQL_restores_ ebpf_lock_state_t state)
{
    KeReleaseSpinLock(lock, state);
}

int32_t
ebpf_interlocked_increment_int32(_Inout_ volatile int32_t* addend)
{
    return InterlockedIncrement((volatile long*)addend);
}

int32_t
ebpf_interlocked_decrement_int32(_Inout_ volatile int32_t* addend)
{
    return InterlockedDecrement((volatile long*)addend);
}

int64_t
ebpf_interlocked_increment_int64(_Inout_ volatile int64_t* addend)
{
    return InterlockedIncrement64(addend);
}

int64_t
ebpf_interlocked_decrement_int64(_Inout_ volatile int64_t* addend)
{
    return InterlockedDecrement64(addend);
}

int32_t
ebpf_interlocked_compare_exchange_int32(_Inout_ volatile int32_t* destination, int32_t exchange, int32_t comperand)
{
    return InterlockedCompareExchange((long volatile*)destination, exchange, comperand);
}

void*
ebpf_interlocked_compare_exchange_pointer(
    _Inout_ void* volatile* destination, _In_opt_ const void* exchange, _In_opt_ const void* comperand)
{
    return InterlockedCompareExchangePointer((void* volatile*)destination, (void*)exchange, (void*)comperand);
}

ebpf_result_t
ebpf_set_current_thread_affinity(uintptr_t new_thread_affinity_mask, _Out_ uintptr_t* old_thread_affinity_mask)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    KAFFINITY old_affinity = KeSetSystemAffinityThreadEx(new_thread_affinity_mask);
    *old_thread_affinity_mask = old_affinity;
    return EBPF_SUCCESS;
}

void
ebpf_restore_current_thread_affinity(uintptr_t old_thread_affinity_mask)
{
    KeRevertToUserAffinityThreadEx(old_thread_affinity_mask);
}

_Ret_range_(>, 0) uint32_t ebpf_get_cpu_count() { return KeQueryMaximumProcessorCount(); }

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
    return KeGetCurrentProcessorNumber();
}

uint64_t
ebpf_get_current_thread_id()
{
    return (uint64_t)KeGetCurrentThread();
}

typedef struct _ebpf_non_preemptible_work_item
{
    KDPC deferred_procedure_call;
    void (*work_item_routine)(void* work_item_context, void* parameter_1);
} ebpf_non_preemptible_work_item_t;

static void
_ebpf_deferred_routine(
    KDPC* deferred_procedure_call, PVOID deferred_context, PVOID system_argument_1, PVOID system_argument_2)
{
    ebpf_non_preemptible_work_item_t* deferred_routine_context =
        (ebpf_non_preemptible_work_item_t*)deferred_procedure_call;
    UNREFERENCED_PARAMETER(system_argument_2);
    deferred_routine_context->work_item_routine(deferred_context, system_argument_1);
}

ebpf_result_t
ebpf_allocate_non_preemptible_work_item(
    _Out_ ebpf_non_preemptible_work_item_t** work_item,
    uint32_t cpu_id,
    _In_ void (*work_item_routine)(void* work_item_context, void* parameter_1),
    _In_opt_ void* work_item_context)
{
    *work_item = ebpf_allocate(sizeof(ebpf_non_preemptible_work_item_t));
    if (*work_item == NULL) {
        return EBPF_NO_MEMORY;
    }

    (*work_item)->work_item_routine = work_item_routine;

    KeInitializeDpc(&(*work_item)->deferred_procedure_call, _ebpf_deferred_routine, work_item_context);
    KeSetTargetProcessorDpc(&(*work_item)->deferred_procedure_call, (uint8_t)cpu_id);
    return EBPF_SUCCESS;
}

void
ebpf_free_non_preemptible_work_item(_Frees_ptr_opt_ ebpf_non_preemptible_work_item_t* work_item)
{
    if (!work_item)
        return;

    KeRemoveQueueDpc(&work_item->deferred_procedure_call);
    ebpf_free(work_item);
}

bool
ebpf_queue_non_preemptible_work_item(_In_ ebpf_non_preemptible_work_item_t* work_item, _In_opt_ void* parameter_1)
{
    return KeInsertQueueDpc(&work_item->deferred_procedure_call, parameter_1, NULL);
}

typedef struct _ebpf_timer_work_item
{
    KDPC deferred_procedure_call;
    KTIMER timer;
    void (*work_item_routine)(void* work_item_context);
    void* work_item_context;
} ebpf_timer_work_item_t;

static void
_ebpf_timer_routine(
    KDPC* deferred_procedure_call, PVOID deferred_context, PVOID system_argument_1, PVOID system_argument_2)
{
    ebpf_timer_work_item_t* timer_work_item = (ebpf_timer_work_item_t*)deferred_procedure_call;
    UNREFERENCED_PARAMETER(system_argument_1);
    UNREFERENCED_PARAMETER(system_argument_2);
    timer_work_item->work_item_routine(deferred_context);
}

ebpf_result_t
ebpf_allocate_timer_work_item(
    _Out_ ebpf_timer_work_item_t** timer_work_item,
    _In_ void (*work_item_routine)(void* work_item_context),
    _In_opt_ void* work_item_context)
{
    *timer_work_item = ebpf_allocate(sizeof(ebpf_timer_work_item_t));
    if (*timer_work_item == NULL)
        return EBPF_NO_MEMORY;

    (*timer_work_item)->work_item_routine = work_item_routine;
    (*timer_work_item)->work_item_context = work_item_context;

    KeInitializeTimer(&(*timer_work_item)->timer);
    KeInitializeDpc(&(*timer_work_item)->deferred_procedure_call, _ebpf_timer_routine, work_item_context);

    return EBPF_SUCCESS;
}

#define MICROSECONDS_PER_TICK 10
#define MICROSECONDS_PER_MILLISECOND 1000

void
ebpf_schedule_timer_work_item(_In_ ebpf_timer_work_item_t* work_item, uint32_t elapsed_microseconds)
{
    LARGE_INTEGER due_time;
    due_time.QuadPart = -((int64_t)elapsed_microseconds * MICROSECONDS_PER_TICK);

    KeSetTimer(&work_item->timer, due_time, &work_item->deferred_procedure_call);
}

void
ebpf_free_timer_work_item(_Frees_ptr_opt_ ebpf_timer_work_item_t* work_item)
{
    if (!work_item)
        return;

    KeCancelTimer(&work_item->timer);
    KeRemoveQueueDpc(&work_item->deferred_procedure_call);
    ebpf_free(work_item);
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

ebpf_result_t
ebpf_access_check(
    _In_ ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    _In_ ebpf_security_generic_mapping_t* generic_mapping)
{
    ebpf_result_t result;
    NTSTATUS status;
    SECURITY_SUBJECT_CONTEXT subject_context = {0};
    DWORD granted_access;

    SeCaptureSubjectContext(&subject_context);
    SeLockSubjectContext(&subject_context);
    if (!SeAccessCheck(
            security_descriptor,
            &subject_context,
            true,
            request_access,
            0,
            NULL,
            generic_mapping,
            KernelMode,
            &granted_access,
            &status)) {
        result = EBPF_ACCESS_DENIED;
    } else {
        result = NT_SUCCESS(status) ? EBPF_SUCCESS : EBPF_ACCESS_DENIED;
    }

    SeUnlockSubjectContext(&subject_context);
    return result;
}

ebpf_result_t
ebpf_validate_security_descriptor(
    _In_ ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
{
    ebpf_result_t result;
    if ((security_descriptor->Control & SE_SELF_RELATIVE) == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (!RtlValidRelativeSecurityDescriptor(
            security_descriptor,
            (ULONG)security_descriptor_length,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = EBPF_SUCCESS;

Done:
    return result;
}

uint32_t
ebpf_random_uint32()
{
    LARGE_INTEGER p = KeQueryPerformanceCounter(NULL);
    ULONG seed = p.LowPart ^ (DWORD)p.HighPart;
    return RtlRandomEx(&seed);
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

ebpf_result_t
ebpf_guid_create(_Out_ GUID* new_guid)
{
    if (NT_SUCCESS(ExUuidCreate(new_guid)))
        return EBPF_SUCCESS;
    else
        return EBPF_OPERATION_NOT_SUPPORTED;
}
