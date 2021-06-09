/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
// ntifs.h needs to be included ahead of other headers to satisfy the Windows
// build system.
#include <ntifs.h>

#include "ebpf_platform.h"

#include <ntstrsafe.h>

typedef struct _ebpf_memory_descriptor
{
    MDL memory_descriptor_list;
} ebpf_memory_descriptor_t;

typedef enum _ebpf_pool_tag
{
    EBPF_POOL_TAG = 'fpbe'
} ebpf_pool_tag_t;

ebpf_result_t
ebpf_platform_initiate()
{
    return EBPF_SUCCESS;
}

void
ebpf_platform_terminate()
{}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(size) void* ebpf_allocate(size_t size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, EBPF_POOL_TAG);
}

void
ebpf_free(_Pre_maybenull_ _Post_invalid_ __drv_freesMem(Mem) void* memory)
{
    if (memory)
        ExFreePool(memory);
}

ebpf_memory_descriptor_t*
ebpf_map_memory(size_t length)
{
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
        MmMapLockedPagesSpecifyCache(memory_descriptor_list, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    }
    return (ebpf_memory_descriptor_t*)memory_descriptor_list;
}

void
ebpf_unmap_memory(_Pre_maybenull_ _Post_invalid_ ebpf_memory_descriptor_t* memory_descriptor)
{
    if (!memory_descriptor)
        return;

    MmUnmapLockedPages(
        ebpf_memory_descriptor_get_base_address(memory_descriptor), &memory_descriptor->memory_descriptor_list);
    MmFreePagesFromMdl(&memory_descriptor->memory_descriptor_list);
    ExFreePool(memory_descriptor);
}

ebpf_result_t
ebpf_protect_memory(_In_ const ebpf_memory_descriptor_t* memory_descriptor, ebpf_page_protection_t protection)
{
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
        return EBPF_INVALID_ARGUMENT;
    }

    status = MmProtectMdlSystemAddress((MDL*)&memory_descriptor->memory_descriptor_list, mm_protection_state);
    if (!NT_SUCCESS(status))
        return EBPF_INVALID_ARGUMENT;

    return EBPF_SUCCESS;
}

void*
ebpf_memory_descriptor_get_base_address(ebpf_memory_descriptor_t* memory_descriptor)
{
    return MmGetSystemAddressForMdlSafe(&memory_descriptor->memory_descriptor_list, NormalPagePriority);
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
        *state = (code_integrity_information.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0
                     ? EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE
                     : EBPF_CODE_INTEGRITY_DEFAULT;
        return EBPF_SUCCESS;
    } else {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
}

ebpf_result_t
ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, _Out_ size_t* result)
{
    return RtlSizeTMult(multiplicand, multiplier, result) == STATUS_SUCCESS ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

ebpf_result_t
ebpf_safe_size_t_add(size_t augend, size_t addend, _Out_ size_t* result)
{
    return RtlSizeTAdd(augend, addend, result) == STATUS_SUCCESS ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

ebpf_result_t
ebpf_safe_size_t_subtract(size_t minuend, size_t subtrahend, _Out_ size_t* result)
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

void
ebpf_get_cpu_count(_Out_ uint32_t* cpu_count)
{
    *cpu_count = KeQueryMaximumProcessorCount();
}

bool
ebpf_is_preemptible()
{
    KIRQL irql = KeGetCurrentIrql();
    return irql >= DISPATCH_LEVEL;
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
ebpf_free_non_preemptible_work_item(_Pre_maybenull_ _Post_invalid_ ebpf_non_preemptible_work_item_t* work_item)
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
    KTIMER timer;
    KDPC deferred_procedure_call;
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
ebpf_free_timer_work_item(_Pre_maybenull_ _Post_invalid_ ebpf_timer_work_item_t* work_item)
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
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "eBPF: context: %s\n", buffer));
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
