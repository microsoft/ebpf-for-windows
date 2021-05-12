/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_platform.h"

#include <ntifs.h>
#include <ntstrsafe.h>

typedef enum _ebpf_pool_tag
{
    EBPF_POOL_TAG = 'fpbe'
} ebpf_pool_tag_t;

ebpf_error_code_t
ebpf_platform_initiate()
{
    return EBPF_ERROR_SUCCESS;
}

void
ebpf_platform_terminate()
{}

void*
ebpf_allocate(size_t size, ebpf_memory_type_t type)
{
    return ExAllocatePool2(
        type == EBPF_MEMORY_EXECUTE ? POOL_FLAG_NON_PAGED_EXECUTE : POOL_FLAG_NON_PAGED, size, EBPF_POOL_TAG);
}

void
ebpf_free(void* memory)
{
    if (memory)
        ExFreePool(memory);
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

ebpf_error_code_t
ebpf_get_code_integrity_state(ebpf_code_integrity_state_t* state)
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
        return EBPF_ERROR_SUCCESS;
    } else {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
}

ebpf_error_code_t
ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result)
{
    return RtlSizeTMult(multiplicand, multiplier, result) == STATUS_SUCCESS ? EBPF_ERROR_SUCCESS
                                                                            : EBPF_ERROR_ARITHMETIC_OVERFLOW;
}

ebpf_error_code_t
ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result)
{
    return RtlSizeTAdd(augend, addend, result) == STATUS_SUCCESS ? EBPF_ERROR_SUCCESS : EBPF_ERROR_ARITHMETIC_OVERFLOW;
}

void
ebpf_lock_create(ebpf_lock_t* lock)
{
    KeInitializeSpinLock((PKSPIN_LOCK)lock);
}

void
ebpf_lock_destroy(ebpf_lock_t* lock)
{
    UNREFERENCED_PARAMETER(lock);
}

void
ebpf_lock_lock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    KeAcquireSpinLock((PKSPIN_LOCK)lock, (PUCHAR)state);
}

void
ebpf_lock_unlock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    KeReleaseSpinLock((PKSPIN_LOCK)lock, *(KIRQL*)state);
}

int32_t
ebpf_interlocked_increment_int32(volatile int32_t* addend)
{
    return InterlockedIncrement((volatile long*)addend);
}

int32_t
ebpf_interlocked_decrement_int32(volatile int32_t* addend)
{
    return InterlockedDecrement((volatile long*)addend);
}

int64_t
ebpf_interlocked_increment_int64(volatile int64_t* addend)
{
    return InterlockedIncrement64(addend);
}

int64_t
ebpf_interlocked_decrement_int64(volatile int64_t* addend)
{
    return InterlockedDecrement64(addend);
}

int32_t
ebpf_interlocked_compare_exchange_int32(volatile int32_t* destination, int32_t exchange, int32_t comperand)
{
    return InterlockedCompareExchange((long volatile*)destination, exchange, comperand);
}

void
ebpf_get_cpu_count(uint32_t* cpu_count)
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

ebpf_error_code_t
ebpf_allocate_non_preemptible_work_item(
    ebpf_non_preemptible_work_item_t** work_item,
    uint32_t cpu_id,
    void (*work_item_routine)(void* work_item_context, void* parameter_1),
    void* work_item_context)
{
    *work_item = ebpf_allocate(sizeof(ebpf_non_preemptible_work_item_t), EBPF_MEMORY_NO_EXECUTE);
    if (*work_item == NULL) {
        return EBPF_ERROR_OUT_OF_RESOURCES;
    }

    (*work_item)->work_item_routine = work_item_routine;

    KeInitializeDpc(&(*work_item)->deferred_procedure_call, _ebpf_deferred_routine, work_item_context);
    KeSetTargetProcessorDpc(&(*work_item)->deferred_procedure_call, (uint8_t)cpu_id);
    return EBPF_ERROR_SUCCESS;
}

void
ebpf_free_non_preemptible_work_item(ebpf_non_preemptible_work_item_t* work_item)
{
    if (!work_item)
        return;

    KeRemoveQueueDpc(&work_item->deferred_procedure_call);
    ebpf_free(work_item);
}

bool
ebpf_queue_non_preemptible_work_item(ebpf_non_preemptible_work_item_t* work_item, void* parameter_1)
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

ebpf_error_code_t
ebpf_allocate_timer_work_item(
    ebpf_timer_work_item_t** timer_work_item,
    void (*work_item_routine)(void* work_item_context),
    void* work_item_context)
{
    *timer_work_item = ebpf_allocate(sizeof(ebpf_timer_work_item_t), EBPF_MEMORY_NO_EXECUTE);
    if (*timer_work_item == NULL)
        return EBPF_ERROR_OUT_OF_RESOURCES;

    (*timer_work_item)->work_item_routine = work_item_routine;
    (*timer_work_item)->work_item_context = work_item_context;

    KeInitializeTimer(&(*timer_work_item)->timer);
    KeInitializeDpc(&(*timer_work_item)->deferred_procedure_call, _ebpf_timer_routine, work_item_context);

    return EBPF_ERROR_SUCCESS;
}

#define MICROSECONDS_PER_TICK 10
#define MICROSECONDS_PER_MILLISECOND 1000

void
ebpf_schedule_timer_work_item(ebpf_timer_work_item_t* work_item, uint32_t elapsed_microseconds)
{
    LARGE_INTEGER due_time;
    due_time.QuadPart = -((int64_t)elapsed_microseconds * MICROSECONDS_PER_TICK);

    KeSetTimer(&work_item->timer, due_time, &work_item->deferred_procedure_call);
}

void
ebpf_free_timer_work_item(ebpf_timer_work_item_t* work_item)
{
    if (!work_item)
        return;

    KeCancelTimer(&work_item->timer);
    KeRemoveQueueDpc(&work_item->deferred_procedure_call);
    ebpf_free(work_item);
}

int32_t
ebpf_log_function(void* context, const char* format_string, ...)
{
    NTSTATUS status;
    char buffer[80];
    va_list arg_start;
    va_start(arg_start, format_string);

    UNREFERENCED_PARAMETER(context);

    status = RtlStringCchVPrintfA(buffer, sizeof(buffer), format_string, arg_start);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "eBPF: context: %s\n", buffer));
    }

    va_end(arg_start);
    return 0;
}

ebpf_error_code_t
ebpf_access_check(
    ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    ebpf_security_generic_mapping_t* generic_mapping)
{
    ebpf_error_code_t result;
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
            &status))
        result = EBPF_ERROR_ACCESS_DENIED;
    else {
        result = NT_SUCCESS(status) ? EBPF_ERROR_SUCCESS : EBPF_ERROR_ACCESS_DENIED;
    }

    SeUnlockSubjectContext(&subject_context);
    return result;
}

ebpf_error_code_t
ebpf_validate_security_descriptor(ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
{
    ebpf_error_code_t result;
    if ((security_descriptor->Control & SE_SELF_RELATIVE) == 0) {
        result = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (!RtlValidRelativeSecurityDescriptor(
            security_descriptor,
            security_descriptor_length,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)) {
        result = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    result = EBPF_ERROR_SUCCESS;

Done:
    return result;
}