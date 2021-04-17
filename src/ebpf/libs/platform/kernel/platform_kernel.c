/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_platform.h"

typedef enum _ebpf_pool_tag
{
    EBPF_POOL_TAG = 'fpbe'
} ebpf_pool_tag_t;

ebpf_error_code_t
ebpf_platform_initialize()
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
ebpf_query_code_integrity_state(ebpf_code_integrity_state_t* state)
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
        return EBPF_ERROR_INVALID_PARAMETER;
    }
}

ebpf_error_code_t
ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result)
{
    return RtlSizeTMult(multiplicand, multiplier, result) == STATUS_SUCCESS ? EBPF_ERROR_SUCCESS
                                                                            : EBPF_ERROR_INVALID_PARAMETER;
}

ebpf_error_code_t
ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result)
{
    return RtlSizeTAdd(augend, addend, result) == STATUS_SUCCESS ? EBPF_ERROR_SUCCESS : EBPF_ERROR_INVALID_PARAMETER;
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
ebpf_interlocked_increment(volatile int32_t* addend)
{
    return InterlockedIncrement((volatile LONG*)addend);
}

int32_t
ebpf_interlocked_decrement(volatile int32_t* addend)
{
    return InterlockedDecrement((volatile LONG*)addend);
}