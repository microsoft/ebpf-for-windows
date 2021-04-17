/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_platform.h"
#include <map>
#include <mutex>
#include <set>
#include <stdbool.h>
#include <stdint.h>
#include <vector>

std::set<uint64_t> _executable_segments;

bool _ebpf_platform_code_integrity_enabled = false;

void (*RtlInitializeGenericTableAvl)(
    _Out_ PRTL_AVL_TABLE Table,
    _In_ PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
    _In_ PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
    _In_ PRTL_AVL_FREE_ROUTINE FreeRoutine,
    _In_opt_ PVOID TableContext);

void* (*RtlEnumerateGenericTableAvl)(_In_ PRTL_AVL_TABLE Table, _In_ BOOLEAN Restart);

BOOLEAN (*RtlDeleteElementGenericTableAvl)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

void* (*RtlLookupElementGenericTableAvl)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

void* (*RtlInsertElementGenericTableAvl)(
    _In_ PRTL_AVL_TABLE Table,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ const uint32_t BufferSize,
    _Out_opt_ PBOOLEAN NewElement);

PVOID(*RtlLookupFirstMatchingElementGenericTableAvl)
(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer, _Out_ PVOID* RestartKey);

template <typename fn>
bool
resolve_function(HMODULE module_handle, fn& function, const char* function_name)
{
    function = reinterpret_cast<fn>(GetProcAddress(module_handle, function_name));
    return (function != nullptr);
}

ebpf_error_code_t
ebpf_platform_initialize()
{
    HMODULE ntdll_module = nullptr;

    ntdll_module = LoadLibrary(L"ntdll.dll");
    if (ntdll_module == nullptr) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }

    if (!resolve_function(ntdll_module, RtlInitializeGenericTableAvl, "RtlInitializeGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
    if (!resolve_function(ntdll_module, RtlEnumerateGenericTableAvl, "RtlEnumerateGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
    if (!resolve_function(ntdll_module, RtlDeleteElementGenericTableAvl, "RtlDeleteElementGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
    if (!resolve_function(ntdll_module, RtlLookupElementGenericTableAvl, "RtlLookupElementGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
    if (!resolve_function(ntdll_module, RtlEnumerateGenericTableAvl, "RtlEnumerateGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
    if (!resolve_function(
            ntdll_module,
            RtlLookupFirstMatchingElementGenericTableAvl,
            "RtlLookupFirstMatchingElementGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }
    if (!resolve_function(ntdll_module, RtlInsertElementGenericTableAvl, "RtlInsertElementGenericTableAvl")) {
        return EBPF_ERROR_NOT_SUPPORTED;
    }

    // Note: This is safe because ntdll is never unloaded becuase
    // ntdll.dll houses the module loader, which cannot unload itself.
    FreeLibrary(ntdll_module);
    return EBPF_ERROR_SUCCESS;
}

void
ebpf_platform_terminate()
{}

ebpf_error_code_t
ebpf_query_code_integrity_state(ebpf_code_integrity_state_t* state)
{
    if (_ebpf_platform_code_integrity_enabled) {
        *state = EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE;
    } else {
        *state = EBPF_CODE_INTEGRITY_DEFAULT;
    }
    return EBPF_ERROR_SUCCESS;
}

void*
ebpf_allocate(size_t size, ebpf_memory_type_t type)
{
    void* memory;
    if (type == EBPF_MEMORY_EXECUTE) {
        memory = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (memory) {
            _executable_segments.insert({reinterpret_cast<uint64_t>(memory)});
        }
        return memory;
    } else {
        return malloc(size);
    }
}

void
ebpf_free(void* memory)
{
    if (_executable_segments.find(reinterpret_cast<uint64_t>(memory)) != _executable_segments.end()) {
        VirtualFree(memory, 0, MEM_RELEASE);
    } else {
        free(memory);
    }
}

ebpf_error_code_t
ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result)
{
    *result = multiplicand * multiplier;
    return EBPF_ERROR_SUCCESS;
}

ebpf_error_code_t
ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result)
{
    *result = augend + addend;
    return EBPF_ERROR_SUCCESS;
}

void
ebpf_lock_create(ebpf_lock_t* lock)
{
    InitializeSRWLock(reinterpret_cast<PSRWLOCK>(lock));
}

void
ebpf_lock_destroy(ebpf_lock_t* lock)
{
    UNREFERENCED_PARAMETER(lock);
}

void
ebpf_lock_lock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    UNREFERENCED_PARAMETER(state);
    AcquireSRWLockExclusive(reinterpret_cast<PSRWLOCK>(lock));
}

void
ebpf_lock_unlock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    UNREFERENCED_PARAMETER(state);
    ReleaseSRWLockExclusive(reinterpret_cast<PSRWLOCK>(lock));
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