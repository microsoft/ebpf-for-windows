/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_platform.h"
#include <intsafe.h>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <stdbool.h>
#include <stdint.h>
#include <vector>

std::set<uint64_t> _executable_segments;

// Global variables used to override behavior for testing.
// Permit the test to simulate both Hyper-V Code Integrity.
bool _ebpf_platform_code_integrity_enabled = false;
// Permit the test to simulate non-preemptible execution.
bool _ebpf_platform_is_preemptible = true;

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

ebpf_result_t
ebpf_platform_initiate()
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
    return EBPF_SUCCESS;
}

void
ebpf_platform_terminate()
{}

ebpf_result_t
ebpf_get_code_integrity_state(ebpf_code_integrity_state_t* state)
{
    if (_ebpf_platform_code_integrity_enabled) {
        *state = EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE;
    } else {
        *state = EBPF_CODE_INTEGRITY_DEFAULT;
    }
    return EBPF_SUCCESS;
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

ebpf_result_t
ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result)
{
    return SUCCEEDED(SizeTMult(multiplicand, multiplier, result)) ? EBPF_SUCCESS : EBPF_ERROR_ARITHMETIC_OVERFLOW;
}

ebpf_result_t
ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result)
{
    return SUCCEEDED(SizeTAdd(augend, addend, result)) ? EBPF_SUCCESS : EBPF_ERROR_ARITHMETIC_OVERFLOW;
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
    SYSTEM_INFO system_information;
    GetNativeSystemInfo(&system_information);
    *cpu_count = system_information.dwNumberOfProcessors;
}

bool
ebpf_is_preemptible()
{
    return _ebpf_platform_is_preemptible;
}

bool
ebpf_is_non_preemptible_work_item_supported()
{
    return false;
}

uint32_t
ebpf_get_current_cpu()
{
    return GetCurrentProcessorNumber();
}

uint64_t
ebpf_get_current_thread_id()
{
    return GetCurrentThreadId();
}

ebpf_result_t
ebpf_allocate_non_preemptible_work_item(
    ebpf_non_preemptible_work_item_t** work_item,
    uint32_t cpu_id,
    void (*work_item_routine)(void* work_item_context, void* parameter_1),
    void* work_item_context)
{
    UNREFERENCED_PARAMETER(work_item);
    UNREFERENCED_PARAMETER(cpu_id);
    UNREFERENCED_PARAMETER(work_item_routine);
    UNREFERENCED_PARAMETER(work_item_context);
    return EBPF_ERROR_NOT_SUPPORTED;
}

void
ebpf_free_non_preemptible_work_item(ebpf_non_preemptible_work_item_t* work_item)
{
    UNREFERENCED_PARAMETER(work_item);
}

bool
ebpf_queue_non_preemptible_work_item(ebpf_non_preemptible_work_item_t* work_item, void* parameter_1)
{
    UNREFERENCED_PARAMETER(work_item);
    UNREFERENCED_PARAMETER(parameter_1);
    return false;
}

typedef struct _ebpf_timer_work_item
{
    TP_TIMER* threadpool_timer;
    void (*work_item_routine)(void* work_item_context);
    void* work_item_context;
} ebpf_timer_work_item_t;

void
_ebpf_timer_callback(_Inout_ TP_CALLBACK_INSTANCE* instance, _Inout_opt_ void* Context, _Inout_ TP_TIMER* Timer)
{
    ebpf_timer_work_item_t* timer_work_item = reinterpret_cast<ebpf_timer_work_item_t*>(Context);
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(Timer);

    timer_work_item->work_item_routine(timer_work_item->work_item_context);
}

ebpf_result_t
ebpf_allocate_timer_work_item(
    ebpf_timer_work_item_t** work_item, void (*work_item_routine)(void* work_item_context), void* work_item_context)
{
    *work_item = (ebpf_timer_work_item_t*)ebpf_allocate(sizeof(ebpf_timer_work_item_t), EBPF_MEMORY_NO_EXECUTE);

    if (*work_item == NULL)
        goto Error;

    (*work_item)->threadpool_timer = CreateThreadpoolTimer(_ebpf_timer_callback, *work_item, NULL);
    if ((*work_item)->threadpool_timer == NULL)
        goto Error;

    (*work_item)->work_item_routine = work_item_routine;
    (*work_item)->work_item_context = work_item_context;

    return EBPF_SUCCESS;

Error:
    if (*work_item != NULL) {
        if ((*work_item)->threadpool_timer != NULL)
            CloseThreadpoolTimer((*work_item)->threadpool_timer);

        ebpf_free(*work_item);
    }
    return EBPF_NO_MEMORY;
}

#define MICROSECONDS_PER_TICK 10
#define MICROSECONDS_PER_MILLISECOND 1000

void
ebpf_schedule_timer_work_item(ebpf_timer_work_item_t* work_item, uint32_t elapsed_microseconds)
{
    int64_t due_time;
    due_time = -static_cast<int64_t>(elapsed_microseconds) * MICROSECONDS_PER_TICK;

    SetThreadpoolTimer(
        work_item->threadpool_timer,
        reinterpret_cast<FILETIME*>(&due_time),
        0,
        elapsed_microseconds / MICROSECONDS_PER_MILLISECOND);
}

void
ebpf_free_timer_work_item(ebpf_timer_work_item_t* work_item)
{
    WaitForThreadpoolTimerCallbacks(work_item->threadpool_timer, true);
    CloseThreadpoolTimer(work_item->threadpool_timer);
    ebpf_free(work_item);
}

ebpf_result_t
ebpf_guid_create(GUID* new_guid)
{
    UuidCreate(new_guid);
    return EBPF_SUCCESS;
}

int32_t
ebpf_log_function(void* context, const char* format_string, ...)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(format_string);
    return 0;
}

ebpf_result_t
ebpf_access_check(
    ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    ebpf_security_generic_mapping_t* generic_mapping)
{
    ebpf_result_t result;
    HANDLE token = INVALID_HANDLE_VALUE;
    BOOL access_status = FALSE;
    DWORD granted_access;
    PRIVILEGE_SET privilege_set;
    DWORD privilege_set_size = sizeof(privilege_set);
    bool is_impersonating = false;

    if (!ImpersonateSelf(SecurityImpersonation)) {
        result = EBPF_ERROR_ACCESS_DENIED;
        goto Done;
    }
    is_impersonating = true;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        result = EBPF_ERROR_ACCESS_DENIED;
        goto Done;
    }

    if (!AccessCheck(
            security_descriptor,
            token,
            request_access,
            generic_mapping,
            &privilege_set,
            &privilege_set_size,
            &granted_access,
            &access_status)) {
        DWORD err = GetLastError();
        printf("LastError: %d\n", err);
        result = EBPF_ERROR_ACCESS_DENIED;
    } else {
        result = access_status ? EBPF_SUCCESS : EBPF_ERROR_ACCESS_DENIED;
    }

Done:
    if (token != INVALID_HANDLE_VALUE)
        CloseHandle(token);

    if (is_impersonating)
        RevertToSelf();
    return result;
}

ebpf_result_t
ebpf_validate_security_descriptor(ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
{
    ebpf_result_t result;
    SECURITY_DESCRIPTOR_CONTROL security_descriptor_control;
    DWORD version;
    DWORD length;
    if (!IsValidSecurityDescriptor(security_descriptor)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (!GetSecurityDescriptorControl(security_descriptor, &security_descriptor_control, &version)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if ((security_descriptor_control & SE_SELF_RELATIVE) == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    length = GetSecurityDescriptorLength(security_descriptor);
    if (length != security_descriptor_length) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = EBPF_SUCCESS;

Done:
    return result;
}
