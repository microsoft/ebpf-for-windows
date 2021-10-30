// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include <intsafe.h>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <stdbool.h>
#include <stdint.h>
#include <vector>
#include <TraceLoggingProvider.h>

// Global variables used to override behavior for testing.
// Permit the test to simulate both Hyper-V Code Integrity.
bool _ebpf_platform_code_integrity_enabled = false;
// Permit the test to simulate non-preemptible execution.
bool _ebpf_platform_is_preemptible = true;

ebpf_result_t
ebpf_platform_initiate()
{
    return EBPF_SUCCESS;
}

void
ebpf_platform_terminate()
{}

ebpf_result_t
ebpf_get_code_integrity_state(_Out_ ebpf_code_integrity_state_t* state)
{
    EBPF_LOG_ENTRY();
    if (_ebpf_platform_code_integrity_enabled) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity enabled");
        *state = EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE;
    } else {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity disabled");
        *state = EBPF_CODE_INTEGRITY_DEFAULT;
    }
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(size) void* ebpf_allocate(size_t size)
{
    void* memory;
    memory = calloc(size, 1);
    if (memory != nullptr)
        memset(memory, 0, size);

    return memory;
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(new_size) void* ebpf_reallocate(_In_ void* memory, size_t old_size, size_t new_size)
{
    UNREFERENCED_PARAMETER(old_size);
    void* p = realloc(memory, new_size);
    if (p && (new_size > old_size))
        memset(((char*)p) + old_size, 0, new_size - old_size);
    return p;
}

void
ebpf_free(_Frees_ptr_opt_ void* memory)
{
    free(memory);
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
    _Post_writable_byte_size_(size) void* ebpf_allocate_cache_aligned(size_t size)
{
    void* memory = _aligned_malloc(size, EBPF_CACHE_LINE_SIZE);
    if (memory) {
        memset(memory, 0, size);
    }
    return memory;
}

void
ebpf_free_cache_aligned(_Frees_ptr_opt_ void* memory)
{
    _aligned_free(memory);
}

struct _ebpf_memory_descriptor
{
    void* base;
    size_t length;
};
typedef struct _ebpf_memory_descriptor ebpf_memory_descriptor_t;

struct _ebpf_ring_descriptor
{
    void* primary_view;
    void* secondary_view;
    size_t length;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

ebpf_memory_descriptor_t*
ebpf_map_memory(size_t length)
{
    ebpf_memory_descriptor_t* descriptor = (ebpf_memory_descriptor_t*)malloc(sizeof(ebpf_memory_descriptor_t));
    if (!descriptor) {
        return nullptr;
    }

    descriptor->base = VirtualAlloc(0, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    descriptor->length = length;

    if (!descriptor->base) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualAlloc);
        free(descriptor);
        descriptor = nullptr;
    }
    return descriptor;
}

void
ebpf_unmap_memory(_Frees_ptr_opt_ ebpf_memory_descriptor_t* memory_descriptor)
{
    if (memory_descriptor) {
        if (!VirtualFree(memory_descriptor->base, 0, MEM_RELEASE)) {
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualFree);
        }
        free(memory_descriptor);
    }
}

// This code is derived from the sample at:
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    bool result = false;
    HANDLE section = nullptr;
    SYSTEM_INFO sysInfo;
    uint8_t* placeholder1 = nullptr;
    uint8_t* placeholder2 = nullptr;
    void* view1 = nullptr;
    void* view2 = nullptr;

    GetSystemInfo(&sysInfo);

    if (length == 0) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Ring buffer length is zero");
        return nullptr;
    }

    if ((length % sysInfo.dwAllocationGranularity) != 0) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        return nullptr;
    }

    ebpf_ring_descriptor_t* descriptor = (ebpf_ring_descriptor_t*)ebpf_allocate(sizeof(ebpf_ring_descriptor_t));
    if (!descriptor) {
        goto Exit;
    }
    descriptor->length = length;

    //
    // Reserve a placeholder region where the buffer will be mapped.
    //
    placeholder1 = reinterpret_cast<uint8_t*>(
        VirtualAlloc2(nullptr, nullptr, 2 * length, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0));

    if (placeholder1 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualAlloc2);
        goto Exit;
    }

#pragma warning(push)
#pragma warning(disable : 6333)  // Invalid parameter:  passing MEM_RELEASE and a non-zero dwSize parameter to
                                 // 'VirtualFree' is not allowed.  This causes the call to fail.
#pragma warning(disable : 28160) // Passing MEM_RELEASE and a non-zero dwSize parameter to VirtualFree is not allowed.
                                 // This results in the failure of this call.
    //
    // Split the placeholder region into two regions of equal size.
    //
    result = VirtualFree(placeholder1, length, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    if (result == FALSE) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualFree);
        goto Exit;
    }
#pragma warning(pop)
    placeholder2 = placeholder1 + length;

    //
    // Create a pagefile-backed section for the buffer.
    //

    section = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<DWORD>(length), nullptr);
    if (section == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, CreateFileMapping);
        goto Exit;
    }

    //
    // Map the section into the first placeholder region.
    //
    view1 =
        MapViewOfFile3(section, nullptr, placeholder1, 0, length, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view1 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile3);
        goto Exit;
    }

    //
    // Ownership transferred, don't free this now.
    //
    placeholder1 = nullptr;

    //
    // Map the section into the second placeholder region.
    //
    view2 =
        MapViewOfFile3(section, nullptr, placeholder2, 0, length, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view2 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile3);
        goto Exit;
    }

    result = true;

    //
    // Success, return both mapped views to the caller.
    //
    descriptor->primary_view = view1;
    descriptor->secondary_view = view2;

    placeholder2 = nullptr;
    view1 = nullptr;
    view2 = nullptr;
Exit:
    if (!result) {
        ebpf_free(descriptor);
        descriptor = nullptr;
    }

    if (section != nullptr) {
        CloseHandle(section);
    }

    if (placeholder1 != nullptr) {
        VirtualFree(placeholder1, 0, MEM_RELEASE);
    }

    if (placeholder2 != nullptr) {
        VirtualFree(placeholder2, 0, MEM_RELEASE);
    }

    if (view1 != nullptr) {
        UnmapViewOfFileEx(view1, 0);
    }

    if (view2 != nullptr) {
        UnmapViewOfFileEx(view2, 0);
    }

    EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, descriptor);
}

void
ebpf_free_ring_buffer_memory(_Frees_ptr_opt_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    if (ring) {
        UnmapViewOfFile(ring->primary_view);
        UnmapViewOfFile(ring->secondary_view);
        ebpf_free(ring);
    }
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_base_address(_In_ ebpf_ring_descriptor_t* ring_descriptor)
{
    return ring_descriptor->primary_view;
}

_Ret_maybenull_ void*
ebpf_ring_map_readonly_user(_In_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_POINTER(void*, ebpf_ring_descriptor_get_base_address(ring));
}

ebpf_result_t
ebpf_protect_memory(_In_ const ebpf_memory_descriptor_t* memory_descriptor, ebpf_page_protection_t protection)
{
    EBPF_LOG_ENTRY();
    ULONG mm_protection_state = 0;
    ULONG old_mm_protection_state = 0;
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

    if (!VirtualProtect(
            memory_descriptor->base, memory_descriptor->length, mm_protection_state, &old_mm_protection_state)) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualProtect);
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

void*
ebpf_memory_descriptor_get_base_address(ebpf_memory_descriptor_t* memory_descriptor)
{
    return memory_descriptor->base;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_multiply(
    size_t multiplicand, size_t multiplier, _Out_ _Deref_out_range_(==, multiplicand* multiplier) size_t* result)
{
    return SUCCEEDED(SizeTMult(multiplicand, multiplier, result)) ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_add(size_t augend, size_t addend, _Out_ _Deref_out_range_(==, augend + addend) size_t* result)
{
    return SUCCEEDED(SizeTAdd(augend, addend, result)) ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_subtract(
    size_t minuend, size_t subtrahend, _Out_ _Deref_out_range_(==, minuend - subtrahend) size_t* result)
{
    return SUCCEEDED(SizeTSub(minuend, subtrahend, result)) ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

void
ebpf_lock_create(_Out_ ebpf_lock_t* lock)
{
    InitializeSRWLock(reinterpret_cast<PSRWLOCK>(lock));
}

void
ebpf_lock_destroy(_In_ ebpf_lock_t* lock)
{
    UNREFERENCED_PARAMETER(lock);
}

_Requires_lock_not_held_(*lock) _Acquires_lock_(*lock) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) ebpf_lock_state_t ebpf_lock_lock(_In_ ebpf_lock_t* lock)
{
    AcquireSRWLockExclusive(reinterpret_cast<PSRWLOCK>(lock));
    return 0;
}

_Requires_lock_held_(*lock) _Releases_lock_(*lock) _IRQL_requires_(DISPATCH_LEVEL) void ebpf_lock_unlock(
    _In_ ebpf_lock_t* lock, _IRQL_restores_ ebpf_lock_state_t state)
{
    UNREFERENCED_PARAMETER(state);
    ReleaseSRWLockExclusive(reinterpret_cast<PSRWLOCK>(lock));
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

uint32_t
ebpf_random_uint32()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    return mt();
}

uint64_t
ebpf_query_time_since_boot(bool include_suspended_time)
{
    uint64_t interrupt_time;
    if (include_suspended_time) {
        // QueryUnbiasedInterruptTimePrecise returns A pointer to a ULONGLONG in which to receive the interrupt-time
        // count in system time units of 100 nanoseconds.
        // Unbiased Interrupt time is the total time since boot including time spent suspended.
        // https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttimeprecise.
        QueryUnbiasedInterruptTimePrecise(&interrupt_time);
    } else {
        // QueryInterruptTimePrecise returns A pointer to a ULONGLONG in which to receive the interrupt-time count in
        // system time units of 100 nanoseconds.
        // (Biased) Interrupt time is the total time since boot excluding time spent suspended.
        // https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise.
        QueryInterruptTimePrecise(&interrupt_time);
    }

    return interrupt_time;
}

ebpf_result_t
ebpf_set_current_thread_affinity(uintptr_t new_thread_affinity_mask, _Out_ uintptr_t* old_thread_affinity_mask)
{
    uintptr_t old_mask = SetThreadAffinityMask(GetCurrentThread(), new_thread_affinity_mask);
    if (old_mask == 0) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    } else {
        *old_thread_affinity_mask = old_mask;
        return EBPF_SUCCESS;
    }
}

void
ebpf_restore_current_thread_affinity(uintptr_t old_thread_affinity_mask)
{
    SetThreadAffinityMask(GetCurrentThread(), old_thread_affinity_mask);
}

_Ret_range_(>, 0) uint32_t ebpf_get_cpu_count()
{
    SYSTEM_INFO system_info;
    GetNativeSystemInfo(&system_info);
    return system_info.dwNumberOfProcessors;
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
    _Out_ ebpf_non_preemptible_work_item_t** work_item,
    uint32_t cpu_id,
    _In_ void (*work_item_routine)(void* work_item_context, void* parameter_1),
    _In_opt_ void* work_item_context)
{
    UNREFERENCED_PARAMETER(work_item);
    UNREFERENCED_PARAMETER(cpu_id);
    UNREFERENCED_PARAMETER(work_item_routine);
    UNREFERENCED_PARAMETER(work_item_context);
    return EBPF_OPERATION_NOT_SUPPORTED;
}

void
ebpf_free_non_preemptible_work_item(_Frees_ptr_opt_ ebpf_non_preemptible_work_item_t* work_item)
{
    UNREFERENCED_PARAMETER(work_item);
}

bool
ebpf_queue_non_preemptible_work_item(_In_ ebpf_non_preemptible_work_item_t* work_item, _In_opt_ void* parameter_1)
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
_ebpf_timer_callback(_Inout_ TP_CALLBACK_INSTANCE* instance, _Inout_opt_ void* context, _Inout_ TP_TIMER* timer)
{
    ebpf_timer_work_item_t* timer_work_item = reinterpret_cast<ebpf_timer_work_item_t*>(context);
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(timer);
    if (timer_work_item)
        timer_work_item->work_item_routine(timer_work_item->work_item_context);
}

ebpf_result_t
ebpf_allocate_timer_work_item(
    _Out_ ebpf_timer_work_item_t** work_item,
    _In_ void (*work_item_routine)(void* work_item_context),
    _In_opt_ void* work_item_context)
{
    *work_item = (ebpf_timer_work_item_t*)ebpf_allocate(sizeof(ebpf_timer_work_item_t));

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
ebpf_schedule_timer_work_item(_In_ ebpf_timer_work_item_t* timer, uint32_t elapsed_microseconds)
{
    int64_t due_time;
    due_time = -static_cast<int64_t>(elapsed_microseconds) * MICROSECONDS_PER_TICK;

    SetThreadpoolTimer(
        timer->threadpool_timer,
        reinterpret_cast<FILETIME*>(&due_time),
        0,
        elapsed_microseconds / MICROSECONDS_PER_MILLISECOND);
}

void
ebpf_free_timer_work_item(_Frees_ptr_opt_ ebpf_timer_work_item_t* work_item)
{
    if (!work_item)
        return;

    WaitForThreadpoolTimerCallbacks(work_item->threadpool_timer, true);
    CloseThreadpoolTimer(work_item->threadpool_timer);
    ebpf_free(work_item);
}

ebpf_result_t
ebpf_guid_create(_Out_ GUID* new_guid)
{
    if (UuidCreate(new_guid) == RPC_S_OK)
        return EBPF_SUCCESS;
    else
        return EBPF_OPERATION_NOT_SUPPORTED;
}

int32_t
ebpf_log_function(_In_ void* context, _In_z_ const char* format_string, ...)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(format_string);
    return 0;
}

ebpf_result_t
ebpf_access_check(
    _In_ ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    _In_ ebpf_security_generic_mapping_t* generic_mapping)
{
    ebpf_result_t result;
    HANDLE token = INVALID_HANDLE_VALUE;
    BOOL access_status = FALSE;
    DWORD granted_access;
    PRIVILEGE_SET privilege_set;
    DWORD privilege_set_size = sizeof(privilege_set);
    bool is_impersonating = false;

    if (!ImpersonateSelf(SecurityImpersonation)) {
        result = EBPF_ACCESS_DENIED;
        goto Done;
    }
    is_impersonating = true;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        result = EBPF_ACCESS_DENIED;
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
        result = EBPF_ACCESS_DENIED;
    } else {
        result = access_status ? EBPF_SUCCESS : EBPF_ACCESS_DENIED;
    }

Done:
    if (token != INVALID_HANDLE_VALUE)
        CloseHandle(token);

    if (is_impersonating)
        RevertToSelf();
    return result;
}

ebpf_result_t
ebpf_validate_security_descriptor(
    _In_ ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
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

uint32_t
ebpf_result_to_win32_error_code(ebpf_result_t result)
{
    static uint32_t (*RtlNtStatusToDosError)(NTSTATUS Status) = NULL;
    if (!RtlNtStatusToDosError) {
        HMODULE ntdll = LoadLibrary(L"ntdll.dll");
        if (!ntdll) {
            return ERROR_OUTOFMEMORY;
        }
        RtlNtStatusToDosError =
            reinterpret_cast<decltype(RtlNtStatusToDosError)>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    }
    return RtlNtStatusToDosError(ebpf_result_to_ntstatus(result));
}
