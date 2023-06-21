// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "..\..\external\usersim\src\platform.h"
#include "ebpf_tracelog.h"
#include "ebpf_utilities.h"

#include <TraceLoggingProvider.h>
#include <functional>
#include <intsafe.h>
#include <map>
#include <mutex>
#include <queue>
#include <random>
#include <set>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <vector>

// Global variables used to override behavior for testing.
// Permit the test to simulate both Hyper-V Code Integrity.
bool _ebpf_platform_code_integrity_enabled = false;

extern "C" size_t ebpf_fuzzing_memory_limit = MAXSIZE_T;

_Must_inspect_result_ ebpf_result_t
ebpf_platform_initiate()
{
    return NT_SUCCESS(usersim_platform_initiate()) ? EBPF_SUCCESS : EBPF_NO_MEMORY;
}

void
ebpf_platform_terminate()
{
    usersim_platform_terminate();
}

_Must_inspect_result_ ebpf_result_t
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

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate(
    _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size)
{
    return usersim_reallocate(memory, old_size, new_size);
}

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned(size_t size)
{
    return usersim_allocate_cache_aligned(size);
}

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned_with_tag(size_t size, uint32_t tag)
{
    UNREFERENCED_PARAMETER(tag);

    return ebpf_allocate_cache_aligned(size);
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
    // Skip fault injection for this VirtualAlloc OS API, as ebpf_allocate already does that.
    ebpf_memory_descriptor_t* descriptor = (ebpf_memory_descriptor_t*)ebpf_allocate(sizeof(ebpf_memory_descriptor_t));
    if (!descriptor) {
        return nullptr;
    }

    descriptor->base = VirtualAlloc(0, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    descriptor->length = length;

    if (!descriptor->base) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualAlloc);
        ebpf_free(descriptor);
        descriptor = nullptr;
    }
    return descriptor;
}

void
ebpf_unmap_memory(_Frees_ptr_opt_ ebpf_memory_descriptor_t* memory_descriptor)
{
    EBPF_LOG_ENTRY();
    if (!memory_descriptor) {
        EBPF_RETURN_VOID();
    }

    if (!VirtualFree(memory_descriptor->base, 0, MEM_RELEASE)) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualFree);
    }
    ExFreePool(memory_descriptor);
    EBPF_RETURN_VOID();
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

    // Skip fault injection for this VirtualAlloc2 OS API, as ebpf_allocate already does that.
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

    section = CreateFileMapping(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<unsigned long>(length), nullptr);
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
    if (!ring) {
        EBPF_RETURN_VOID();
    }

    UnmapViewOfFile(ring->primary_view);
    UnmapViewOfFile(ring->secondary_view);
    ebpf_free(ring);
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_base_address(_In_ const ebpf_ring_descriptor_t* ring_descriptor)
{
    return ring_descriptor->primary_view;
}

_Ret_maybenull_ void*
ebpf_ring_map_readonly_user(_In_ const ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_POINTER(void*, ebpf_ring_descriptor_get_base_address(ring));
}

uint32_t
ntstatus_to_win32_error_code(NTSTATUS status)
{
    static uint32_t (*RtlNtStatusToDosError)(NTSTATUS Status) = nullptr;
    if (!RtlNtStatusToDosError) {
        HMODULE ntdll = LoadLibrary(L"ntdll.dll");
        if (!ntdll) {
            return ERROR_OUTOFMEMORY;
        }
        RtlNtStatusToDosError =
            reinterpret_cast<decltype(RtlNtStatusToDosError)>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    }
    return RtlNtStatusToDosError(status);
}

uint32_t
ebpf_result_to_win32_error_code(ebpf_result_t result)
{
    return ntstatus_to_win32_error_code(ebpf_result_to_ntstatus(result));
}

ebpf_result_t
ntstatus_to_ebpf_result(NTSTATUS status)
{
    uint32_t error = ntstatus_to_win32_error_code(status);
    return win32_error_code_to_ebpf_result(error);
}

_Must_inspect_result_ ebpf_result_t
ebpf_protect_memory(_In_ const ebpf_memory_descriptor_t* memory_descriptor, ebpf_page_protection_t protection)
{
    NTSTATUS status = usersim_protect_memory(
        (const usersim_memory_descriptor_t*)memory_descriptor, (usersim_page_protection_t)protection);
    return ntstatus_to_ebpf_result(status);
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

uint32_t
ebpf_random_uint32()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    return mt();
}

_Must_inspect_result_ ebpf_result_t
ebpf_set_current_thread_affinity(uintptr_t new_thread_affinity_mask, _Out_ uintptr_t* old_thread_affinity_mask)
{
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    uintptr_t old_mask = SetThreadAffinityMask(GetCurrentThread(), new_thread_affinity_mask);
    if (old_mask == 0) {
        unsigned long error = GetLastError();
        ebpf_assert(error != ERROR_SUCCESS);
        return EBPF_OPERATION_NOT_SUPPORTED;
    } else {
        *old_thread_affinity_mask = old_mask;
        return EBPF_SUCCESS;
    }
}

_Ret_range_(>, 0) uint32_t ebpf_get_cpu_count() { return usersim_get_cpu_count(); }

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_non_preemptible_work_item(
    _Outptr_ ebpf_non_preemptible_work_item_t** work_item,
    uint32_t cpu_id,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context, _Inout_opt_ void* parameter_1),
    _Inout_opt_ void* work_item_context)
{
    NTSTATUS status = usersim_allocate_non_preemptible_work_item(
        (usersim_non_preemptible_work_item_t**)work_item, cpu_id, work_item_routine, work_item_context);
    return ntstatus_to_ebpf_result(status);
}

void
ebpf_free_non_preemptible_work_item(_Frees_ptr_opt_ ebpf_non_preemptible_work_item_t* work_item)
{
    ebpf_free(work_item);
}

bool
ebpf_queue_non_preemptible_work_item(_Inout_ ebpf_non_preemptible_work_item_t* work_item, _Inout_opt_ void* parameter_1)
{
    return usersim_queue_non_preemptible_work_item((usersim_non_preemptible_work_item_t*)work_item, parameter_1);
}

typedef struct _ebpf_preemptible_work_item
{
    int dummy;
} ebpf_preemptible_work_item_t;

void
ebpf_free_preemptible_work_item(_Frees_ptr_opt_ ebpf_preemptible_work_item_t* work_item)
{
    return usersim_free_preemptible_work_item((usersim_preemptible_work_item_t*)work_item);
}

void
ebpf_queue_preemptible_work_item(_Inout_ ebpf_preemptible_work_item_t* work_item)
{
    usersim_queue_preemptible_work_item((usersim_preemptible_work_item_t*)work_item);
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_preemptible_work_item(
    _Outptr_ ebpf_preemptible_work_item_t** work_item,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
    _Inout_opt_ void* work_item_context)
{
    NTSTATUS status = usersim_allocate_preemptible_work_item(
        (usersim_preemptible_work_item_t**)work_item, work_item_routine, work_item_context);
    return ntstatus_to_ebpf_result(status);
}

typedef struct _ebpf_timer_work_item
{
    TP_TIMER* threadpool_timer;
    void (*work_item_routine)(_Inout_opt_ void* work_item_context);
    void* work_item_context;
} ebpf_timer_work_item_t;

void
_ebpf_timer_callback(_Inout_ TP_CALLBACK_INSTANCE* instance, _Inout_opt_ void* context, _Inout_ TP_TIMER* timer)
{
    ebpf_timer_work_item_t* timer_work_item = reinterpret_cast<ebpf_timer_work_item_t*>(context);
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(timer);
    if (timer_work_item) {
        timer_work_item->work_item_routine(timer_work_item->work_item_context);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_timer_work_item(
    _Outptr_ ebpf_timer_work_item_t** work_item,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
    _Inout_opt_ void* work_item_context)
{
    *work_item = (ebpf_timer_work_item_t*)ebpf_allocate(sizeof(ebpf_timer_work_item_t));

    if (*work_item == nullptr) {
        goto Error;
    }

    (*work_item)->threadpool_timer = CreateThreadpoolTimer(_ebpf_timer_callback, *work_item, nullptr);
    if ((*work_item)->threadpool_timer == nullptr) {
        goto Error;
    }

    (*work_item)->work_item_routine = work_item_routine;
    (*work_item)->work_item_context = work_item_context;

    return EBPF_SUCCESS;

Error:
    if (*work_item != nullptr) {
        if ((*work_item)->threadpool_timer != nullptr) {
            CloseThreadpoolTimer((*work_item)->threadpool_timer);
        }

        ebpf_free(*work_item);
    }
    return EBPF_NO_MEMORY;
}

#define MICROSECONDS_PER_TICK 10
#define MICROSECONDS_PER_MILLISECOND 1000

void
ebpf_schedule_timer_work_item(_Inout_ ebpf_timer_work_item_t* timer, uint32_t elapsed_microseconds)
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
    return usersim_free_timer_work_item((usersim_timer_work_item_t*)work_item);
}

int32_t
ebpf_log_function(_In_ void* context, _In_z_ const char* format_string, ...)
{
    UNREFERENCED_PARAMETER(context);

    va_list arg_start;
    va_start(arg_start, format_string);

    vprintf(format_string, arg_start);

    va_end(arg_start);
    return 0;
}

_Must_inspect_result_ ebpf_result_t
ebpf_access_check(
    _In_ const ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    _In_ const ebpf_security_generic_mapping_t* generic_mapping)
{
    NTSTATUS status = usersim_access_check(
        (const usersim_security_descriptor_t*)security_descriptor, request_access, generic_mapping);
    return ntstatus_to_ebpf_result(status);
}

_Must_inspect_result_ ebpf_result_t
ebpf_validate_security_descriptor(
    _In_ const ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
{
    NTSTATUS status = usersim_validate_security_descriptor(security_descriptor, security_descriptor_length);
    return ntstatus_to_ebpf_result(status);
}

static std::vector<std::string> _ebpf_platform_printk_output;
static std::mutex _ebpf_platform_printk_output_lock;

/**
 * @brief Get the strings written via bpf_printk.
 *
 * @return Vector of strings written via bpf_printk.
 */
std::vector<std::string>
ebpf_platform_printk_output()
{
    std::unique_lock<std::mutex> lock(_ebpf_platform_printk_output_lock);
    return std::move(_ebpf_platform_printk_output);
}

long
ebpf_platform_printk(_In_z_ const char* format, va_list arg_list)
{
    int bytes_written = vprintf(format, arg_list);
    if (bytes_written >= 0) {
        putchar('\n');
        bytes_written++;
    }

    std::string output;
    output.resize(bytes_written);

    vsprintf_s(output.data(), output.size(), format, arg_list);
    // Remove the trailing null.
    output.pop_back();

    std::unique_lock<std::mutex> lock(_ebpf_platform_printk_output_lock);
    _ebpf_platform_printk_output.emplace_back(std::move(output));

    return bytes_written;
}

_Must_inspect_result_ ebpf_result_t
ebpf_update_global_helpers(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count)
{
    UNREFERENCED_PARAMETER(helper_info);
    UNREFERENCED_PARAMETER(helper_info_count);
    return EBPF_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
    ebpf_platform_get_authentication_id(_Out_ uint64_t* authentication_id)
{
    NTSTATUS status = usersim_platform_get_authentication_id(authentication_id);
    return ntstatus_to_ebpf_result(status);
}

void
ebpf_semaphore_destroy(_Frees_ptr_opt_ ebpf_semaphore_t* semaphore)
{
    if (semaphore) {
        ::CloseHandle(semaphore->handle);
        ebpf_free(semaphore);
    }
}

ebpf_result_t
ebpf_utf8_string_to_unicode(_In_ const ebpf_utf8_string_t* input, _Outptr_ wchar_t** output)
{
    wchar_t* unicode_string = NULL;
    ebpf_result_t retval;

    // Compute the size needed to hold the unicode string.
    int result = MultiByteToWideChar(CP_UTF8, 0, (const char*)input->value, (int)input->length, NULL, 0);

    if (result <= 0) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result++;

    unicode_string = (wchar_t*)ebpf_allocate(result * sizeof(wchar_t));
    if (unicode_string == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    result = MultiByteToWideChar(CP_UTF8, 0, (const char*)input->value, (int)input->length, unicode_string, result);

    if (result == 0) {
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
