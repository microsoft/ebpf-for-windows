// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "..\..\external\usersim\src\platform.h"
#include "ebpf_platform.h"
#include "ebpf_tracelog.h"
#include "ebpf_utilities.h"
#include "usersim/ke.h"

#include <TraceLoggingProvider.h>
#include <functional>
#include <intsafe.h>
#include <map>
#include <mutex>
#include <queue>
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

struct _ebpf_ring_descriptor
{
    void* primary_view;
    void* secondary_view;
    size_t length;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

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

static uint32_t
_ntstatus_to_win32_error_code(NTSTATUS status)
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
    return _ntstatus_to_win32_error_code(ebpf_result_to_ntstatus(result));
}

ebpf_result_t
ntstatus_to_ebpf_result(NTSTATUS status)
{
    uint32_t error = _ntstatus_to_win32_error_code(status);
    return win32_error_code_to_ebpf_result(error);
}

struct _DEVICE_OBJECT
{
    int reserved;
};

static DEVICE_OBJECT _ebpf_device_object = {};

_Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object()
{
    return &_ebpf_device_object;
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

_IRQL_requires_max_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
    ebpf_platform_get_authentication_id(_Out_ uint64_t* authentication_id)
{
    NTSTATUS status = usersim_platform_get_authentication_id(authentication_id);
    return ntstatus_to_ebpf_result(status);
}
