// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "..\..\external\usersim\src\platform.h"
#include "ebpf_error.h"
#include "ebpf_platform.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_tracelog.h"
#include "ebpf_utilities.h"
#include "usersim/ke.h"

#include <TraceLoggingProvider.h>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <vector>

// Global variables used to override behavior for testing.
// Permit the test to simulate both Hyper-V Code Integrity and Test Signing
// being enabled or disabled.
bool _ebpf_platform_code_integrity_enabled = false;
bool _ebpf_platform_code_integrity_test_signing_enabled = true;

extern "C" size_t ebpf_fuzzing_memory_limit = MAXSIZE_T;

_Must_inspect_result_ ebpf_result_t
ebpf_get_code_integrity_state(_Out_ bool* test_signing_enabled, _Out_ bool* hypervisor_kernel_mode_enabled)
{
    EBPF_LOG_ENTRY();
    if (_ebpf_platform_code_integrity_test_signing_enabled) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Test signing enabled");
        *test_signing_enabled = true;
    } else {
        *test_signing_enabled = false;
    }
    if (_ebpf_platform_code_integrity_enabled) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity enabled");
        *hypervisor_kernel_mode_enabled = true;
    } else {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity disabled");
        *hypervisor_kernel_mode_enabled = false;
    }
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

typedef struct _ebpf_ring_section
{
    HANDLE section_handle;
    void* view;
    size_t view_size;
} ebpf_ring_section_t;

struct _ebpf_ring_descriptor
{
    size_t length;
    ebpf_ring_buffer_kernel_page_t* kernel_page;
    ebpf_ring_section_t consumer;
    ebpf_ring_section_t producer;
    ebpf_ring_section_t data;
    void* data_secondary_view;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

static void
_ebpf_ring_cleanup_section(_Inout_ ebpf_ring_section_t* section)
{
    if (section->view != nullptr) {
        UnmapViewOfFile(section->view);
        section->view = nullptr;
    }

    if (section->section_handle != nullptr) {
        CloseHandle(section->section_handle);
        section->section_handle = nullptr;
    }

    section->view_size = 0;
}

static _Must_inspect_result_ ebpf_result_t
_ebpf_ring_create_section(size_t size, _Inout_ ebpf_ring_section_t* section)
{
    uint64_t section_size = size;

    section->section_handle = CreateFileMapping(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        static_cast<unsigned long>(section_size >> 32),
        static_cast<unsigned long>(section_size & MAXUINT32),
        nullptr);
    if (section->section_handle == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, CreateFileMapping);
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    section->view = MapViewOfFile(section->section_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size);
    if (section->view == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile);
        _ebpf_ring_cleanup_section(section);
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    section->view_size = size;
    return EBPF_SUCCESS;
}

static _Must_inspect_result_ ebpf_result_t
_ebpf_ring_create_double_map(
    _In_ HANDLE section_handle, size_t view_length, _Outptr_ void** primary_view, _Outptr_ void** secondary_view)
{
    uint8_t* placeholder1 = nullptr;
    uint8_t* placeholder2 = nullptr;
    void* view1 = nullptr;
    void* view2 = nullptr;
    bool result = false;
    ebpf_result_t return_value = EBPF_SUCCESS;

    placeholder1 = reinterpret_cast<uint8_t*>(VirtualAlloc2(
        nullptr, nullptr, view_length * 2, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0));
    if (placeholder1 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualAlloc2);
        return win32_error_code_to_ebpf_result(GetLastError());
    }

#pragma warning(push)
#pragma warning(disable : 6333)
#pragma warning(disable : 28160)
    result = VirtualFree(placeholder1, view_length, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    if (result == FALSE) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualFree);
        return_value = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }
#pragma warning(pop)

    placeholder2 = placeholder1 + view_length;

    view1 = MapViewOfFile3(
        section_handle, nullptr, placeholder1, 0, view_length, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view1 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile3);
        return_value = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }
    placeholder1 = nullptr;

    view2 = MapViewOfFile3(
        section_handle, nullptr, placeholder2, 0, view_length, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view2 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile3);
        return_value = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }

    *primary_view = view1;
    *secondary_view = view2;
    view1 = nullptr;
    view2 = nullptr;
    placeholder2 = nullptr;
    return_value = EBPF_SUCCESS;

Exit:
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

    return return_value;
}

// This code is derived from the sample at:
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    SYSTEM_INFO sysInfo;
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_ring_descriptor_t* descriptor = nullptr;

    // Skip fault injection for this VirtualAlloc2 OS API, as ebpf_allocate already does that.
    GetSystemInfo(&sysInfo);
    ebpf_assert(sysInfo.dwPageSize == PAGE_SIZE);

    if (length == 0) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Ring buffer length is zero");
        return nullptr;
    }

    if (length % PAGE_SIZE != 0) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match page size",
            length);
        return nullptr;
    }

    descriptor =
        (ebpf_ring_descriptor_t*)ebpf_allocate_with_tag(sizeof(ebpf_ring_descriptor_t), EBPF_POOL_TAG_DEFAULT);
    if (!descriptor) {
        return nullptr;
    }
    memset(descriptor, 0, sizeof(*descriptor));
    descriptor->length = length;
    descriptor->kernel_page =
        (ebpf_ring_buffer_kernel_page_t*)ebpf_allocate_with_tag(PAGE_SIZE, EBPF_POOL_TAG_DEFAULT);
    if (descriptor->kernel_page == nullptr) {
        goto Exit;
    }
    memset(descriptor->kernel_page, 0, PAGE_SIZE);

    result = _ebpf_ring_create_section(PAGE_SIZE, &descriptor->consumer);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _ebpf_ring_create_section(PAGE_SIZE, &descriptor->producer);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _ebpf_ring_create_section(length, &descriptor->data);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    UnmapViewOfFile(descriptor->data.view);
    descriptor->data.view = nullptr;
    result = _ebpf_ring_create_double_map(
        descriptor->data.section_handle, descriptor->data.view_size, &descriptor->data.view, &descriptor->data_secondary_view);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_free_ring_buffer_memory(descriptor);
        descriptor = nullptr;
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
    ebpf_ring_descriptor_t* descriptor = ring;
    __analysis_assume(descriptor != NULL);

#pragma warning(push)
#pragma warning(suppress : 6001) // Ring descriptors are zero-initialized on allocation, so partially constructed
                                 // descriptors can be cleaned up by testing members against nullptr.
    if (descriptor->data_secondary_view != nullptr) {
        UnmapViewOfFileEx(descriptor->data_secondary_view, 0);
    }
    _ebpf_ring_cleanup_section(&descriptor->data);
    _ebpf_ring_cleanup_section(&descriptor->producer);
    _ebpf_ring_cleanup_section(&descriptor->consumer);
    if (descriptor->kernel_page != nullptr) {
        ebpf_free(descriptor->kernel_page);
    }
#pragma warning(pop)
    ebpf_free(descriptor);
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_kernel_page_address(_In_ const ebpf_ring_descriptor_t* ring_descriptor)
{
    return ring_descriptor->kernel_page;
}

void*
ebpf_ring_descriptor_get_consumer_page_address(_In_ const ebpf_ring_descriptor_t* ring_descriptor)
{
    return ring_descriptor->consumer.view;
}

void*
ebpf_ring_descriptor_get_producer_page_address(_In_ const ebpf_ring_descriptor_t* ring_descriptor)
{
    return ring_descriptor->producer.view;
}

uint8_t*
ebpf_ring_descriptor_get_data_address(_In_ const ebpf_ring_descriptor_t* ring_descriptor)
{
    return (uint8_t*)ring_descriptor->data.view;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_open_user_section(
    _In_ const ebpf_ring_descriptor_t* ring,
    ebpf_ring_buffer_user_section_t section,
    _Out_ ebpf_handle_t* handle,
    _Out_ size_t* view_size)
{
    const ebpf_ring_section_t* source_section = nullptr;
    DWORD desired_access = FILE_MAP_READ;
    HANDLE duplicated_handle = nullptr;

    if (ring == nullptr || handle == nullptr || view_size == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    switch (section) {
    case EBPF_RING_BUFFER_USER_SECTION_CONSUMER:
        source_section = &ring->consumer;
        desired_access = FILE_MAP_READ | FILE_MAP_WRITE;
        break;
    case EBPF_RING_BUFFER_USER_SECTION_PRODUCER:
        source_section = &ring->producer;
        break;
    case EBPF_RING_BUFFER_USER_SECTION_DATA:
        source_section = &ring->data;
        break;
    default:
        return EBPF_INVALID_ARGUMENT;
    }

    if (!DuplicateHandle(
            GetCurrentProcess(),
            source_section->section_handle,
            GetCurrentProcess(),
            &duplicated_handle,
            desired_access,
            FALSE,
            0)) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, DuplicateHandle);
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    *handle = (ebpf_handle_t)duplicated_handle;
    *view_size = source_section->view_size;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_map_user(
    _In_ ebpf_ring_descriptor_t* ring, _Outptr_ void** consumer, _Outptr_ void** producer, _Outptr_ uint8_t** data)
{
    EBPF_LOG_ENTRY();
    if (!ring || !consumer || !producer || !data) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }
    *consumer = ebpf_ring_descriptor_get_consumer_page_address(ring);
    *producer = ebpf_ring_descriptor_get_producer_page_address(ring);
    *data = ebpf_ring_descriptor_get_data_address(ring);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_unmap_user(_In_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(ring);
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
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

_Must_inspect_result_ ebpf_result_t
ebpf_open_readonly_file_mapping(
    _In_ const cxplat_utf8_string_t* file_name,
    _Outptr_ HANDLE* file_handle,
    _Outptr_ HANDLE* mapping_handle,
    _Outptr_ void** base_address,
    _Out_ size_t* size)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = INVALID_HANDLE_VALUE;
    void* address = nullptr;
    size_t file_size = 0;
    ebpf_result_t result = EBPF_SUCCESS;
    std::vector<wchar_t> wide_file_name;
    int utf16_length = 0;
    EBPF_LOG_ENTRY();

    // Convert from UTF-8 string to wide string.
    utf16_length = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(file_name->value), -1, nullptr, 0);

    if (utf16_length <= 0) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MultiByteToWideChar);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    wide_file_name.resize(utf16_length);

    utf16_length = MultiByteToWideChar(
        CP_UTF8,
        0,
        reinterpret_cast<const char*>(file_name->value),
        -1,
        wide_file_name.data(),
        static_cast<int>(wide_file_name.size()));

    if (utf16_length <= 0) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MultiByteToWideChar);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Open the file in read-only mode.
    file = CreateFile(
        wide_file_name.data(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, CreateFile);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    // Create a file mapping for the file.
    mapping = CreateFileMapping(file, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if (mapping == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, CreateFileMapping);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    // Get the size of the file.
    file_size = GetFileSize(file, nullptr);

    if (file_size == INVALID_FILE_SIZE) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, GetFileSize);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    // Map the file into the process address space.
    address = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, file_size);
    if (address == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile);
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    // Set the output parameters.
    *file_handle = file;
    file = INVALID_HANDLE_VALUE; // Ownership transferred, don't close this now.
    *mapping_handle = mapping;
    mapping = INVALID_HANDLE_VALUE; // Ownership transferred, don't close this now.
    *base_address = address;
    address = nullptr; // Ownership transferred, don't unmap this now.
    *size = file_size;

    result = EBPF_SUCCESS;

Done:
    ebpf_close_file_mapping(file, mapping, address);

    EBPF_RETURN_RESULT(result);
}

void
ebpf_close_file_mapping(_In_opt_ HANDLE file_handle, _In_opt_ HANDLE mapping_handle, _In_opt_ void* base_address)
{
    EBPF_LOG_ENTRY();
    if (base_address != nullptr) {
        UnmapViewOfFile(base_address);
    }

    if (mapping_handle != NULL) {
        CloseHandle(mapping_handle);
    }

    if (file_handle != INVALID_HANDLE_VALUE && file_handle != NULL) {
        CloseHandle(file_handle);
    }
}
