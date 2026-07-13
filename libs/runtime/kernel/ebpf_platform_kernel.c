// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_error.h"
#include "ebpf_platform.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_tracelog.h"

extern _Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object();

typedef struct _ebpf_ring_section
{
    HANDLE section_handle;
    void* section_object;
    void* kernel_view;
    size_t view_size;
} ebpf_ring_section_t;

struct _ebpf_ring_descriptor
{
    size_t length;
    ebpf_ring_buffer_kernel_page_t* kernel_page;
    ebpf_ring_section_t consumer;
    ebpf_ring_section_t producer;
    ebpf_ring_section_t data;
    MDL* data_source_mdl;
    MDL* data_double_mdl;
    uint8_t* data_double_mapped_view;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

static KDEFERRED_ROUTINE _ebpf_deferred_routine;
static KDEFERRED_ROUTINE _ebpf_timer_routine;

static void
_ebpf_ring_cleanup_section(_Inout_ ebpf_ring_section_t* section)
{
    if (section->kernel_view != NULL) {
        MmUnmapViewInSystemSpace(section->kernel_view);
        section->kernel_view = NULL;
    }

    if (section->section_object != NULL) {
        ObDereferenceObject(section->section_object);
        section->section_object = NULL;
    }

    if (section->section_handle != NULL) {
        ZwClose(section->section_handle);
        section->section_handle = NULL;
    }

    section->view_size = 0;
}

static ebpf_result_t
_ebpf_ring_create_kernel_double_map(_Inout_ ebpf_ring_descriptor_t* ring_descriptor)
{
    NTSTATUS status = STATUS_SUCCESS;
    uint32_t page_count = (uint32_t)(ring_descriptor->length / PAGE_SIZE);
    size_t pfn_array_size = sizeof(PFN_NUMBER) * page_count;

    ring_descriptor->data_source_mdl =
        IoAllocateMdl(ring_descriptor->data.kernel_view, (ULONG)ring_descriptor->length, FALSE, FALSE, NULL);
    if (ring_descriptor->data_source_mdl == NULL) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        return EBPF_NO_MEMORY;
    }

    __try {
        MmProbeAndLockPages(ring_descriptor->data_source_mdl, KernelMode, IoModifyAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmProbeAndLockPages, status);
        return EBPF_NO_MEMORY;
    }

    ring_descriptor->data_double_mdl = IoAllocateMdl(NULL, (ULONG)(ring_descriptor->length * 2), FALSE, FALSE, NULL);
    if (ring_descriptor->data_double_mdl == NULL) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        return EBPF_NO_MEMORY;
    }

    memcpy(
        MmGetMdlPfnArray(ring_descriptor->data_double_mdl),
        MmGetMdlPfnArray(ring_descriptor->data_source_mdl),
        pfn_array_size);
    memcpy(
        MmGetMdlPfnArray(ring_descriptor->data_double_mdl) + page_count,
        MmGetMdlPfnArray(ring_descriptor->data_source_mdl),
        pfn_array_size);

#pragma warning(push)
#pragma warning(disable : 28145)
    ring_descriptor->data_double_mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

    ring_descriptor->data_double_mapped_view = (uint8_t*)MmMapLockedPagesSpecifyCache(
        ring_descriptor->data_double_mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute);
    if (ring_descriptor->data_double_mapped_view == NULL) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapLockedPagesSpecifyCache, STATUS_NO_MEMORY);
        return EBPF_NO_MEMORY;
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_ebpf_ring_create_section(size_t size, _Inout_ ebpf_ring_section_t* section)
{
    NTSTATUS status;
    LARGE_INTEGER section_size = {0};
    SIZE_T view_size = size;
    OBJECT_ATTRIBUTES object_attributes;

    InitializeObjectAttributes(&object_attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    section_size.QuadPart = size;
    status = ZwCreateSection(
        &section->section_handle,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
        &object_attributes,
        &section_size,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ZwCreateSection, status);
        return EBPF_NO_MEMORY;
    }

    status = ObReferenceObjectByHandle(
        section->section_handle,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
        NULL,
        KernelMode,
        &section->section_object,
        NULL);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ObReferenceObjectByHandle, status);
        _ebpf_ring_cleanup_section(section);
        return EBPF_NO_MEMORY;
    }

    status = MmMapViewInSystemSpace(section->section_object, &section->kernel_view, &view_size);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapViewInSystemSpace, status);
        _ebpf_ring_cleanup_section(section);
        return EBPF_NO_MEMORY;
    }

    section->view_size = view_size;
    return EBPF_SUCCESS;
}

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    ebpf_ring_descriptor_t* ring_descriptor =
        ebpf_allocate_with_tag(sizeof(ebpf_ring_descriptor_t), EBPF_POOL_TAG_DEFAULT);
    ebpf_result_t result;

    if (!ring_descriptor) {
        EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, NULL);
    }

    if (length == 0 || (length % PAGE_SIZE) != 0) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        ebpf_free(ring_descriptor);
        EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, NULL);
    }

    memset(ring_descriptor, 0, sizeof(*ring_descriptor));
    ring_descriptor->length = length;

    ring_descriptor->kernel_page =
        (ebpf_ring_buffer_kernel_page_t*)ebpf_allocate_with_tag(PAGE_SIZE, EBPF_POOL_TAG_DEFAULT);
    if (ring_descriptor->kernel_page == NULL) {
        ebpf_free(ring_descriptor);
        EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, NULL);
    }
    memset(ring_descriptor->kernel_page, 0, PAGE_SIZE);

    result = _ebpf_ring_create_section(PAGE_SIZE, &ring_descriptor->consumer);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = _ebpf_ring_create_section(PAGE_SIZE, &ring_descriptor->producer);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = _ebpf_ring_create_section(length, &ring_descriptor->data);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = _ebpf_ring_create_kernel_double_map(ring_descriptor);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, ring_descriptor);

Done:
    ebpf_free_ring_buffer_memory(ring_descriptor);
    EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, NULL);
}

void
ebpf_free_ring_buffer_memory(_Frees_ptr_opt_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    if (!ring) {
        EBPF_RETURN_VOID();
    }

    _ebpf_ring_cleanup_section(&ring->consumer);
    _ebpf_ring_cleanup_section(&ring->producer);
    if (ring->data_double_mapped_view != NULL) {
        MmUnmapLockedPages(ring->data_double_mapped_view, ring->data_double_mdl);
    }
    if (ring->data_double_mdl != NULL) {
        IoFreeMdl(ring->data_double_mdl);
    }
    if (ring->data_source_mdl != NULL) {
        MmUnlockPages(ring->data_source_mdl);
        IoFreeMdl(ring->data_source_mdl);
    }
    _ebpf_ring_cleanup_section(&ring->data);
    if (ring->kernel_page != NULL) {
        ebpf_free(ring->kernel_page);
    }
    ebpf_free(ring);
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_kernel_page_address(_In_ const ebpf_ring_descriptor_t* ring)
{
    return ring->kernel_page;
}

void*
ebpf_ring_descriptor_get_consumer_page_address(_In_ const ebpf_ring_descriptor_t* ring)
{
    return ring->consumer.kernel_view;
}

void*
ebpf_ring_descriptor_get_producer_page_address(_In_ const ebpf_ring_descriptor_t* ring)
{
    return ring->producer.kernel_view;
}

uint8_t*
ebpf_ring_descriptor_get_data_address(_In_ const ebpf_ring_descriptor_t* ring)
{
    return ring->data_double_mapped_view;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_open_user_section(
    _In_ const ebpf_ring_descriptor_t* ring,
    ebpf_ring_buffer_user_section_t section,
    _Out_ ebpf_handle_t* handle,
    _Out_ size_t* view_size)
{
    ebpf_ring_section_t* source_section = NULL;
    ACCESS_MASK desired_access = SECTION_MAP_READ | SECTION_QUERY;
    HANDLE user_handle = NULL;
    NTSTATUS status;

    if (ring == NULL || handle == NULL || view_size == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    switch (section) {
    case EBPF_RING_BUFFER_USER_SECTION_CONSUMER:
        source_section = (ebpf_ring_section_t*)&ring->consumer;
        desired_access = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY;
        break;
    case EBPF_RING_BUFFER_USER_SECTION_PRODUCER:
        source_section = (ebpf_ring_section_t*)&ring->producer;
        break;
    case EBPF_RING_BUFFER_USER_SECTION_DATA:
        source_section = (ebpf_ring_section_t*)&ring->data;
        break;
    default:
        return EBPF_INVALID_ARGUMENT;
    }

    status =
        ObOpenObjectByPointer(source_section->section_object, 0, NULL, desired_access, NULL, KernelMode, &user_handle);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ObOpenObjectByPointer, status);
        return _ntstatus_to_ebpf_result(status);
    }

    *handle = (ebpf_handle_t)user_handle;
    *view_size = source_section->view_size;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_map_user(
    _In_ ebpf_ring_descriptor_t* ring, _Outptr_ void** consumer, _Outptr_ void** producer, _Outptr_ uint8_t** data)
{
    if (ring == NULL || consumer == NULL || producer == NULL || data == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    *consumer = ring->consumer.kernel_view;
    *producer = ring->producer.kernel_view;
    *data = ring->data_double_mapped_view;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_unmap_user(_In_ ebpf_ring_descriptor_t* ring)
{
    UNREFERENCED_PARAMETER(ring);
    return EBPF_SUCCESS;
}

// There isn't an official API to query this information from kernel.
// Use NtQuerySystemInformation with struct + header from winternl.h.

// Begin code pulled from winternl.h.
#define SystemCodeIntegrityInformation 103
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    unsigned long Length;
    unsigned long CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;
#define CODEINTEGRITY_OPTION_TEST_SIGN 0x02
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
NTSTATUS
NtQuerySystemInformation(
    uint32_t system_information_class,
    void* system_information,
    uint32_t system_information_length,
    uint32_t* return_length);
// End code pulled from winternl.h.

_Must_inspect_result_ ebpf_result_t
ebpf_get_code_integrity_state(_Out_ bool* test_signing_enabled, _Out_ bool* hypervisor_kernel_mode_enabled)
{
    NTSTATUS status;
    SYSTEM_CODEINTEGRITY_INFORMATION code_integrity_information = {sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0};
    uint32_t system_information_length = sizeof(code_integrity_information);
    uint32_t returned_length = 0;
    status = NtQuerySystemInformation(
        SystemCodeIntegrityInformation, &code_integrity_information, system_information_length, &returned_length);
    if (NT_SUCCESS(status)) {
        if ((code_integrity_information.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TEST_SIGN) != 0) {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Test signing enabled");
            *test_signing_enabled = true;
        } else {
            *test_signing_enabled = false;
        }
        if ((code_integrity_information.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0) {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity enabled");
            *hypervisor_kernel_mode_enabled = true;
        } else {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity disabled");
            *hypervisor_kernel_mode_enabled = false;
        }
        return EBPF_SUCCESS;
    } else {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NtQuerySystemInformation, status);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_access_check(
    _In_ const ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    _In_ const ebpf_security_generic_mapping_t* generic_mapping)
{
    ebpf_result_t result;
    NTSTATUS status;
    SECURITY_SUBJECT_CONTEXT subject_context = {0};
    unsigned long granted_access;

    SeCaptureSubjectContext(&subject_context);
    SeLockSubjectContext(&subject_context);
    if (!SeAccessCheck(
            (ebpf_security_descriptor_t*)security_descriptor,
            &subject_context,
            true,
            request_access,
            0,
            NULL,
            (ebpf_security_generic_mapping_t*)generic_mapping,
            KernelMode,
            &granted_access,
            &status)) {
        result = EBPF_ACCESS_DENIED;
    } else {
        result = NT_SUCCESS(status) ? EBPF_SUCCESS : EBPF_ACCESS_DENIED;
    }

    SeUnlockSubjectContext(&subject_context);
    SeReleaseSubjectContext(&subject_context);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_validate_security_descriptor(
    _In_ const ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
{
    ebpf_result_t result;
    if ((security_descriptor->Control & SE_SELF_RELATIVE) == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (!RtlValidRelativeSecurityDescriptor(
            (ebpf_security_descriptor_t*)security_descriptor,
            (unsigned long)security_descriptor_length,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = EBPF_SUCCESS;

Done:
    return result;
}

_IRQL_requires_max_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
    ebpf_platform_get_authentication_id(_Out_ uint64_t* authentication_id)
{
    SECURITY_SUBJECT_CONTEXT context = {0};
    SeCaptureSubjectContext(&context);
    LUID local_authentication_id;

    PACCESS_TOKEN access_token = SeQuerySubjectContextToken(&context);
    // SeQuerySubjectContextToken() is not expected to fail.
    if (access_token == NULL) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "SeQuerySubjectContextToken failed");

        SeReleaseSubjectContext(&context);
        return EBPF_FAILED;
    }

    NTSTATUS status = SeQueryAuthenticationIdToken(access_token, &local_authentication_id);
    // SeQueryAuthenticationIdToken() is not expected to fail.
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, SeQueryAuthenticationIdToken, status);

        SeReleaseSubjectContext(&context);
        return EBPF_FAILED;
    }

    *authentication_id = *(uint64_t*)&local_authentication_id;

    SeReleaseSubjectContext(&context);
    return EBPF_SUCCESS;
}

// Function to convert a UTF-8 string to a UTF-16LE string.
static ebpf_result_t
_convert_utf8_string_to_unicode_string(
    _Out_ PUNICODE_STRING destination_string, _In_ PCSZ source_string, BOOLEAN allocate_destination_string)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    NTSTATUS status;
    ULONG bytes_in_unicode_string = 0;

    ebpf_assert(destination_string);
    ebpf_assert(source_string);

    destination_string->Buffer = NULL;
    destination_string->Length = 0;
    destination_string->MaximumLength = 0;

    ULONG source_length = (ULONG)strlen(source_string);
    ebpf_assert(source_length < USHORT_MAX);

    // First pass: Calculate how many bytes are needed for the UTF-16LE string.
    status = RtlUTF8ToUnicodeN(
        NULL,                     // No destination buffer, just calculate size.
        0,                        // No destination buffer size.
        &bytes_in_unicode_string, // Receives the required size.
        source_string,            // Source UTF-8 string.
        source_length);           // Source length in bytes.

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, RtlUTF8ToUnicodeN, status);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Add space for null terminator.
    uint32_t required_bytes = 0;
    if (cxplat_safe_uint32_t_add(bytes_in_unicode_string, sizeof(wchar_t), &required_bytes) != CXPLAT_STATUS_SUCCESS) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "_convert_utf8_string_to_unicode_string: File path too long");
        goto Done;
    }

    if (required_bytes > USHORT_MAX) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "_convert_utf8_string_to_unicode_string: File path too long");
        goto Done;
    }

    // Allocate buffer if needed.
    if (allocate_destination_string) {
        destination_string->Buffer = ebpf_allocate_with_tag(required_bytes, EBPF_POOL_TAG_DEFAULT);
        if (!destination_string->Buffer) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
        destination_string->MaximumLength = (USHORT)required_bytes;
    } else if (!destination_string->Buffer || destination_string->MaximumLength < required_bytes) {
        result = EBPF_INSUFFICIENT_BUFFER;
        goto Done;
    }

    // Second pass: Perform the actual conversion.
    status = RtlUTF8ToUnicodeN(
        destination_string->Buffer, // Destination buffer.
        bytes_in_unicode_string,    // Destination buffer size (excluding null terminator).
        &bytes_in_unicode_string,   // Receives actual bytes written.
        source_string,              // Source UTF-8 string.
        source_length);             // Source length in bytes.

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, RtlUTF8ToUnicodeN, status);
        if (allocate_destination_string) {
            ebpf_free(destination_string->Buffer);
            destination_string->Buffer = NULL;
        }
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Add null terminator.
    destination_string->Buffer[bytes_in_unicode_string / sizeof(wchar_t)] = L'\0';
    destination_string->Length = (USHORT)bytes_in_unicode_string;

Done:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_open_readonly_file_mapping(
    _In_ const cxplat_utf8_string_t* file_name,
    _Outptr_ HANDLE* file_handle,
    _Outptr_ HANDLE* mapping_handle,
    _Outptr_ void** base_address,
    _Out_ size_t* size)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;

    HANDLE file = NULL;
    HANDLE mapping = NULL;
    void* address = NULL;
    size_t file_size = 0;
    size_t view_size = 0;
    NTSTATUS status;
    UNICODE_STRING file_name_unicode = {0};
    OBJECT_ATTRIBUTES object_attributes = {0};
    IO_STATUS_BLOCK io_status_block = {0};
    FILE_STANDARD_INFORMATION file_standard_information = {0};

    // If file path size is more than USHORT_MAX, fail the call.
    if (file_name->length >= USHORT_MAX) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "ebpf_open_readonly_file_mapping: File path too long");
        goto Done;
    }

    UTF8_STRING utf8_string = {
        .Buffer = (char*)file_name->value,
        .Length = (USHORT)file_name->length,
        .MaximumLength = (USHORT)file_name->length};

    // Convert from UTF-8 string to UTF-16LE string.
    result = _convert_utf8_string_to_unicode_string(&file_name_unicode, utf8_string.Buffer, TRUE);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "_convert_utf8_string_to_unicode_string failed");
        goto Done;
    }

    // If the last character is a null terminator, remove it.
    if (file_name_unicode.Length > 0 &&
        file_name_unicode.Buffer[file_name_unicode.Length / sizeof(wchar_t) - 1] == L'\0') {
        file_name_unicode.Length -= sizeof(wchar_t);
    }

    InitializeObjectAttributes(
        &object_attributes,
        &file_name_unicode,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, // Case insensitive and kernel handle.
        NULL,                                     // No root directory.
        NULL);                                    // No security descriptor.

    // Open the file in read-only mode.
    status = ZwOpenFile(
        &file,
        SYNCHRONIZE | FILE_READ_DATA,
        &object_attributes,
        &io_status_block,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, NtOpenFile, status);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    // Query the file size.
    status = ZwQueryInformationFile(
        file, &io_status_block, &file_standard_information, sizeof(file_standard_information), FileStandardInformation);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ZwQueryInformationFile, status);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    file_size = file_standard_information.EndOfFile.QuadPart;
    if (file_size == 0) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "File size is zero");
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    status = ZwCreateSection(
        &mapping,
        SECTION_MAP_READ | SECTION_QUERY,
        NULL, // No object attributes.
        NULL, // No maximum size.
        PAGE_READONLY,
        SEC_COMMIT,
        file);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ZwCreateSection, status);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    status = ZwMapViewOfSection(
        mapping,
        ZwCurrentProcess(),
        &address,
        0,    // Zero-based address.
        0,    // Zero size means map the entire section.
        NULL, // No offset.
        &view_size,
        ViewUnmap,
        0,
        PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ZwMapViewOfSection, status);
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    *file_handle = file;
    file = NULL; // Ownership transferred, don't close this now.

    *mapping_handle = mapping;
    mapping = NULL; // Ownership transferred, don't close this now.

    *base_address = address;
    address = NULL; // Ownership transferred, don't unmap this now.

    *size = file_size;

    result = EBPF_SUCCESS;
Done:
    ebpf_close_file_mapping(file, mapping, address);
    if (file_name_unicode.Buffer != NULL) {
        RtlFreeUnicodeString(&file_name_unicode);
    }
    EBPF_RETURN_RESULT(result);
}

void
ebpf_close_file_mapping(_In_opt_ HANDLE file_handle, _In_opt_ HANDLE mapping_handle, _In_opt_ void* base_address)
{
    if (base_address != NULL) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), base_address);
    }

    if (mapping_handle != NULL) {
        ZwClose(mapping_handle);
    }

    if (file_handle != NULL) {
        ZwClose(file_handle);
    }
}
