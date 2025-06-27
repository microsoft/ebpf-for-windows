// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

extern _Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object();

struct _ebpf_ring_descriptor
{
    MDL* memory_descriptor_list;
    MDL* memory;
    void* base_address;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

static KDEFERRED_ROUTINE _ebpf_deferred_routine;
static KDEFERRED_ROUTINE _ebpf_timer_routine;

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    size_t requested_page_count = length / PAGE_SIZE;

    ebpf_ring_descriptor_t* ring_descriptor = ebpf_allocate(sizeof(ebpf_ring_descriptor_t));
    MDL* source_mdl = NULL;
    MDL* new_mdl = NULL;

    if (!ring_descriptor) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    if (length % PAGE_SIZE != 0 || length > MAXUINT32 / 2) {
        status = STATUS_NO_MEMORY;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        goto Done;
    }

    // Allocate pages using ebpf_map_memory.
    ring_descriptor->memory = ebpf_map_memory(requested_page_count * PAGE_SIZE);
    if (!ring_descriptor->memory) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    source_mdl = ring_descriptor->memory;

    // Create a MDL big enough to double map the pages.
    ring_descriptor->memory_descriptor_list =
        IoAllocateMdl(NULL, (uint32_t)(requested_page_count * 2 * PAGE_SIZE), FALSE, FALSE, NULL);
    if (!ring_descriptor->memory_descriptor_list) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    new_mdl = ring_descriptor->memory_descriptor_list;

    memcpy(MmGetMdlPfnArray(new_mdl), MmGetMdlPfnArray(source_mdl), sizeof(PFN_NUMBER) * requested_page_count);

    memcpy(
        MmGetMdlPfnArray(new_mdl) + requested_page_count,
        MmGetMdlPfnArray(source_mdl),
        sizeof(PFN_NUMBER) * requested_page_count);

#pragma warning(push)
#pragma warning(disable : 28145) /* The opaque MDL structure should not be modified by a driver except for \
                                    MDL_PAGES_LOCKED and MDL_MAPPING_CAN_FAIL. */
    new_mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

    ring_descriptor->base_address = MmMapLockedPagesSpecifyCache(
        new_mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute);
    if (!ring_descriptor->base_address) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapLockedPagesSpecifyCache, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    status = STATUS_SUCCESS;

Done:
    if (!NT_SUCCESS(status)) {
        if (ring_descriptor) {
            if (ring_descriptor->memory_descriptor_list) {
                IoFreeMdl(ring_descriptor->memory_descriptor_list);
            }
            if (ring_descriptor->memory) {
                ebpf_unmap_memory(ring_descriptor->memory);
            }
            ebpf_free(ring_descriptor);
            ring_descriptor = NULL;
        }
    }

    EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, ring_descriptor);
}

void
ebpf_free_ring_buffer_memory(_Frees_ptr_opt_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    if (!ring) {
        EBPF_RETURN_VOID();
    }

    MmUnmapLockedPages(ring->base_address, ring->memory_descriptor_list);

    IoFreeMdl(ring->memory_descriptor_list);
    ebpf_unmap_memory(ring->memory);
    ebpf_free(ring);
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_base_address(_In_ const ebpf_ring_descriptor_t* memory_descriptor)
{
    return memory_descriptor->base_address;
}

_Ret_maybenull_ void*
ebpf_ring_map_readonly_user(_In_ const ebpf_ring_descriptor_t* ring)
{
    __try {
        return MmMapLockedPagesSpecifyCache(
            ring->memory_descriptor_list, UserMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoWrite);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmMapLockedPagesSpecifyCache, STATUS_NO_MEMORY);
        return NULL;
    }
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

        return EBPF_FAILED;
    }

    NTSTATUS status = SeQueryAuthenticationIdToken(access_token, &local_authentication_id);
    // SeQueryAuthenticationIdToken() is not expected to fail.
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, SeQueryAuthenticationIdToken, status);

        return EBPF_FAILED;
    }

    *authentication_id = *(uint64_t*)&local_authentication_id;

    return EBPF_SUCCESS;
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
    UTF8_STRING utf8_string = {
        .Buffer = (char*)file_name->value,
        .Length = (USHORT)file_name->length,
        .MaximumLength = (USHORT)file_name->length};
    UNICODE_STRING file_name_unicode = {0};
    OBJECT_ATTRIBUTES object_attributes = {0};
    IO_STATUS_BLOCK io_status_block = {0};
    FILE_STANDARD_INFORMATION file_standard_information = {0};

    // Convert from UTF-8 string to wide string.
    status = RtlUTF8StringToUnicodeString(&file_name_unicode, &utf8_string, TRUE); // AllocateDestinationString = TRUE
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, RtlUTF8StringToUnicodeString, status);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // If the last character is a null terminator, remove it.
    if (file_name_unicode.Length > 0 &&
        file_name_unicode.Buffer[file_name_unicode.Length / sizeof(WCHAR) - 1] == L'\0') {
        file_name_unicode.Length -= sizeof(WCHAR);
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
