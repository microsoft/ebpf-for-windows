// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_tracelog.h"

extern _Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object();

struct _ebpf_ring_descriptor
{
    MDL* kernel_mdl;
    MDL* user_mdl_consumer;
    MDL* user_mdl_producer;
    MDL* memory;
    void* base_address;
    // User-mode mapping state for serialized map and unmap transitions.
    // 0 = unmapped, 1 = fully mapped, 2 = mapping in progress, 3 = unmapping in progress.
    volatile LONG user_mapping_state;
    PEPROCESS user_process;
    void* user_consumer_address;
    void* user_producer_address;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

static KDEFERRED_ROUTINE _ebpf_deferred_routine;
static KDEFERRED_ROUTINE _ebpf_timer_routine;

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;
    ebpf_result_t result;

    ebpf_ring_descriptor_t* ring_descriptor =
        ebpf_allocate_with_tag(sizeof(ebpf_ring_descriptor_t), EBPF_POOL_TAG_DEFAULT);
    MDL* source_mdl = NULL;
    MDL* kernel_mdl = NULL;

    if (!ring_descriptor) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    const size_t kernel_pages = 1;
    const size_t user_pages = 2; // consumer, producer
    size_t requested_page_count = 0;
    size_t mapped_memory_length = 0;
    size_t data_mapped_length = 0;
    size_t header_page_count = 0;
    size_t header_mapped_length = 0;
    size_t total_mapped_size = 0;
    size_t user_mdl_producer_length = 0;

    if (length % PAGE_SIZE != 0) {
        status = STATUS_NO_MEMORY;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        goto Done;
    }

    size_t data_pages = length / PAGE_SIZE;
    result = ebpf_safe_size_t_add(kernel_pages, user_pages, &requested_page_count);
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_add(requested_page_count, data_pages, &requested_page_count);
    }
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_multiply(requested_page_count, PAGE_SIZE, &mapped_memory_length);
    }
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_multiply(length, 2, &data_mapped_length);
    }
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_add(kernel_pages, user_pages, &header_page_count);
    }
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_multiply(header_page_count, PAGE_SIZE, &header_mapped_length);
    }
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_add(header_mapped_length, data_mapped_length, &total_mapped_size);
    }
    if (result == EBPF_SUCCESS) {
        result = ebpf_safe_size_t_add(PAGE_SIZE, data_mapped_length, &user_mdl_producer_length);
    }
    if ((result != EBPF_SUCCESS) || (total_mapped_size > MAXULONG) || (user_mdl_producer_length > MAXULONG)) {
        status = STATUS_NO_MEMORY;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Ring buffer length is too large", length);
        goto Done;
    }

    // Allocate pages using ebpf_map_memory.
    ring_descriptor->memory = ebpf_map_memory(mapped_memory_length);
    if (!ring_descriptor->memory) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    source_mdl = ring_descriptor->memory;

    // Create a MDL big enough to include the header and double-mapped pages.
    ring_descriptor->kernel_mdl = IoAllocateMdl(NULL, (ULONG)total_mapped_size, FALSE, FALSE, NULL);
    if (!ring_descriptor->kernel_mdl) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    kernel_mdl = ring_descriptor->kernel_mdl;

    ring_descriptor->user_mdl_consumer = IoAllocateMdl(NULL, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!ring_descriptor->user_mdl_consumer) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    ring_descriptor->user_mdl_producer = IoAllocateMdl(NULL, (ULONG)user_mdl_producer_length, FALSE, FALSE, NULL);
    if (!ring_descriptor->user_mdl_producer) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    // Black magic to create an MDL where the data pages are mapped twice.
    // We set MDL_PAGES_LOCKED here, but crucially never unlock the MDL.
    // Instead this happens via ebpf_unmap_memory.
    memcpy(MmGetMdlPfnArray(kernel_mdl), MmGetMdlPfnArray(source_mdl), sizeof(PFN_NUMBER) * requested_page_count);

    // Double map the data pages.
    memcpy(
        MmGetMdlPfnArray(kernel_mdl) + requested_page_count,
        MmGetMdlPfnArray(kernel_mdl) + kernel_pages + user_pages,
        sizeof(PFN_NUMBER) * data_pages);

#pragma warning(push)
#pragma warning(disable : 28145) /* The opaque MDL structure should not be modified by a driver except for \
                                    MDL_PAGES_LOCKED and MDL_MAPPING_CAN_FAIL. */
    kernel_mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

    // Create separate user mappings to allow different protection settings.
    IoBuildPartialMdl(
        kernel_mdl,
        ring_descriptor->user_mdl_consumer,
        (PVOID)((ULONG_PTR)MmGetMdlVirtualAddress(kernel_mdl) + PAGE_SIZE),
        PAGE_SIZE);

    IoBuildPartialMdl(
        kernel_mdl,
        ring_descriptor->user_mdl_producer,
        (PVOID)((ULONG_PTR)MmGetMdlVirtualAddress(kernel_mdl) + 2 * PAGE_SIZE),
        (ULONG)(PAGE_SIZE + length * 2));

    // Map the kernel MDL to system memory.
    ring_descriptor->base_address = MmGetSystemAddressForMdlSafe(kernel_mdl, NormalPagePriority | MdlMappingNoExecute);
    if (!ring_descriptor->base_address) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MmGetSystemAddressForMdlSafe, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    status = STATUS_SUCCESS;

Done:
    if (!NT_SUCCESS(status)) {
        if (ring_descriptor) {
            if (ring_descriptor->kernel_mdl) {
                IoFreeMdl(ring_descriptor->kernel_mdl);
            }
            if (ring_descriptor->user_mdl_consumer) {
                IoFreeMdl(ring_descriptor->user_mdl_consumer);
            }
            if (ring_descriptor->user_mdl_producer) {
                IoFreeMdl(ring_descriptor->user_mdl_producer);
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

    // Unmap a fully established user mapping before freeing the MDLs.
    // Use InterlockedExchange to claim the state atomically.
    // False positive: ring is allocated via ebpf_allocate_with_tag/cxplat_allocate and is zero-initialized.
#pragma warning(suppress : 6001)
    long old_state = InterlockedExchange(&ring->user_mapping_state, 0);
    ebpf_assert(old_state != 2 && old_state != 3);
    if (old_state == 1) {
        if (PsGetCurrentProcess() == ring->user_process) {
            // Same process context: safe to unmap directly.
            MmUnmapLockedPages(ring->user_consumer_address, ring->user_mdl_consumer);
            MmUnmapLockedPages(ring->user_producer_address, ring->user_mdl_producer);
        } else {
            // Cross-process context (typical during process teardown on a worker thread).
            // KeStackAttachProcess is unsafe for a dying process. The OS will clean up
            // user-mode VA mappings during process address space teardown.
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_BASE,
                "Ring buffer freed with outstanding user mapping; relying on OS process teardown for VA cleanup");
        }
        ObDereferenceObject(ring->user_process);
        ring->user_process = NULL;
        ring->user_consumer_address = NULL;
        ring->user_producer_address = NULL;
    }

    IoFreeMdl(ring->user_mdl_consumer);
    IoFreeMdl(ring->user_mdl_producer);

    MmUnmapLockedPages(ring->base_address, ring->kernel_mdl);
    IoFreeMdl(ring->kernel_mdl);
    ebpf_unmap_memory(ring->memory);
    ebpf_free(ring);
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_base_address(_In_ const ebpf_ring_descriptor_t* memory_descriptor)
{
    return memory_descriptor->base_address;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_map_user(
    _In_ ebpf_ring_descriptor_t* ring, _Outptr_ void** consumer, _Outptr_ void** producer, _Outptr_ uint8_t** data)
{
    if (!ring || !consumer || !producer || !data) {
        return EBPF_INVALID_ARGUMENT;
    }

    *consumer = NULL;
    *producer = NULL;
    *data = NULL;

    // Atomically transition from unmapped (0) to mapping-in-progress (2).
    if (InterlockedCompareExchange(&ring->user_mapping_state, 2, 0) != 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    __try {
        *consumer =
            MmMapLockedPagesSpecifyCache(ring->user_mdl_consumer, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *consumer = NULL;
    }
    if (!*consumer) {
        InterlockedExchange(&ring->user_mapping_state, 0);
        return EBPF_INVALID_ARGUMENT;
    }

    __try {
        *producer = MmMapLockedPagesSpecifyCache(
            ring->user_mdl_producer, UserMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoWrite);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *producer = NULL;
    }
    if (!*producer) {
        MmUnmapLockedPages(*consumer, ring->user_mdl_consumer);
        *consumer = NULL;
        InterlockedExchange(&ring->user_mapping_state, 0);
        return EBPF_INVALID_ARGUMENT;
    }

    // Capture process reference and addresses for secure unmapping.
    ring->user_process = PsGetCurrentProcess();
    ObReferenceObject(ring->user_process);
    ring->user_consumer_address = *consumer;
    ring->user_producer_address = *producer;

    // All fields are now valid — transition to fully mapped (1).
    InterlockedExchange(&ring->user_mapping_state, 1);

    *data = (uint8_t*)*producer + PAGE_SIZE;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_unmap_user(_In_ ebpf_ring_descriptor_t* ring)
{
    // Atomically transition from mapped (1) to unmapping-in-progress (3).
    if (InterlockedCompareExchange(&ring->user_mapping_state, 3, 1) != 1) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Verify the call is from the same process that mapped the ring.
    if (PsGetCurrentProcess() != ring->user_process) {
        // Wrong process — restore to mapped state and reject.
        InterlockedExchange(&ring->user_mapping_state, 1);
        return EBPF_INVALID_ARGUMENT;
    }

    // Use the stored addresses, not the user-provided ones.
    MmUnmapLockedPages(ring->user_consumer_address, ring->user_mdl_consumer);
    MmUnmapLockedPages(ring->user_producer_address, ring->user_mdl_producer);

    ObDereferenceObject(ring->user_process);
    ring->user_process = NULL;
    ring->user_consumer_address = NULL;
    ring->user_producer_address = NULL;

    // Transition to fully unmapped (0), allowing new map operations.
    InterlockedExchange(&ring->user_mapping_state, 0);
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
