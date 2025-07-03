// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_tracelog.h"
#include "ebpf_ring_buffer.h"

extern _Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object();

struct _ebpf_ring_descriptor
{
    MDL* kernel_mdl;
    MDL* user_mdl_consumer;
    MDL* user_mdl_producer;
    MDL* memory;
    void* base_address;
    size_t length; //< Length of the ring buffer in bytes, excluding the header.
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

static KDEFERRED_ROUTINE _ebpf_deferred_routine;
static KDEFERRED_ROUTINE _ebpf_timer_routine;

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status;

    ebpf_ring_descriptor_t* ring_descriptor = ebpf_allocate(sizeof(ebpf_ring_descriptor_t));
    MDL* source_mdl = NULL;
    MDL* kernel_mdl = NULL;

    if (!ring_descriptor) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    if (length % PAGE_SIZE != 0 || length > (MAXUINT32 / 2 - 2 * PAGE_SIZE)) {
        status = STATUS_NO_MEMORY;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        goto Done;
    }
    ring_descriptor->length = length;

    const size_t kernel_pages = 1;
    const size_t user_pages = 2; // consumer, producer
    size_t data_pages = length / PAGE_SIZE;
    size_t requested_page_count = kernel_pages + user_pages + data_pages;

    if (requested_page_count < data_pages) {
        status = STATUS_NO_MEMORY;
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Ring buffer length is too large", length);
        goto Done;
    }

    // Allocate pages using ebpf_map_memory.
    ring_descriptor->memory = ebpf_map_memory(requested_page_count * PAGE_SIZE);
    if (!ring_descriptor->memory) {
        status = STATUS_NO_MEMORY;
        goto Done;
    }
    source_mdl = ring_descriptor->memory;

    // Create a MDL big enough to include the header and double-mapped pages
    uint32_t total_mapped_size = (uint32_t)((kernel_pages + user_pages) * PAGE_SIZE + length * 2);
    ring_descriptor->kernel_mdl = IoAllocateMdl(NULL, total_mapped_size, FALSE, FALSE, NULL);
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

    ring_descriptor->user_mdl_producer = IoAllocateMdl(NULL, PAGE_SIZE + ((ULONG)length * 2), FALSE, FALSE, NULL);
    if (!ring_descriptor->user_mdl_producer) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, IoAllocateMdl, STATUS_NO_MEMORY);
        status = STATUS_NO_MEMORY;
        goto Done;
    }

    // Black magic to create a MDL where the data pages are mapped twice.
    // We set MDL_PAGES_LOCKED here, but crucially never unlock the MDL.
    // Instead this happens via ebpf_unmap_memory.
    memcpy(MmGetMdlPfnArray(kernel_mdl), MmGetMdlPfnArray(source_mdl), sizeof(PFN_NUMBER) * requested_page_count);

    // Double map the data pages.
    memcpy(
        MmGetMdlPfnArray(kernel_mdl) + requested_page_count,
        MmGetMdlPfnArray(kernel_mdl) + user_pages,
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
        (PVOID)((ULONG_PTR)MmGetMdlVirtualAddress(kernel_mdl) + 2*PAGE_SIZE),
        (ULONG)(PAGE_SIZE + length * 2));

    // Map the kernel MDL to system memory.
    ring_descriptor->base_address = MmGetSystemAddressForMdlSafe(
        kernel_mdl, NormalPagePriority | MdlMappingNoExecute);
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

static MDL* _get_user_mdl(ebpf_ring_descriptor_t* ring, uint32_t offset)
{
    switch (offset) {
        case 0:
            return ring->user_mdl_consumer;
        case PAGE_SIZE:
            return ring->user_mdl_producer;
        default:
            return NULL;
    }
}

_Ret_maybenull_ void*
ebpf_ring_map_user(ebpf_ring_descriptor_t* ring, uint32_t offset, uint32_t size, uint32_t page_protection)
{
    MDL* user_mdl = _get_user_mdl(ring, offset);
    if (!user_mdl) {
        return NULL;
    }

    if (size == 0) {
        size = MmGetMdlByteCount(user_mdl);
    } else if (size != MmGetMdlByteCount(user_mdl)) {
        return NULL;
    }

    if (offset < PAGE_SIZE) {
        if (page_protection != PAGE_READWRITE) {
            return NULL;
        }
    } else {
        if (page_protection != PAGE_READONLY) {
            return NULL;
        }
    }

    ULONG priority = NormalPagePriority;
    if (page_protection == PAGE_READONLY) {
        priority |= MdlMappingNoWrite;
    }

    __try {
        void *user = MmMapLockedPagesSpecifyCache(
            user_mdl, UserMode, MmCached, NULL, FALSE, priority);
        if (!user) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "MmMapLockedPagesSpecifyCache failed");
            return NULL;
        }
        return user;
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
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
NTSTATUS
NtQuerySystemInformation(
    uint32_t system_information_class,
    void* system_information,
    uint32_t system_information_length,
    uint32_t* return_length);
// End code pulled from winternl.h.

_Must_inspect_result_ ebpf_result_t
ebpf_get_code_integrity_state(_Out_ ebpf_code_integrity_state_t* state)
{
    NTSTATUS status;
    SYSTEM_CODEINTEGRITY_INFORMATION code_integrity_information = {sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0};
    uint32_t system_information_length = sizeof(code_integrity_information);
    uint32_t returned_length = 0;
    status = NtQuerySystemInformation(
        SystemCodeIntegrityInformation, &code_integrity_information, system_information_length, &returned_length);
    if (NT_SUCCESS(status)) {
        if ((code_integrity_information.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0) {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity enabled");
            *state = EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE;
        } else {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity disabled");
            *state = EBPF_CODE_INTEGRITY_DEFAULT;
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
