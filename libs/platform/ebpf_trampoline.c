// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_epoch.h"

#pragma pack(push)
#pragma pack(1)
typedef struct _ebpf_trampoline_entry
{
    uint16_t load_rax;
    void* indirect_address;
    uint16_t jmp_rax;
    void* address;
} ebpf_trampoline_entry_t;
#pragma pack(pop)

typedef struct _ebpf_trampoline_table
{
    ebpf_memory_descriptor_t* memory_descriptor;
    size_t entry_count;
} ebpf_trampoline_table_t;

ebpf_result_t
ebpf_allocate_trampoline_table(size_t entry_count, _Outptr_ ebpf_trampoline_table_t** trampoline_table)
{
    ebpf_result_t return_value;
    ebpf_trampoline_table_t* local_trampoline_table = NULL;

    local_trampoline_table = ebpf_allocate(sizeof(ebpf_trampoline_table_t));
    if (!local_trampoline_table) {
        return_value = EBPF_NO_MEMORY;
        goto Exit;
    }

    local_trampoline_table->entry_count = entry_count;
    local_trampoline_table->memory_descriptor = ebpf_map_memory(entry_count * sizeof(ebpf_trampoline_entry_t));
    if (!local_trampoline_table->memory_descriptor) {
        return_value = EBPF_NO_MEMORY;
        goto Exit;
    }

    *trampoline_table = local_trampoline_table;
    local_trampoline_table = NULL;
    return_value = EBPF_SUCCESS;
Exit:
    ebpf_free_trampoline_table(local_trampoline_table);
    // Set local_trampoline_table to satisfy the static analyzer.
    local_trampoline_table = NULL;
    return return_value;
}

void
ebpf_free_trampoline_table(_Pre_maybenull_ _Post_invalid_ ebpf_trampoline_table_t* trampoline_table)
{
    if (trampoline_table) {
        ebpf_unmap_memory(trampoline_table->memory_descriptor);
        ebpf_free(trampoline_table);
    }
}

ebpf_result_t
ebpf_update_trampoline_table(
    _Inout_ ebpf_trampoline_table_t* trampoline_table, _In_ const ebpf_extension_dispatch_table_t* dispatch_table)
{
#if defined(_AMD64_)

    size_t function_count = (dispatch_table->size - EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function)) /
                            sizeof(dispatch_table->function[0]);
    ebpf_trampoline_entry_t* local_entries;
    ebpf_result_t return_value;

    if (function_count != trampoline_table->entry_count) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    return_value = ebpf_protect_memory(trampoline_table->memory_descriptor, EBPF_PAGE_PROTECT_READ_WRITE);
    if (return_value != EBPF_SUCCESS) {
        goto Exit;
    }

    local_entries =
        (ebpf_trampoline_entry_t*)ebpf_memory_descriptor_get_base_address(trampoline_table->memory_descriptor);
    if (!local_entries) {
        return_value = EBPF_NO_MEMORY;
        goto Exit;
    }

    size_t index;
    for (index = 0; index < trampoline_table->entry_count; index++) {
        local_entries[index].load_rax = 0xa148;
        local_entries[index].indirect_address = &local_entries[index].address;
        local_entries[index].jmp_rax = 0xe0ff;
        local_entries[index].address = (void*)dispatch_table->function[index];
    }

Exit:
    return_value = ebpf_protect_memory(trampoline_table->memory_descriptor, EBPF_PAGE_PROTECT_READ_EXECUTE);
    return return_value;
#elif
    UNREFERENCED_PARAMETER(trampoline_table);
    UNREFERENCED_PARAMETER(dispatch_table);
    return EBPF_OPERATION_NOT_SUPPORTED;
#endif
}

ebpf_result_t
ebpf_get_trampoline_function(_In_ const ebpf_trampoline_table_t* trampoline_table, size_t index, _Out_ void** function)
{
    ebpf_trampoline_entry_t* local_entries;
    ebpf_result_t return_value;

    if (index >= trampoline_table->entry_count) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    local_entries =
        (ebpf_trampoline_entry_t*)ebpf_memory_descriptor_get_base_address(trampoline_table->memory_descriptor);
    if (!local_entries) {
        return_value = EBPF_NO_MEMORY;
        goto Exit;
    }

    *function = &(local_entries[index]);

    return_value = EBPF_SUCCESS;
Exit:
    return return_value;
}
