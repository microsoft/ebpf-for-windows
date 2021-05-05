/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "ebpf_platform.h"
#include "ebpf_epoch.h"

ebpf_error_code_t
ebpf_build_trampoline_table(
    size_t* entry_count, ebpf_trampoline_entry_t** entries, const ebpf_extension_dispatch_table_t* dispatch_table)
{
    size_t function_count = (dispatch_table->size - EBPF_OFFSET_OF(ebpf_extension_dispatch_table_t, function)) /
                            sizeof(dispatch_table->function[0]);
    ebpf_trampoline_entry_t* local_entries = *entries;
    size_t local_entry_count = *entry_count;

    // If there is no existing table, allocate a new table.
    if (local_entries == NULL) {
        local_entry_count = function_count;
        local_entries = ebpf_epoch_allocate(local_entry_count * sizeof(ebpf_trampoline_entry_t), EBPF_MEMORY_EXECUTE);
        if (local_entries == NULL)
            return EBPF_ERROR_OUT_OF_RESOURCES;
    } else {
        // Verify the existing table is the correct size
        if (local_entry_count != function_count)
            return EBPF_ERROR_EXTENSION_FAILED_TO_LOAD;
    }

    size_t index;
    for (index = 0; index < local_entry_count; index++) {
        local_entries[index].load_rax = 0xa148;
        local_entries[index].indirect_address = &local_entries[index].address;
        local_entries[index].jmp_rax = 0xe0ff;
        local_entries[index].address = (void*)dispatch_table->function[index];
    }
    *entry_count = local_entry_count;
    *entries = local_entries;
    return EBPF_ERROR_SUCCESS;
}