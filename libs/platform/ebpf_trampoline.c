// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_tracelog.h"

#pragma pack(push)
#pragma pack(1)
typedef struct _ebpf_trampoline_entry
{
    uint16_t load_rax;
    void* indirect_address;
    uint16_t jmp_rax;
    void* address;
    uint32_t helper_id;
} ebpf_trampoline_entry_t;
#pragma pack(pop)

typedef struct _ebpf_trampoline_table
{
    ebpf_memory_descriptor_t* memory_descriptor;
    size_t entry_count;
    bool updated;
} ebpf_trampoline_table_t;

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_trampoline_table(size_t entry_count, _Outptr_ ebpf_trampoline_table_t** trampoline_table)
{
    EBPF_LOG_ENTRY();
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
    EBPF_RETURN_RESULT(return_value);
}

void
ebpf_free_trampoline_table(_Frees_ptr_opt_ ebpf_trampoline_table_t* trampoline_table)
{
    EBPF_LOG_ENTRY();
    if (trampoline_table) {
        ebpf_unmap_memory(trampoline_table->memory_descriptor);
        ebpf_free(trampoline_table);
    }
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_update_trampoline_table(
    _Inout_ ebpf_trampoline_table_t* trampoline_table,
    uint32_t helper_function_count,
    _In_reads_(helper_function_count) const uint32_t* helper_function_ids,
    _In_ const ebpf_helper_function_addresses_t* helper_function_addresses)
{
    EBPF_LOG_ENTRY();
#if defined(_AMD64_)

    size_t function_count = helper_function_addresses->helper_function_count;
    ebpf_trampoline_entry_t* local_entries;
    ebpf_result_t return_value;
    size_t index;
    size_t helper_index;
    uint32_t helper_id;

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

    for (helper_index = 0; helper_index < helper_function_count; helper_index++) {
        helper_id = helper_function_ids[helper_index];
        if (trampoline_table->updated) {
            // If the trampoline table has been updated earlier, ensure that the helper ids
            // have not changed on this update.
            for (index = 0; index < trampoline_table->entry_count; index++) {
                if (local_entries[index].helper_id == helper_id) {
                    break;
                }
            }
            if (index == trampoline_table->entry_count) {
                return_value = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }
        } else {
            // Trampoline table has not been updated yet. Use the next available slot.
            index = helper_index;
        }

        local_entries[index].load_rax = 0xa148;
        local_entries[index].indirect_address = &local_entries[index].address;
        local_entries[index].jmp_rax = 0xe0ff;
        local_entries[index].address = (void*)helper_function_addresses->helper_function_address[helper_index];
        local_entries[index].helper_id = helper_id;
    }
    trampoline_table->updated = true;

Exit:
    return_value = ebpf_protect_memory(trampoline_table->memory_descriptor, EBPF_PAGE_PROTECT_READ_EXECUTE);
    EBPF_RETURN_RESULT(return_value);
#elif
    UNREFERENCED_PARAMETER(trampoline_table);
    UNREFERENCED_PARAMETER(dispatch_table);
    EBPF_RETURN_RESULT(EBPF_OPERATION_NOT_SUPPORTED);
#endif
}

_Must_inspect_result_ ebpf_result_t
ebpf_get_trampoline_function(
    _In_ const ebpf_trampoline_table_t* trampoline_table, size_t helper_id, _Outptr_ void** function)
{
    EBPF_LOG_ENTRY();
    ebpf_trampoline_entry_t* local_entries;
    ebpf_result_t return_value;
    size_t index;

    local_entries =
        (ebpf_trampoline_entry_t*)ebpf_memory_descriptor_get_base_address(trampoline_table->memory_descriptor);
    if (!local_entries) {
        return_value = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (index = 0; index < trampoline_table->entry_count; index++) {
        if (local_entries[index].helper_id == helper_id) {
            break;
        }
    }
    if (index == trampoline_table->entry_count) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    *function = &(local_entries[index]);

    return_value = EBPF_SUCCESS;
Exit:
    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_get_trampoline_helper_address(
    _In_ const ebpf_trampoline_table_t* trampoline_table, size_t index, _Outptr_ void** helper_address)
{
    EBPF_LOG_ENTRY();
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

    *helper_address = local_entries[index].address;

    return_value = EBPF_SUCCESS;
Exit:
    EBPF_RETURN_RESULT(return_value);
}
