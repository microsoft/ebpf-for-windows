/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/
#include <ntddk.h>
#include "types.h"
#include "protocol.h"
#include "ebpf_core.h"
#include "ebpf_platform.h"
#include <ntintsafe.h>

typedef enum
{
    ebpfPoolTag = 'fpbe'
} EBPF_POOL_TAG;

void* ebpf_allocate(size_t size, ebpf_memory_type_t type)
{
    return ExAllocatePool2(
        type == EBPF_MEMORY_EXECUTE ? POOL_FLAG_NON_PAGED_EXECUTE : POOL_FLAG_NON_PAGED,
        size,
        ebpfPoolTag
    );
}

void ebpf_free(void* memory)
{
    ExFreePool(memory);
}

ebpf_error_code_t ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result)
{
    return RtlSizeTMult(multiplicand, multiplier, result) == STATUS_SUCCESS ? EBPF_ERROR_SUCCESS : EBPF_ERROR_INVALID_PARAMETER;
}

ebpf_error_code_t ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result)
{
    return RtlSizeTAdd(augend, addend, result) == STATUS_SUCCESS ? EBPF_ERROR_SUCCESS : EBPF_ERROR_INVALID_PARAMETER;
}

void ebpf_lock_create(ebpf_lock_t* lock)
{
    KeInitializeSpinLock((PKSPIN_LOCK)lock);
}

void ebpf_lock_destroy(ebpf_lock_t* lock)
{
}

void ebpf_lock_lock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    KeAcquireSpinLock((PKSPIN_LOCK)lock, (PUCHAR)state);
}

void ebpf_lock_unlock(ebpf_lock_t* lock, ebpf_lock_state_t* state)
{
    KeReleaseSpinLock((PKSPIN_LOCK)lock, *(KIRQL*)state);
}

// NOTE:
// AVL tree gives a single struct containing both key and value
// Compare can be called with a partial struct only containing the key.
// Do not access beyond map->ebpf_map_definition.key_size bytes.
static RTL_GENERIC_COMPARE_RESULTS
ebpf_hash_map_compare(
    _In_ struct _RTL_AVL_TABLE* table,
    _In_ PVOID  first_struct,
    _In_ PVOID  second_struct
)
{
    size_t sizes = (size_t)table->TableContext;
    uint16_t key_size = (uint16_t)(sizes >> 16);
    int result = memcmp(first_struct, second_struct, key_size);
    if (result < 0)
    {
        return GenericLessThan;
    }
    else if (result > 0)
    {
        return GenericGreaterThan;
    }
    else
    {
        return GenericEqual;
    }
}

static PVOID
ebpf_hash_map_allocate(
    _In_ struct _RTL_AVL_TABLE* table,
    _In_ CLONG  byte_size
)
{
    UNREFERENCED_PARAMETER(table);
    return ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        byte_size,
        ebpfPoolTag
    );
}

static VOID
ebpf_hash_map_free(
    _In_ struct _RTL_AVL_TABLE* table,
    _In_ PVOID  buffer
)
{
    UNREFERENCED_PARAMETER(table);
    ExFreePool(buffer);
}

ebpf_error_code_t ebpf_hash_table_create(ebpf_hash_table_t** hash_table, size_t key_size, size_t value_size)
{
    ebpf_error_code_t retval;
    RTL_AVL_TABLE* table = NULL;
    uint32_t sizes = ((uint16_t)key_size << 16) | (uint16_t)value_size;

    // allocate
    table = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RTL_AVL_TABLE),
        ebpfPoolTag
    );
    if (table == NULL) {
        retval = EBPF_ERROR_OUT_OF_RESOURCES;
        goto Done;
    }

    RtlInitializeGenericTableAvl(table, ebpf_hash_map_compare, ebpf_hash_map_allocate, ebpf_hash_map_free, (PVOID)sizes);

    *hash_table = (ebpf_hash_table_t*)table;
    retval = EBPF_ERROR_SUCCESS;
Done:
    return retval;
}

void ebpf_hash_table_destroy(ebpf_hash_table_t* hash_table)
{
    ExFreePool(hash_table);
}

ebpf_error_code_t ebpf_hash_table_lookup(ebpf_hash_table_t* hash_table, const uint8_t* key, uint8_t** value)
{
    ebpf_error_code_t retval;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;
    size_t sizes = (size_t)table->TableContext;
    uint16_t key_size = (uint16_t)(sizes >> 16);

    entry = RtlLookupElementGenericTableAvl(table, (uint8_t*)key);

    if (!entry)
    {
        *value = entry + key_size;
        retval = EBPF_ERROR_SUCCESS;
    }
    else
    {
        retval = EBPF_ERROR_NOT_FOUND;
    }
    return retval;
}

ebpf_error_code_t ebpf_hash_table_update(ebpf_hash_table_t* hash_table, const uint8_t* key, const uint8_t* value)
{
    ebpf_error_code_t retval;
    RTL_AVL_TABLE* table = (RTL_AVL_TABLE*)hash_table;
    uint8_t* entry;
    size_t sizes = (size_t)table->TableContext;
    uint16_t key_size = (uint16_t)(sizes >> 16);
    uint16_t value_size = sizes & 0xFFFF;
    uint8_t* temp = NULL;
    size_t temp_size = key_size + value_size;
    BOOLEAN new_entry;

    if (!hash_table || !key || !value)
    {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    temp = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        temp_size,
        ebpfPoolTag
    );

    if (!temp)
    {
        retval = EBPF_ERROR_INVALID_PARAMETER;
        goto Done;
    }

    memcpy(temp, key, key_size);
    memcpy(temp + key_size, value, value_size);

    entry = RtlInsertElementGenericTableAvl(table, temp, (CLONG)temp_size, &new_entry);

    // Update existing entry
    if (!new_entry)
    {
        memcpy(entry + key_size, value, value_size);
    }
    retval = EBPF_ERROR_SUCCESS;

Done:
    if (temp != NULL)
    {
        ExFreePool(temp);
    }

    return retval;
}

ebpf_error_code_t ebpf_hash_table_delete(ebpf_hash_table_t* hash_table, const uint8_t* key)
{
    PRTL_AVL_TABLE table = NULL;
    BOOLEAN result;

    result = RtlDeleteElementGenericTableAvl(table, (uint8_t*)key);
    return result == FALSE ? EBPF_ERROR_NOT_FOUND : EBPF_ERROR_SUCCESS;
}

