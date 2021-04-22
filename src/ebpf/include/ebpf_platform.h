/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "framework.h"
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))

    typedef enum _ebpf_memory_type
    {
        EBPF_MEMORY_NO_EXECUTE = 0,
        EBPF_MEMORY_EXECUTE = 1,
    } ebpf_memory_type_t;

    typedef enum _ebpf_code_integrity_state
    {
        EBPF_CODE_INTEGRITY_DEFAULT = 0,
        EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE = 1
    } ebpf_code_integrity_state_t;

    typedef struct _epbf_non_preemptable_work_item epbf_non_preepmtable_work_item_t;
    typedef struct _ebpf_timer_work_item ebpf_timer_work_item_t;
    typedef struct _ebpf_extension_client ebpf_extension_client_t;
    typedef ebpf_error_code_t (*_ebpf_extension_dispatch_function)();
    typedef struct _ebpf_extension_dispatch_table
    {
        size_t size;
        _ebpf_extension_dispatch_function function[1];
    } ebpf_extension_dispatch_table_t;

    ebpf_error_code_t
    ebpf_platform_initiate();

    void
    ebpf_platform_terminate();

    void*
    ebpf_allocate(size_t size, ebpf_memory_type_t type);
    void
    ebpf_free(void* memory);

    ebpf_error_code_t
    ebpf_query_code_integrity_state(ebpf_code_integrity_state_t* state);

#define EBPF_LOCK_SIZE sizeof(uint64_t)
#define EBPF_LOCK_STATE_SIZE sizeof(uint64_t)
    ebpf_error_code_t
    ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result);
    ebpf_error_code_t
    ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result);

    typedef uint8_t ebpf_lock_t[EBPF_LOCK_SIZE];
    typedef uint8_t ebpf_lock_state_t[EBPF_LOCK_STATE_SIZE];

    void
    ebpf_lock_create(ebpf_lock_t* lock);
    void
    ebpf_lock_destroy(ebpf_lock_t* lock);
    void
    ebpf_lock_lock(ebpf_lock_t* lock, ebpf_lock_state_t* state);
    void
    ebpf_lock_unlock(ebpf_lock_t* lock, ebpf_lock_state_t* state);

    ebpf_error_code_t
    ebpf_get_cpu_count(uint32_t* cpu_count);

    bool
    ebpf_is_preemptable();

    uint32_t
    ebpf_get_current_cpu();

    uint64_t
    ebpf_get_current_thread_id();

    bool
    ebpf_is_non_preepmtable_work_item_supported();

    ebpf_error_code_t
    ebpf_allocate_non_preemptable_work_item(
        epbf_non_preepmtable_work_item_t** work_item,
        uint32_t cpu_id,
        void (*work_item_routine)(void* work_item_context, void* parameter_1),
        void* work_item_context);

    void
    ebpf_free_non_preemptable_work_item(epbf_non_preepmtable_work_item_t* work_item);

    bool
    ebpf_queue_non_preemptable_work_item(epbf_non_preepmtable_work_item_t* work_item, void* parameter_1);

    ebpf_error_code_t
    ebpf_allocate_timer_work_item(
        ebpf_timer_work_item_t** work_item,
        void (*work_item_routine)(void* work_item_context),
        void* work_item_context);

    void
    ebpf_schedule_timer_work_item(ebpf_timer_work_item_t* work_item, uint32_t elaped_microseconds);

    void
    ebpf_free_timer_work_item(ebpf_timer_work_item_t* work_item);

    typedef struct _ebpf_hash_table ebpf_hash_table_t;

    typedef enum _ebpf_hash_table_compare_result
    {
        EBPF_HASH_TABLE_LESS_THAN = 0,
        EBPF_HASH_TABLE_GREATER_THAN = 1,
        EBPF_HASH_TABLE_EQUAL = 2,
    } ebpf_hash_table_compare_result_t;

    ebpf_error_code_t
    ebpf_hash_table_create(
        ebpf_hash_table_t** hash_table,
        void* (*allocate)(size_t size, ebpf_memory_type_t type),
        void (*free)(void* memory),
        size_t key_size,
        size_t value_size,
        ebpf_hash_table_compare_result_t (*compare_function)(const uint8_t* key1, const uint8_t* key2));

    void
    ebpf_hash_table_destroy(ebpf_hash_table_t* hash_table);
    ebpf_error_code_t
    ebpf_hash_table_lookup(ebpf_hash_table_t* hash_table, const uint8_t* key, uint8_t** value);
    ebpf_error_code_t
    ebpf_hash_table_update(ebpf_hash_table_t* hash_table, const uint8_t* key, const uint8_t* value);
    ebpf_error_code_t
    ebpf_hash_table_delete(ebpf_hash_table_t* hash_table, const uint8_t* key);
    ebpf_error_code_t
    ebpf_hash_table_next_key(ebpf_hash_table_t* hash_table, const uint8_t* previous_key, uint8_t* next_key);

    int32_t
    ebpf_interlocked_increment_int32(volatile int32_t* addend);

    int32_t
    ebpf_interlocked_decrement_int32(volatile int32_t* addend);

    int64_t
    ebpf_interlocked_increment_int64(volatile int64_t* addend);

    int64_t
    ebpf_interlocked_decrement_int64(volatile int64_t* addend);

    int32_t
    ebpf_interlocked_compare_exchange_int32(volatile int32_t* destination, int32_t exchange, int32_t comperand);

    typedef struct _ebpf_pinning_table ebpf_pinning_table_t;

    ebpf_error_code_t
    ebpf_pinning_table_allocate(
        ebpf_pinning_table_t** pinning_table, void (*acquire_reference)(void*), void (*release_reference)(void*));

    void
    ebpf_pinning_table_free(ebpf_pinning_table_t* pinning_table);

    ebpf_error_code_t
    ebpf_pinning_table_insert(ebpf_pinning_table_t* pinning_table, const uint8_t* name, void* object);

    ebpf_error_code_t
    ebpf_pinning_table_lookup(ebpf_pinning_table_t* pinning_table, const uint8_t* name, void** object);

    ebpf_error_code_t
    ebpf_pinning_table_delete(ebpf_pinning_table_t* pinning_table, const uint8_t* name);

    ebpf_error_code_t
    ebpf_pinning_table_next_name(ebpf_pinning_table_t* hash_table, const uint8_t* previous_name, uint8_t* next_name);

    ebpf_error_code_t
    ebpf_extension_load(
        ebpf_extension_client_t** client_context,
        GUID client_id,
        const uint8_t* client_data,
        size_t client_data_length,
        const ebpf_extension_dispatch_table_t* client_dispatch_table,
        GUID provider_id,
        uint8_t** provider_data,
        size_t* provider_data_length,
        ebpf_extension_dispatch_table_t** provider_dispatch_table);

    void
    ebpf_extension_unload(ebpf_extension_client_t* client_context);

#ifdef __cplusplus
}
#endif
