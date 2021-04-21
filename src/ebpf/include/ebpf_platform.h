/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "framework.h"
#include "ebpf_object.h"
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

    typedef struct _epbf_non_preemptible_work_item epbf_non_preemptible_work_item_t;
    typedef struct _ebpf_timer_work_item ebpf_timer_work_item_t;
    typedef struct _ebpf_extension_client ebpf_extension_client_t;
    typedef ebpf_error_code_t (*_ebpf_extension_dispatch_function)();
    typedef struct _ebpf_extension_dispatch_table
    {
        size_t size;
        _ebpf_extension_dispatch_function function[1];
    } ebpf_extension_dispatch_table_t;

#define EBPF_LOCK_SIZE sizeof(uint64_t)
#define EBPF_LOCK_STATE_SIZE sizeof(uint64_t)
    typedef uint8_t ebpf_lock_t[EBPF_LOCK_SIZE];
    typedef uint8_t ebpf_lock_state_t[EBPF_LOCK_STATE_SIZE];

    /**
     *  @brief Initialize the eBPF platform abstraction layer.
     */
    ebpf_error_code_t
    ebpf_platform_initiate();

    /**
     *  @brief Terminate the eBPF platform abstraction layer.
     */
    void
    ebpf_platform_terminate();

    /**
     * @brief Allocate memory.
     * @param[in] size Size of memory to allocate
     * @param[in] type Allocate memory as executable vs non-executable
     * @returns Pointer to memory block allocated, or null on failure.
     */
    void*
    ebpf_allocate(size_t size, ebpf_memory_type_t type);

    /**
     * @brief Free memory.
     * @param[in] memory Allocation to be freed.
     */
    void
    ebpf_free(void* memory);

    /**
     * @brief Get the code integrity state from the platform.
     * @param[out] state The code integrity state being enforced.
     * @retval EBPF_ERROR_INVALID_PARAMETER Call to platform to get code
     *   integrity state failed.
     */
    ebpf_error_code_t
    ebpf_get_code_integrity_state(ebpf_code_integrity_state_t* state);

    /**
     * @brief Multiplies one value of type size_t by another and check for
     *   overflow.
     * @param[in] multiplicand The value to be multiplied by multiplier.
     * @param[in] multiplicand The value by which to multiply multiplicand.
     * @param[out] result A pointer to the result.
     * @retval EBPF_ERROR_INVALID_PARAMETER Multiplication overflowed.
     */
    ebpf_error_code_t
    ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result);

    /**
     * @brief Add one value of type size_t by another and check for
     *   overflow.
     * @param[in] augend The value to be added by addend.
     * @param[in] addend The value add to augend.
     * @param[out] result A pointer to the result.
     * @retval EBPF_ERROR_INVALID_PARAMETER Addition overflowed.
     */
    ebpf_error_code_t
    ebpf_safe_size_t_add(size_t augend, size_t addend, size_t* result);

    /**
     * @brief Create an instance of a lock.
     * @param[in] lock Pointer to memory location that will contain the lock.
     */
    void
    ebpf_lock_create(ebpf_lock_t* lock);

    /**
     * @brief Destroy an instance of a lock.
     * @param[in] lock Pointer to memory location that contains the lock.
     */
    void
    ebpf_lock_destroy(ebpf_lock_t* lock);

    /**
     * @brief Acquire exclusive access to the lock.
     * @param[in] lock Pointer to memory location that contains the lock.
     * @param[out] state Pointer to memory location that contains state that
     *    needs to be passed to ebpf_lock_unlock.
     */
    void
    ebpf_lock_lock(ebpf_lock_t* lock, ebpf_lock_state_t* state);

    /**
     * @brief Release exclusive access to the lock.
     * @param[in] lock Pointer to memory location that contains the lock.
     * @param[in] state Pointer to memory location that contains state that
     *    needs to be passed to ebpf_lock_unlock.
     */
    void
    ebpf_lock_unlock(ebpf_lock_t* lock, ebpf_lock_state_t* state);

    /**
     * @brief Query the platform for the total number of CPUs.
     * @param[out] cpu_count Pointer to memory location that contains the
     *    number of CPUs.
     */
    void
    ebpf_get_cpu_count(uint32_t* cpu_count);

    /**
     * @brief Query the platform to determine if the current execution can
     *    be preempted by other execution.
     * @return True if this execution can be preempted.
     */
    bool
    ebpf_is_preemptible();

    /**
     * @brief Query the platform to determine which CPU this execution is
     *   running on. Only valid if ebpf_is_preemptible() == true.
     * @return Zero based index of CPUs.
     */
    uint32_t
    ebpf_get_current_cpu();

    /**
     * @brief Query the platform to determine an opaque identifier for the
     *   current thread. Only valid if ebpf_is_preemptible() == false.
     * @return Zero based index of CPUs.
     */
    uint64_t
    ebpf_get_current_thread_id();

    /**
     * @brief Query the platform to determine if non-preemptible work items are
     *   supported.
     *
     * @return true non-preemptible work items are supported.
     */
    bool
    ebpf_is_non_preemptible_work_item_supported();

    /**
     * @brief Create a non-preemptible work item.
     *
     * @param[out] work_item Pointer to memory that will contain the pointer to
     *  the non-preemptible work item on success.
     * @param[in] cpu_id Associate the work item with this CPU.
     * @param[in] work_item_routine Routine to execute as a work item.
     * @param[in] work_item_context Context to pass to the routine.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  work item.
     */
    ebpf_error_code_t
    ebpf_allocate_non_preemptible_work_item(
        epbf_non_preemptible_work_item_t** work_item,
        uint32_t cpu_id,
        void (*work_item_routine)(void* work_item_context, void* parameter_1),
        void* work_item_context);

    /**
     * @brief Free a non-preemptible work item.
     *
     * @param[in] work_item Pointer to the work item to free.
     */
    void
    ebpf_free_non_preemptible_work_item(epbf_non_preemptible_work_item_t* work_item);

    /**
     * @brief Schedule a non-preemptible work item to run.
     *
     * @param[in] work_item Work item to schedule.
     * @param[in] parameter_1 Parameter to pass to work item.
     * @retval false Work item is already queued.
     */
    bool
    ebpf_queue_non_preemptible_work_item(epbf_non_preemptible_work_item_t* work_item, void* parameter_1);

    /**
     * @brief Allocate a timer to run a non-preemptible work item.
     *
     * @param[out] timer Pointer to memory that will contain timer on success.
     * @param[in] work_item_routine Routine to execute when time expires.
     * @param[in] work_item_context Context to pass to routine.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  timer.
     */
    ebpf_error_code_t
    ebpf_allocate_timer_work_item(
        ebpf_timer_work_item_t** timer, void (*work_item_routine)(void* work_item_context), void* work_item_context);

    /**
     * @brief Schedule
     *
     * @param[in] timer Pointer to timer to schedule.
     * @param[in] elapsed_microseconds Microseconds to delay before executing
     *   work item.
     */
    void
    ebpf_schedule_timer_work_item(ebpf_timer_work_item_t* timer, uint32_t elapsed_microseconds);

    /**
     * @brief Free a timer.
     *
     * @param[in] work_item Timer to be freed.
     */
    void
    ebpf_free_timer_work_item(ebpf_timer_work_item_t* timer);

    typedef struct _ebpf_hash_table ebpf_hash_table_t;

    typedef enum _ebpf_hash_table_compare_result
    {
        EBPF_HASH_TABLE_LESS_THAN = 0,
        EBPF_HASH_TABLE_GREATER_THAN = 1,
        EBPF_HASH_TABLE_EQUAL = 2,
    } ebpf_hash_table_compare_result_t;

    /**
     * @brief Allocate and initialize a hash table.
     *
     * @param[out] hash_table Pointer to memory that will contain hash-table on
     *   success.
     * @param[in] allocate Function to use when allocating elements in the
     *   hash-table.
     * @param[in] free Function to use when freeing elements in the hash-table.
     * @param[in] key_size Size of the keys used in the hash-table.
     * @param[in] value_size
     * @param[in] compare_function
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  hash-table.
     */
    ebpf_error_code_t
    ebpf_hash_table_create(
        ebpf_hash_table_t** hash_table,
        void* (*allocate)(size_t size, ebpf_memory_type_t type),
        void (*free)(void* memory),
        size_t key_size,
        size_t value_size,
        ebpf_hash_table_compare_result_t (*compare_function)(const uint8_t* key1, const uint8_t* key2));

    /**
     * @brief Remove all items from the hash table and release memory.
     *
     * @param[in] hash_table Hash-table to release.
     */
    void
    ebpf_hash_table_destroy(ebpf_hash_table_t* hash_table);

    /**
     * @brief Find an element in the hash-table.
     *
     * @param[in] hash_table Hash-table to search.
     * @param[in] key Key to find in hash-table.
     * @param[out] value Pointer to value if found.
     * @retval EBPF_ERROR_NOT_FOUND Key not found in hash-table.
     */
    ebpf_error_code_t
    ebpf_hash_table_lookup(ebpf_hash_table_t* hash_table, const uint8_t* key, uint8_t** value);

    /**
     * @brief Insert or update an entry in the hash-table.
     *
     * @param[in] hash_table Hash-table to update.
     * @param[in] key Key to find and insert or update.
     * @param[in] value Value to insert into hash-table.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate memory for this
     *  entry in the hash-table.
     */
    ebpf_error_code_t
    ebpf_hash_table_update(ebpf_hash_table_t* hash_table, const uint8_t* key, const uint8_t* value);

    /**
     * @brief Remove an entry from the hash-table.
     *
     * @param hash_table Hash-table to update.
     * @param key Key to find and remove.
     * @return ebpf_error_code_t
     */
    ebpf_error_code_t
    ebpf_hash_table_delete(ebpf_hash_table_t* hash_table, const uint8_t* key);

    /**
     * @brief Find the next key in the hash-table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key Next key if it exists.
     * @retval EBPF_ERROR_NO_MORE_KEYS Previous_key is the last key.
     */
    ebpf_error_code_t
    ebpf_hash_table_next_key(ebpf_hash_table_t* hash_table, const uint8_t* previous_key, uint8_t* next_key);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return int32_t The new value.
     */
    int32_t
    ebpf_interlocked_increment_int32(volatile int32_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to decrease by 1.
     * @return int32_t The new value.
     */
    int32_t
    ebpf_interlocked_decrement_int32(volatile int32_t* addend);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return int64_t The new value.
     */
    int64_t
    ebpf_interlocked_increment_int64(volatile int64_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return int64_t The new value.
     */
    int64_t
    ebpf_interlocked_decrement_int64(volatile int64_t* addend);

    /**
     * @brief Performs an atomic operation that compares the input value pointed
     *  to by destination with the value of comperand and replaces it with
     *  exchange.
     *
     * @param[in,out] destination A pointer to the input value that is compared
     *  with the value of comperand.
     * @param[in] exchange Specifies the output value pointed to by destination
     *  if the input value pointed to by destination equals the value of
     *  comperand.
     * @param[in] comperand Specifies the value that is compared with the input
     *  value pointed to by destination.
     * @return int32_t Returns the original value of memory pointed to by
     *  destination.
     */
    int32_t
    ebpf_interlocked_compare_exchange_int32(volatile int32_t* destination, int32_t exchange, int32_t comperand);

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
