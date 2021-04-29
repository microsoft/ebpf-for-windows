/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))

    /**
     * @brief A UTF-8 encoded string.
     * Notes:
     * 1) This string is not NULL terminated, instead relies on length.
     * 2) A single UTF-8 code point (aka character) could be 1-4 bytes in
     *  length.
     *
     */
    typedef struct _ebpf_utf8_string
    {
        uint8_t* value;
        size_t length;
    } ebpf_utf8_string_t;

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
    typedef struct _ebpf_extension_provider ebpf_extension_provider_t;
    typedef ebpf_error_code_t (*_ebpf_extension_dispatch_function)();
    typedef struct _ebpf_extension_dispatch_table
    {
        uint16_t version;
        uint16_t size;
        _ebpf_extension_dispatch_function function[1];
    } ebpf_extension_dispatch_table_t;

    typedef struct _ebpf_extension_data
    {
        uint16_t version;
        uint16_t size;
        uint8_t data[1];
    } ebpf_extension_data_t;

#define EBPF_LOCK_SIZE sizeof(uint64_t)
#define EBPF_LOCK_STATE_SIZE sizeof(uint64_t)
    typedef uint8_t ebpf_lock_t[EBPF_LOCK_SIZE];
    typedef uint8_t ebpf_lock_state_t[EBPF_LOCK_STATE_SIZE];

    /**
     *  @brief Initialize the eBPF platform abstraction layer.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  operation.
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
     * @brief Allocate and copy a UTF-8 string.
     *
     * @param[out] destination Pointer to memory where the new UTF-8 character
     * sequence will be allocated.
     * @param[in] source UTF-8 string that will be copied.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  UTF-8 string.
     */
    ebpf_error_code_t
    ebpf_duplicate_utf8_string(ebpf_utf8_string_t* destination, const ebpf_utf8_string_t* source);

    /**
     * @brief Get the code integrity state from the platform.
     * @param[out] state The code integrity state being enforced.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_NOT_SUPPORTED Unable to obtain state from platform.
     */
    ebpf_error_code_t
    ebpf_get_code_integrity_state(ebpf_code_integrity_state_t* state);

    /**
     * @brief Multiplies one value of type size_t by another and check for
     *   overflow.
     * @param[in] multiplicand The value to be multiplied by multiplier.
     * @param[in] multiplier The value by which to multiply multiplicand.
     * @param[out] result A pointer to the result.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Multiplication overflowed.
     */
    ebpf_error_code_t
    ebpf_safe_size_t_multiply(size_t multiplicand, size_t multiplier, size_t* result);

    /**
     * @brief Add one value of type size_t by another and check for
     *   overflow.
     * @param[in] augend The value to be added by addend.
     * @param[in] addend The value add to augend.
     * @param[out] result A pointer to the result.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Addition overflowed.
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
     * @retrval True if this execution can be preempted.
     */
    bool
    ebpf_is_preemptible();

    /**
     * @brief Query the platform to determine which CPU this execution is
     *   running on. Only valid if ebpf_is_preemptible() == true.
     * @retval Zero based index of CPUs.
     */
    uint32_t
    ebpf_get_current_cpu();

    /**
     * @brief Query the platform to determine an opaque identifier for the
     *   current thread. Only valid if ebpf_is_preemptible() == false.
     * @return Opaque identifier for the current thread.
     */
    uint64_t
    ebpf_get_current_thread_id();

    /**
     * @brief Query the platform to determine if non-preemptible work items are
     *   supported.
     *
     * @retval true Non-preemptible work items are supported.
     * @retval false Non-preemptible work items are not supported.
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
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
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
     * @retval true Work item was queued.
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
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  timer.
     */
    ebpf_error_code_t
    ebpf_allocate_timer_work_item(
        ebpf_timer_work_item_t** timer, void (*work_item_routine)(void* work_item_context), void* work_item_context);

    /**
     * @brief Schedule a work item to be executed after elaped_microseconds.
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
     * @param[in] timer Timer to be freed.
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
     * @param[out] hash_table Pointer to memory that will contain hash table on
     *   success.
     * @param[in] allocate Function to use when allocating elements in the
     *   hash table.
     * @param[in] free Function to use when freeing elements in the hash table.
     * @param[in] key_size Size of the keys used in the hash table.
     * @param[in] value_size Size of the values used in the hash table.
     * @param[in] compare_function Function used to lexicographically order
     * keys.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  hash table.
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
     * @brief Find an element in the hash table.
     *
     * @param[in] hash_table Hash-table to search.
     * @param[in] key Key to find in hash table.
     * @param[out] value Pointer to value if found.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_NOT_FOUND Key not found in hash table.
     */
    ebpf_error_code_t
    ebpf_hash_table_find(ebpf_hash_table_t* hash_table, const uint8_t* key, uint8_t** value);

    /**
     * @brief Insert or update an entry in the hash table.
     *
     * @param[in] hash_table Hash-table to update.
     * @param[in] key Key to find and insert or update.
     * @param[in] value Value to insert into hash table.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate memory for this
     *  entry in the hash table.
     */
    ebpf_error_code_t
    ebpf_hash_table_update(ebpf_hash_table_t* hash_table, const uint8_t* key, const uint8_t* value);

    /**
     * @brief Remove an entry from the hash table.
     *
     * @param[in] hash_table Hash-table to update.
     * @param[in] key Key to find and remove.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     */
    ebpf_error_code_t
    ebpf_hash_table_delete(ebpf_hash_table_t* hash_table, const uint8_t* key);

    /**
     * @brief Find the next key in the hash table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key Next key if it exists.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_NO_MORE_KEYS No keys exist in the hash table that
     * are lexicographically after the specified key.
     */
    ebpf_error_code_t
    ebpf_hash_table_next_key(ebpf_hash_table_t* hash_table, const uint8_t* previous_key, uint8_t* next_key);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return The new value.
     */
    int32_t
    ebpf_interlocked_increment_int32(volatile int32_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to decrease by 1.
     * @return The new value.
     */
    int32_t
    ebpf_interlocked_decrement_int32(volatile int32_t* addend);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return The new value.
     */
    int64_t
    ebpf_interlocked_increment_int64(volatile int64_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return The new value.
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
     * @return Returns the original value of memory pointed to by
     *  destination.
     */
    int32_t
    ebpf_interlocked_compare_exchange_int32(volatile int32_t* destination, int32_t exchange, int32_t comperand);

    /**
     * @brief Load an extension and get its dispatch table.
     *
     * @param[out] client_context Context used to unload the extension.
     * @param[in] interface_id GUID representing the identity of the interface.
     * @param[in] client_binding_context Opaque per-instance pointer passed to the extension.
     * @param[in] client_data Opaque client data passed to the extension.
     * @param[in] client_data_length Length of the client data.
     * @param[in] client_dispatch_table Table of function pointers the client
     *  exposes.
     * @param[in] provider_id GUID representing the extension to load.
     * @param[out] provider_data Opaque provider data.
     * @param[out] provider_dispatch_table Table of function pointers the
     *  provider exposes.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_NOT_FOUND The provider was not found.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  operation.
     */
    ebpf_error_code_t
    ebpf_extension_load(
        ebpf_extension_client_t** client_context,
        const GUID* interface_id,
        void* client_binding_context,
        const ebpf_extension_data_t* client_data,
        const ebpf_extension_dispatch_table_t* client_dispatch_table,
        void** provider_binding_context,
        const ebpf_extension_data_t** provider_data,
        const ebpf_extension_dispatch_table_t** provider_dispatch_table);

    /**
     * @brief Unload an extension.
     *
     * @param[in] client_context Context of the extension to unload.
     */
    void
    ebpf_extension_unload(ebpf_extension_client_t* client_context);

    typedef ebpf_error_code_t (*ebpf_provider_client_attach_callback_t)(
        void* context,
        const GUID* client_id,
        void* client_binding_context,
        const ebpf_extension_data_t* client_data,
        const ebpf_extension_dispatch_table_t* client_dispatch_table);

    typedef ebpf_error_code_t (*ebpf_provider_client_detach_callback_t)(void* context, const GUID* client_id);

    /**
     * @brief Register as an extension provider.
     *
     * @param[out] provider_context Context used to unload the provider.
     * @param[in] interface_id GUID representing the identity of the interface.
     * @param[in] provider_data Opaque provider data.
     * @param[in] provider_dispatch_table Table of function pointers the
     *  provider exposes.
     * @param[in] client_attach_callback Function invoked when a client attaches.
     * @param[in] client_detach_callback Function invoked when a client detaches.
     * @retval EBPF_ERROR_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_EXTENSION_FAILED_TO_LOAD The provider was unable to
     *  load.
     * @retval EBPF_ERROR_OUT_OF_RESOURCES Unable to allocate resources for this
     *  operation.
     */
    ebpf_error_code_t
    ebpf_provider_load(
        ebpf_extension_provider_t** provider_context,
        const GUID* interface_id,
        void* provider_binding_context,
        const ebpf_extension_data_t* provider_data,
        const ebpf_extension_dispatch_table_t* provider_dispatch_table,
        void* callback_context,
        ebpf_provider_client_attach_callback_t client_attach_callback,
        ebpf_provider_client_detach_callback_t client_detach_callback);

    /**
     * @brief Unload a provider.
     *
     * @param[in] provider_context Provider to unload.
     */
    void
    epbf_provider_unload(ebpf_extension_provider_t* provider_context);

    ebpf_error_code_t
    ebpf_guid_create(GUID* new_guid);

    int32_t
    ebpf_log_function(void* context, const char* format_string, ...);

#ifdef __cplusplus
}
#endif
