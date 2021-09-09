// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "ebpf_result.h"
#include "ebpf_windows.h"
#include "framework.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FROM_FIELD(s, m, o) (s*)((uint8_t*)o - EBPF_OFFSET_OF(s, m))

#define EBPF_DEVICE_NAME L"\\Device\\EbpfIoDevice"
#define EBPF_SYMBOLIC_DEVICE_NAME L"\\GLOBAL??\\EbpfIoDevice"
#define EBPF_DEVICE_WIN32_NAME L"\\\\.\\EbpfIoDevice"

#define EBPF_MAX_GENERAL_HELPER_FUNCTION 0xFFFF

#define EBPF_UTF8_STRING_FROM_CONST_STRING(x) \
    {                                         \
        ((uint8_t*)(x)), sizeof((x)) - 1      \
    }

#define EBPF_CACHE_LINE_SIZE 64
#define EBPF_CACHE_ALIGN_POINTER(P) (void*)(((uintptr_t)P + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))

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

    typedef enum _ebpf_code_integrity_state
    {
        EBPF_CODE_INTEGRITY_DEFAULT = 0,
        EBPF_CODE_INTEGRITY_HYPER_VISOR_KERNEL_MODE = 1
    } ebpf_code_integrity_state_t;

    typedef struct _ebpf_non_preemptible_work_item ebpf_non_preemptible_work_item_t;
    typedef struct _ebpf_timer_work_item ebpf_timer_work_item_t;
    typedef struct _ebpf_extension_client ebpf_extension_client_t;
    typedef struct _ebpf_extension_provider ebpf_extension_provider_t;
    typedef ebpf_result_t (*_ebpf_extension_dispatch_function)();
    typedef struct _ebpf_extension_dispatch_table
    {
        uint16_t version;
        uint16_t size;
        _ebpf_extension_dispatch_function function[1];
    } ebpf_extension_dispatch_table_t;

    typedef struct _ebpf_extension_data
    {
        uint16_t version;
        size_t size;
        void* data;
    } ebpf_extension_data_t;

    typedef struct _ebpf_attach_provider_data
    {
        ebpf_program_type_t supported_program_type;
    } ebpf_attach_provider_data_t;
#define EBPF_ATTACH_PROVIDER_DATA_VERSION 1

    typedef struct _ebpf_trampoline_table ebpf_trampoline_table_t;

    typedef uintptr_t ebpf_lock_t;
    typedef uint8_t ebpf_lock_state_t;

    // A self-relative security descriptor.
    typedef struct _SECURITY_DESCRIPTOR ebpf_security_descriptor_t;
    typedef struct _GENERIC_MAPPING ebpf_security_generic_mapping_t;
    typedef uint32_t ebpf_security_access_mask_t;

    typedef struct _ebpf_helper_function_addresses ebpf_helper_function_addresses_t;

    typedef enum _ebpf_hash_table_operations
    {
        EBPF_HASH_TABLE_OPERATION_ANY = 0,
        EBPF_HASH_TABLE_OPERATION_INSERT = 1,
        EBPF_HASH_TABLE_OPERATION_REPLACE = 2,
    } ebpf_hash_table_operations_t;

    /**
     * @brief Initialize the eBPF platform abstraction layer.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_platform_initiate();

    /**
     * @brief Terminate the eBPF platform abstraction layer.
     */
    void
    ebpf_platform_terminate();

    /**
     * @brief Allocate memory.
     * @param[in] size Size of memory to allocate
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
        _Post_writable_byte_size_(size) void* ebpf_allocate(size_t size);

    /**
     * @brief Free memory.
     * @param[in] memory Allocation to be freed.
     */
    void
    ebpf_free(_Frees_ptr_opt_ void* memory);

    /**
     * @brief Allocate memory that has a starting address that is cache aligned.
     * @param[in] size Size of memory to allocate
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_maybenull_
        _Post_writable_byte_size_(size) void* ebpf_allocate_cache_aligned(size_t size);

    /**
     * @brief Free memory that has a starting address that is cache aligned.
     * @param[in] memory Allocation to be freed.
     */
    void
    ebpf_free_cache_aligned(_Frees_ptr_opt_ void* memory);

    typedef enum _ebpf_page_protection
    {
        EBPF_PAGE_PROTECT_READ_ONLY,
        EBPF_PAGE_PROTECT_READ_WRITE,
        EBPF_PAGE_PROTECT_READ_EXECUTE,
    } ebpf_page_protection_t;

    typedef struct _ebpf_memory_descriptor ebpf_memory_descriptor_t;

    /**
     * @brief Allocate pages from physical memory and create a mapping into the
     * system address space.
     *
     * @param[in] length Size of memory to allocate (internally this gets rounded
     * up to a page boundary).
     * @return Pointer to an ebpf_memory_descriptor_t on success, NULL on failure.
     */
    ebpf_memory_descriptor_t*
    ebpf_map_memory(size_t length);

    /**
     * @brief Release physical memory previously allocated via ebpf_map_memory.
     *
     * @param[in] memory_descriptor Pointer to ebpf_memory_descriptor_t describing
     * allocated pages.
     */
    void
    ebpf_unmap_memory(_Frees_ptr_opt_ ebpf_memory_descriptor_t* memory_descriptor);

    /**
     * @brief Change the page protection on memory allocated via
     * ebpf_map_memory.
     *
     * @param[in] memory_descriptor Pointer to an ebpf_memory_descriptor_t
     * describing allocated pages.
     * @param[in] protection The new page protection to apply.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     */
    ebpf_result_t
    ebpf_protect_memory(_In_ const ebpf_memory_descriptor_t* memory_descriptor, ebpf_page_protection_t protection);

    /**
     * @brief Given an ebpf_memory_descriptor_t allocated via ebpf_map_memory
     * obtain the base virtual address.
     *
     * @param[in] memory_descriptor Pointer to an ebpf_memory_descriptor_t
     * describing allocated pages.
     * @return Base virtual address of pages that have been allocated.
     */
    void*
    ebpf_memory_descriptor_get_base_address(ebpf_memory_descriptor_t* memory_descriptor);

    /**
     * @brief Allocate and copy a UTF-8 string.
     *
     * @param[out] destination Pointer to memory where the new UTF-8 character
     * sequence will be allocated.
     * @param[in] source UTF-8 string that will be copied.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  UTF-8 string.
     */
    ebpf_result_t
    ebpf_duplicate_utf8_string(_Out_ ebpf_utf8_string_t* destination, _In_ const ebpf_utf8_string_t* source);

    /**
     * @brief Get the code integrity state from the platform.
     * @param[out] state The code integrity state being enforced.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_SUPPORTED Unable to obtain state from platform.
     */
    ebpf_result_t
    ebpf_get_code_integrity_state(_Out_ ebpf_code_integrity_state_t* state);

    /**
     * @brief Multiplies one value of type size_t by another and check for
     *   overflow.
     * @param[in] multiplicand The value to be multiplied by multiplier.
     * @param[in] multiplier The value by which to multiply multiplicand.
     * @param[out] result A pointer to the result.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Multiplication overflowed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_safe_size_t_multiply(
        size_t multiplicand, size_t multiplier, _Out_ _Deref_out_range_(==, multiplicand* multiplier) size_t* result);

    /**
     * @brief Add one value of type size_t by another and check for
     *   overflow.
     * @param[in] augend The value to be added by addend.
     * @param[in] addend The value add to augend.
     * @param[out] result A pointer to the result.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Addition overflowed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_safe_size_t_add(size_t augend, size_t addend, _Out_ _Deref_out_range_(==, augend + addend) size_t* result);

    /**
     * @brief Subtract one value of type size_t from another and check for
     *   overflow or underflow.
     * @param[in] minuend The value from which subtrahend is subtracted.
     * @param[in] subtrahend The value subtract from minuend.
     * @param[out] result A pointer to the result.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_ARITHMETIC_OVERFLOW Addition overflowed or underflowed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_safe_size_t_subtract(
        size_t minuend, size_t subtrahend, _Out_ _Deref_out_range_(==, minuend - subtrahend) size_t* result);

    /**
     * @brief Create an instance of a lock.
     * @param[out] lock Pointer to memory location that will contain the lock.
     */
    void
    ebpf_lock_create(_Out_ ebpf_lock_t* lock);

    /**
     * @brief Destroy an instance of a lock.
     * @param[in] lock Pointer to memory location that contains the lock.
     */
    void
    ebpf_lock_destroy(_In_ ebpf_lock_t* lock);

    /**
     * @brief Acquire exclusive access to the lock.
     * @param[in] lock Pointer to memory location that contains the lock.
     * @returns - The previous lock_state required for unlock.
     */
    _Requires_lock_not_held_(*lock) _Acquires_lock_(*lock) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
        _IRQL_raises_(DISPATCH_LEVEL) ebpf_lock_state_t ebpf_lock_lock(_In_ ebpf_lock_t* lock);

    /**
     * @brief Release exclusive access to the lock.
     * @param[in] lock Pointer to memory location that contains the lock.
     * @param[in] state The state returned from ebpf_lock_lock.
     */
    _Requires_lock_held_(*lock) _Releases_lock_(*lock) _IRQL_requires_(DISPATCH_LEVEL) void ebpf_lock_unlock(
        _In_ ebpf_lock_t* lock, _IRQL_restores_ ebpf_lock_state_t state);

    /**
     * @brief Query the platform for the total number of CPUs.
     * @return The count of logical cores in the system.
     */
    _Ret_range_(>, 0) uint32_t ebpf_get_cpu_count();

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
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  work item.
     */
    ebpf_result_t
    ebpf_allocate_non_preemptible_work_item(
        _Out_ ebpf_non_preemptible_work_item_t** work_item,
        uint32_t cpu_id,
        _In_ void (*work_item_routine)(void* work_item_context, void* parameter_1),
        _In_opt_ void* work_item_context);

    /**
     * @brief Free a non-preemptible work item.
     *
     * @param[in] work_item Pointer to the work item to free.
     */
    void
    ebpf_free_non_preemptible_work_item(_Frees_ptr_opt_ ebpf_non_preemptible_work_item_t* work_item);

    /**
     * @brief Schedule a non-preemptible work item to run.
     *
     * @param[in] work_item Work item to schedule.
     * @param[in] parameter_1 Parameter to pass to work item.
     * @retval true Work item was queued.
     * @retval false Work item is already queued.
     */
    bool
    ebpf_queue_non_preemptible_work_item(_In_ ebpf_non_preemptible_work_item_t* work_item, _In_opt_ void* parameter_1);

    /**
     * @brief Allocate a timer to run a non-preemptible work item.
     *
     * @param[out] timer Pointer to memory that will contain timer on success.
     * @param[in] work_item_routine Routine to execute when time expires.
     * @param[in] work_item_context Context to pass to routine.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  timer.
     */
    ebpf_result_t
    ebpf_allocate_timer_work_item(
        _Out_ ebpf_timer_work_item_t** timer,
        _In_ void (*work_item_routine)(void* work_item_context),
        _In_opt_ void* work_item_context);

    /**
     * @brief Schedule a work item to be executed after elaped_microseconds.
     *
     * @param[in] timer Pointer to timer to schedule.
     * @param[in] elapsed_microseconds Microseconds to delay before executing
     *   work item.
     */
    void
    ebpf_schedule_timer_work_item(_In_ ebpf_timer_work_item_t* timer, uint32_t elapsed_microseconds);

    /**
     * @brief Free a timer.
     *
     * @param[in] timer Timer to be freed.
     */
    void
    ebpf_free_timer_work_item(_Frees_ptr_opt_ ebpf_timer_work_item_t* timer);

    typedef struct _ebpf_hash_table ebpf_hash_table_t;

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
     * @param[in] bucket_count Count of buckets to use.
     * @param[in] extract_function Function used to convert a key into a value
     * that can be hashed and compared. If NULL, key is assumes to be
     * comparable.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  hash table.
     */
    ebpf_result_t
    ebpf_hash_table_create(
        _Out_ ebpf_hash_table_t** hash_table,
        _In_ void* (*allocate)(size_t size),
        _In_ void (*free)(void* memory),
        size_t key_size,
        size_t value_size,
        size_t bucket_count,
        _In_opt_ void (*extract_function)(
            _In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* length));

    /**
     * @brief Remove all items from the hash table and release memory.
     *
     * @param[in] hash_table Hash-table to release.
     */
    void
    ebpf_hash_table_destroy(_In_opt_ _Post_ptr_invalid_ ebpf_hash_table_t* hash_table);

    /**
     * @brief Find an element in the hash table.
     *
     * @param[in] hash_table Hash-table to search.
     * @param[in] key Key to find in hash table.
     * @param[out] value Pointer to value if found.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND Key not found in hash table.
     */
    ebpf_result_t
    ebpf_hash_table_find(_In_ ebpf_hash_table_t* hash_table, _In_ const uint8_t* key, _Outptr_ uint8_t** value);

    /**
     * @brief Insert or update an entry in the hash table.
     *
     * @param[in] hash_table Hash-table to update.
     * @param[in] key Key to find and insert or update.
     * @param[in] value Value to insert into hash table or NULL to insert zero entry.
     * @param[in] operation One of ebpf_hash_table_operations_t operations.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate memory for this
     *  entry in the hash table.
     */
    ebpf_result_t
    ebpf_hash_table_update(
        _In_ ebpf_hash_table_t* hash_table,
        _In_ const uint8_t* key,
        _In_opt_ const uint8_t* value,
        ebpf_hash_table_operations_t operation);

    /**
     * @brief Remove an entry from the hash table.
     *
     * @param[in] hash_table Hash-table to update.
     * @param[in] key Key to find and remove.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_hash_table_delete(_In_ ebpf_hash_table_t* hash_table, _In_ const uint8_t* key);

    /**
     * @brief Find the next key in the hash table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key Next key if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No keys exist in the hash table that
     * are lexicographically after the specified key.
     */
    ebpf_result_t
    ebpf_hash_table_next_key(
        _In_ ebpf_hash_table_t* hash_table, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key);

    /**
     * @brief Returns the next (key, value) pair in the hash table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key Next key if it exists.
     * @param[out] next_value If non-NULL, returns the next value if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No keys exist in the hash table that
     * are lexicographically after the specified key.
     */
    ebpf_result_t
    ebpf_hash_table_next_key_and_value(
        _In_ ebpf_hash_table_t* hash_table,
        _In_opt_ const uint8_t* previous_key,
        _Out_ uint8_t* next_key,
        _Inout_opt_ uint8_t** next_value);

    /**
     * @brief Returns the next (key, value) pair in the hash table.
     *
     * @param[in] hash_table Hash-table to query.
     * @param[in] previous_key Previous key or NULL to restart.
     * @param[out] next_key_pointer Pointer to next key if one exists.
     * @param[out] next_value If non-NULL, returns the next value if it exists.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No keys exist in the hash table that
     * are lexicographically after the specified key.
     */
    ebpf_result_t
    ebpf_hash_table_next_key_pointer_and_value(
        _In_ ebpf_hash_table_t* hash_table,
        _In_opt_ const uint8_t* previous_key,
        _Outptr_ uint8_t** next_key_pointer,
        _Outptr_opt_ uint8_t** next_value);

    /**
     * @brief Get the number of keys in the hash table
     *
     * @param[in] hash_table  Hash-table to query.
     * @return Count of entries in the hash table.
     */
    size_t
    ebpf_hash_table_key_count(_In_ ebpf_hash_table_t* hash_table);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return The new value.
     */
    int32_t
    ebpf_interlocked_increment_int32(_Inout_ volatile int32_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to decrease by 1.
     * @return The new value.
     */
    int32_t
    ebpf_interlocked_decrement_int32(_Inout_ volatile int32_t* addend);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return The new value.
     */
    int64_t
    ebpf_interlocked_increment_int64(_Inout_ volatile int64_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in,out] addend Value to increase by 1.
     * @return The new value.
     */
    int64_t
    ebpf_interlocked_decrement_int64(_Inout_ volatile int64_t* addend);

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
    ebpf_interlocked_compare_exchange_int32(_Inout_ volatile int32_t* destination, int32_t exchange, int32_t comperand);

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
    void*
    ebpf_interlocked_compare_exchange_pointer(
        _Inout_ void* volatile* destination, _In_opt_ const void* exchange, _In_opt_ const void* comperand);

    typedef void (*ebpf_extension_change_callback_t)(
        _In_ void* client_binding_context,
        _In_ const void* provider_binding_context,
        _In_opt_ const ebpf_extension_data_t* provider_data);

    /**
     * @brief Load an extension and get its dispatch table.
     *
     * @param[out] client_context Context used to unload the extension.
     * @param[in] interface_id GUID representing the identity of the interface.
     * @param[in] extension_client_context Opaque per-instance pointer passed to the extension.
     * @param[in] client_data Opaque client data passed to the extension or
        NULL if there is none.
     * @param[in] client_data_length Length of the client data.
     * @param[in] client_dispatch_table Table of function pointers the client
     *  exposes or NULL if there is none.
     * @param[out] provider_binding_context Provider binding context. Can be NULL.
     * @param[out] provider_data Opaque provider data. Can be NULL.
     * @param[out] provider_dispatch_table Table of function pointers the
     *  provider exposes. Can be NULL.
     * @param[in] extension_changed Callback invoked when a provider attaches
     *  or detaches. NULL if not used.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND The provider was not found.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_extension_load(
        _Outptr_ ebpf_extension_client_t** client_context,
        _In_ const GUID* interface_id,
        _In_ void* extension_client_context,
        _In_opt_ const ebpf_extension_data_t* client_data,
        _In_opt_ const ebpf_extension_dispatch_table_t* client_dispatch_table,
        _Outptr_opt_ void** provider_binding_context,
        _Outptr_opt_ const ebpf_extension_data_t** provider_data,
        _Outptr_opt_ const ebpf_extension_dispatch_table_t** provider_dispatch_table,
        _In_opt_ ebpf_extension_change_callback_t extension_changed);

    /**
     * @brief Helper function that returns an opaque client context from an extension client.
     *
     * @param[in] extension_client_binding_context Opaque pointer to an extension client binding context. This is the
     * same as the extension_client_binding_context input parameter obtained in the _ebpf_extension_dispatch_function
     * callback function.
     *
     * @returns Pointer to opaque per-instance context that was passed in call to ebpf_extension_load, or NULL on
     * failure.
     */
    void*
    ebpf_extension_get_client_context(_In_ const void* extension_client_binding_context);

    /**
     * @brief Unload an extension.
     *
     * @param[in] client_context Context of the extension to unload.
     */
    void
    ebpf_extension_unload(_Frees_ptr_opt_ ebpf_extension_client_t* client_context);

    typedef ebpf_result_t (*ebpf_provider_client_attach_callback_t)(
        void* context,
        const GUID* client_id,
        void* client_binding_context,
        const ebpf_extension_data_t* client_data,
        const ebpf_extension_dispatch_table_t* client_dispatch_table);

    typedef ebpf_result_t (*ebpf_provider_client_detach_callback_t)(void* context, const GUID* client_id);

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
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_EXTENSION_FAILED_TO_LOAD The provider was unable to
     *  load.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_provider_load(
        _Outptr_ ebpf_extension_provider_t** provider_context,
        _In_ const GUID* interface_id,
        _In_opt_ void* provider_binding_context,
        _In_opt_ const ebpf_extension_data_t* provider_data,
        _In_opt_ const ebpf_extension_dispatch_table_t* provider_dispatch_table,
        _In_opt_ void* callback_context,
        _In_opt_ ebpf_provider_client_attach_callback_t client_attach_callback,
        _In_opt_ ebpf_provider_client_detach_callback_t client_detach_callback);

    /**
     * @brief Unload a provider.
     *
     * @param[in] provider_context Provider to unload.
     */
    void
    ebpf_provider_unload(_Frees_ptr_opt_ ebpf_extension_provider_t* provider_context);

    ebpf_result_t
    ebpf_guid_create(_Out_ GUID* new_guid);

    int32_t
    ebpf_log_function(_In_ void* context, _In_z_ const char* format_string, ...);

    /**
     * @brief Allocate a new empty trampoline table of entry_count size.
     *
     * @param[in] entry_count Maximum number of functions to build trampolines for.
     * @param[out] trampoline_table Pointer to memory that holds the trampoline
     * table on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_allocate_trampoline_table(size_t entry_count, _Outptr_ ebpf_trampoline_table_t** trampoline_table);

    /**
     * @brief Free a previously allocated trampoline table.
     *
     * @param[in] trampoline_table Pointer to trampoline table to free.
     */
    void
    ebpf_free_trampoline_table(_Frees_ptr_opt_ ebpf_trampoline_table_t* trampoline_table);

    /**
     * @brief Populate the function pointers in a trampoline table.
     *
     * @param[in] trampoline_table Trampoline table to populate.
     * @param[in] helper_function_count Count of helper functions.
     * @param[in] helper_function_ids Array of helper function IDs.
     * @param[in] dispatch_table Dispatch table to populate from.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     */
    ebpf_result_t
    ebpf_update_trampoline_table(
        _Inout_ ebpf_trampoline_table_t* trampoline_table,
        uint32_t helper_function_count,
        _In_reads_(helper_function_count) const uint32_t* helper_function_ids,
        _In_ const ebpf_helper_function_addresses_t* helper_function_addresses);

    /**
     * @brief Get the address of a trampoline function.
     *
     * @param[in] trampoline_table Trampoline table to query.
     * @param[in] index Index of function to get.
     * @param[out] function Pointer to memory that contains the function on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     */
    ebpf_result_t
    ebpf_get_trampoline_function(
        _In_ const ebpf_trampoline_table_t* trampoline_table, size_t index, _Out_ void** function);

    /**
     * @brief Get the address of the helper function from the trampoline table entry.
     *
     * @param[in] trampoline_table Trampoline table to query.
     * @param[in] index Index of trampoline table entry.
     * @param[out] helper_address Pointer to memory that contains the address to helper function on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     */
    ebpf_result_t
    ebpf_get_trampoline_helper_address(
        _In_ const ebpf_trampoline_table_t* trampoline_table, size_t index, _Out_ void** helper_address);

    typedef struct _ebpf_program_info ebpf_program_info_t;

    /**
     * @brief Serialize an ebpf_program_info_t structure into a flat
     *  buffer.
     *
     * @param[in] program_info ebpf_program_info_t to be serialized.
     * @param[out] buffer On success, the buffer that contains the serialized
     *  structure. Must be freed by caller using ebpf_free.
     * @param[out] buffer_size On success, the size of the serialized buffer.
     * @retval EBPF_SUCCESS The operation succeeded.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_program_info_encode(
        _In_ const ebpf_program_info_t* program_info,
        _Outptr_result_bytebuffer_(*buffer_size) uint8_t** buffer,
        _Out_ unsigned long* buffer_size);

    /**
     * @brief Deserialize an ebpf_program_info_t structure from a flat
     *  buffer.
     *
     * @param[out] program_info On success, a newly allocated
     *  ebpf_program_info_t with the data from the flat buffer. Must be
     *  freed by the caller using ebpf_free.
     * @param[in] buffer Buffer containing the serialized structure.
     * @param[in] buffer_size Size of the buffer.
     * @retval EBPF_SUCCESS The operation succeeded.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    ebpf_result_t
    ebpf_program_info_decode(
        _Outptr_ ebpf_program_info_t** program_info,
        _In_ _Readable_bytes_(buffer_size) const uint8_t* buffer,
        size_t buffer_size);

    /**
     * @brief Check if the user associated with the current thread is granted
     *  the rights requested.
     *
     * @param[in] security_descriptor Security descriptor representing the
     *  security policy.
     * @param[in] request_access Access the caller is requesting.
     * @param[in] generic_mapping Mappings for generic read/write/execute to
     *  specific rights.
     * @retval EBPF_SUCCESS Requested access is granted.
     * @retval EBPF_ACCESS_DENIED Requested access is denied.
     */
    ebpf_result_t
    ebpf_access_check(
        _In_ ebpf_security_descriptor_t* security_descriptor,
        ebpf_security_access_mask_t request_access,
        _In_ ebpf_security_generic_mapping_t* generic_mapping);

    /**
     * @brief Check the validity of the provided security descriptor.
     *
     * @param[in] security_descriptor Security descriptor to verify.
     * @param[in] security_descriptor_length Length of security descriptor.
     * @retval EBPF_SUCCESS Security descriptor is well formed.
     * @retval EBPF_INVALID_ARGUMENT Security descriptor is malformed.
     */
    ebpf_result_t
    ebpf_validate_security_descriptor(
        _In_ ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length);

    /**
     * @brief Return a pseudorandom number.
     *
     * @return A pseudorandom number.
     */
    uint32_t
    ebpf_random_uint32();

    /**
     * @brief Return time elapsed since boot in units of 100 nanoseconds.
     *
     * @return Time elapsed since boot in 100 nanosecond units.
     */
    uint64_t
    ebpf_query_interrupt_time_precise();

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <memory>
namespace ebpf_helper {

struct _ebpf_free_functor
{
    void
    operator()(void* memory)
    {
        ebpf_free(memory);
    }
};

typedef std::unique_ptr<void, _ebpf_free_functor> ebpf_memory_ptr;

} // namespace ebpf_helper

#endif
