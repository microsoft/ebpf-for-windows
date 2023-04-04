// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_extension.h"
#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "framework.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

typedef intptr_t ebpf_handle_t;

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

#define EBPF_UTF8_STRING_FROM_CONST_STRING(x) \
    {                                         \
        ((uint8_t*)(x)), sizeof((x)) - 1      \
    }

#define EBPF_CACHE_LINE_SIZE 64
#define EBPF_CACHE_ALIGN_POINTER(P) (void*)(((uintptr_t)P + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))
#define EBPF_PAD_CACHE(X) ((X + EBPF_CACHE_LINE_SIZE - 1) & ~(EBPF_CACHE_LINE_SIZE - 1))
#define EBPF_PAD_8(X) ((X + 7) & ~7)

#define EBPF_HASH_TABLE_NO_LIMIT 0
#define EBPF_HASH_TABLE_DEFAULT_BUCKET_COUNT 64

#define EBPF_NS_PER_FILETIME 100

// Macro locally suppresses "Unreferenced variable" warning, which in 'Release' builds is treated as an error.
#define ebpf_assert_success(x)                                     \
    _Pragma("warning(push)") _Pragma("warning(disable : 4189)") do \
    {                                                              \
        ebpf_result_t _result = (x);                               \
        ebpf_assert(_result == EBPF_SUCCESS && #x);                \
    }                                                              \
    while (0)                                                      \
    _Pragma("warning(pop)")

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

    typedef enum _ebpf_pool_tag
    {
        EBPF_POOL_TAG_ASYNC = 'nsae',
        EBPF_POOL_TAG_CORE = 'roce',
        EBPF_POOL_TAG_DEFAULT = 'fpbe',
        EBPF_POOL_TAG_EPOCH = 'cpee',
        EBPF_POOL_TAG_LINK = 'knle',
        EBPF_POOL_TAG_MAP = 'pame',
        EBPF_POOL_TAG_NATIVE = 'vtne',
        EBPF_POOL_TAG_PROGRAM = 'grpe',
        EBPF_POOL_TAG_RING_BUFFER = 'fbre',
        EBPF_POOL_TAG_STATE = 'atse',
    } ebpf_pool_tag_t;

    typedef enum _ebpf_code_integrity_state
    {
        EBPF_CODE_INTEGRITY_DEFAULT = 0,
        EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE = 1
    } ebpf_code_integrity_state_t;

    typedef struct _ebpf_non_preemptible_work_item ebpf_non_preemptible_work_item_t;
    typedef struct _ebpf_preemptible_work_item ebpf_preemptible_work_item_t;
    typedef struct _ebpf_timer_work_item ebpf_timer_work_item_t;
    typedef struct _ebpf_extension_client ebpf_extension_client_t;
    typedef struct _ebpf_extension_provider ebpf_extension_provider_t;
    typedef struct _ebpf_helper_function_prototype ebpf_helper_function_prototype_t;

    typedef struct _ebpf_trampoline_table ebpf_trampoline_table_t;

    typedef uintptr_t ebpf_lock_t;
    typedef uint8_t ebpf_lock_state_t;

    // A self-relative security descriptor.
    typedef struct _SECURITY_DESCRIPTOR ebpf_security_descriptor_t;
    typedef struct _GENERIC_MAPPING ebpf_security_generic_mapping_t;
    typedef uint32_t ebpf_security_access_mask_t;

    typedef struct _ebpf_helper_function_addresses ebpf_helper_function_addresses_t;

    extern bool ebpf_fuzzing_enabled;

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_platform_initiate();

    /**
     * @brief Terminate the eBPF platform abstraction layer.
     */
    void
    ebpf_platform_terminate();

    /**
     * @brief Allocate memory.
     * @param[in] size Size of memory to allocate.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size);

    /**
     * @brief Allocate memory.
     * @param[in] size Size of memory to allocate.
     * @param[in] tag Pool tag to use.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_
        _Ret_writes_maybenull_(size) void* ebpf_allocate_with_tag(size_t size, uint32_t tag);

    /**
     * @brief Reallocate memory.
     * @param[in] memory Allocation to be reallocated.
     * @param[in] old_size Old size of memory to reallocate.
     * @param[in] new_size New size of memory to reallocate.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate(
        _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size);

    /**
     * @brief Reallocate memory with tag.
     * @param[in] memory Allocation to be reallocated.
     * @param[in] old_size Old size of memory to reallocate.
     * @param[in] new_size New size of memory to reallocate.
     * @param[in] tag Pool tag to use.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate_with_tag(
        _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size, uint32_t tag);

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
    __drv_allocatesMem(Mem) _Must_inspect_result_
        _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned(size_t size);

    /**
     * @brief Allocate memory that has a starting address that is cache aligned with tag.
     * @param[in] size Size of memory to allocate
     * @param[in] tag Pool tag to use.
     * @returns Pointer to memory block allocated, or null on failure.
     */
    __drv_allocatesMem(Mem) _Must_inspect_result_
        _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned_with_tag(size_t size, uint32_t tag);

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
    typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

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
    _Must_inspect_result_ ebpf_result_t
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
     * @brief Allocate pages from physical memory and create a mapping into the
     * system address space with the same pages mapped twice.
     *
     * @param[in] length Size of memory to allocate (internally this gets rounded
     * up to a page boundary).
     * @return Pointer to an ebpf_memory_descriptor_t on success, NULL on failure.
     */
    _Ret_maybenull_ ebpf_ring_descriptor_t*
    ebpf_allocate_ring_buffer_memory(size_t length);

    /**
     * @brief Release physical memory previously allocated via ebpf_allocate_ring_buffer_memory.
     *
     * @param[in] memory_descriptor Pointer to ebpf_ring_descriptor_t describing
     * allocated pages.
     */
    void
    ebpf_free_ring_buffer_memory(_Frees_ptr_opt_ ebpf_ring_descriptor_t* ring);

    /**
     * @brief Given an ebpf_ring_descriptor_t allocated via ebpf_allocate_ring_buffer_memory
     * obtain the base virtual address.
     *
     * @param[in] memory_descriptor Pointer to an ebpf_ring_descriptor_t
     * describing allocated pages.
     * @return Base virtual address of pages that have been allocated.
     */
    void*
    ebpf_ring_descriptor_get_base_address(_In_ const ebpf_ring_descriptor_t* ring);

    /**
     * @brief Create a read-only mapping in the calling process of the ring buffer.
     *
     * @param[in] ring Ring buffer to map.
     * @return Pointer to the base of the ring buffer.
     */
    _Ret_maybenull_ void*
    ebpf_ring_map_readonly_user(_In_ const ebpf_ring_descriptor_t* ring);

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_duplicate_utf8_string(_Out_ ebpf_utf8_string_t* destination, _In_ const ebpf_utf8_string_t* source);

    /**
     * @brief Free a UTF-8 string allocated by ebpf_duplicate_utf8_string.
     *
     * @param[in,out] string The string to free.
     */
    void
    ebpf_utf8_string_free(_Inout_ ebpf_utf8_string_t* string);

    /**
     * @brief Duplicate a null-terminated string.
     *
     * @param[in] source String to duplicate.
     * @return Pointer to the duplicated string or NULL if out of memory.
     */
    _Must_inspect_result_ char*
    ebpf_duplicate_string(_In_z_ const char* source);

    /**
     * @brief Get the code integrity state from the platform.
     * @param[out] state The code integrity state being enforced.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_SUPPORTED Unable to obtain state from platform.
     */
    _Must_inspect_result_ ebpf_result_t
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
    ebpf_lock_destroy(_In_ _Post_invalid_ ebpf_lock_t* lock);

    /**
     * @brief Acquire exclusive access to the lock.
     * @param[in, out] lock Pointer to memory location that contains the lock.
     * @returns The previous lock_state required for unlock.
     */
    _Requires_lock_not_held_(*lock) _Acquires_lock_(*lock) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
        _IRQL_raises_(DISPATCH_LEVEL) ebpf_lock_state_t ebpf_lock_lock(_Inout_ ebpf_lock_t* lock);

    /**
     * @brief Release exclusive access to the lock.
     * @param[in, out] lock Pointer to memory location that contains the lock.
     * @param[in] state The state returned from ebpf_lock_lock.
     */
    _Requires_lock_held_(*lock) _Releases_lock_(*lock) _IRQL_requires_(DISPATCH_LEVEL) void ebpf_lock_unlock(
        _Inout_ ebpf_lock_t* lock, _IRQL_restores_ ebpf_lock_state_t state);

    /**
     * @brief Raise the IRQL to new_irql.
     *
     * @param[in] new_irql The new IRQL.
     * @return The previous IRQL.
     */
    _IRQL_requires_max_(HIGH_LEVEL) _IRQL_raises_(new_irql) _IRQL_saves_ uint8_t ebpf_raise_irql(uint8_t new_irql);

    /**
     * @brief Lower the IRQL to old_irql.
     *
     * @param[in] old_irql The old IRQL.
     */
    _IRQL_requires_max_(HIGH_LEVEL) void ebpf_lower_irql(_In_ _Notliteral_ _IRQL_restores_ uint8_t old_irql);

    /**
     * @brief Query the platform for the total number of CPUs.
     * @return The count of logical cores in the system.
     */
    _Ret_range_(>, 0) uint32_t ebpf_get_cpu_count();

    /**
     * @brief Query the platform to determine if the current execution can
     *    be preempted by other execution.
     * @retval True if this execution can be preempted.
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
     * @param[in, out] work_item_context Context to pass to the routine.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  work item.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_allocate_non_preemptible_work_item(
        _Outptr_ ebpf_non_preemptible_work_item_t** work_item,
        uint32_t cpu_id,
        _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context, _Inout_opt_ void* parameter_1),
        _Inout_opt_ void* work_item_context);

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
     * @param[in, out] work_item Work item to schedule.
     * @param[in, out] parameter_1 Parameter to pass to work item.
     * @retval true Work item was queued.
     * @retval false Work item is already queued.
     */
    bool
    ebpf_queue_non_preemptible_work_item(
        _Inout_ ebpf_non_preemptible_work_item_t* work_item, _Inout_opt_ void* parameter_1);

    /**
     * @brief Create a preemptible work item.
     *
     * @param[out] work_item Pointer to memory that will contain the pointer to
     *  the preemptible work item on success.
     * @param[in] work_item_routine Routine to execute as a work item.
     * @param[in, out] work_item_context Context to pass to the routine.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  work item.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_allocate_preemptible_work_item(
        _Outptr_ ebpf_preemptible_work_item_t** work_item,
        _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
        _Inout_opt_ void* work_item_context);

    /**
     * @brief Free a preemptible work item.
     *
     * @param[in] work_item Pointer to the work item to free.
     */
    void
    ebpf_free_preemptible_work_item(_Frees_ptr_opt_ ebpf_preemptible_work_item_t* work_item);

    /**
     * @brief Schedule a preemptible work item to run.
     *
     * @param[in, out] work_item Work item to schedule.
     */
    void
    ebpf_queue_preemptible_work_item(_Inout_ ebpf_preemptible_work_item_t* work_item);

    /**
     * @brief Allocate a timer to run a non-preemptible work item.
     *
     * @param[out] timer Pointer to memory that will contain timer on success.
     * @param[in] work_item_routine Routine to execute when time expires.
     * @param[in, out] work_item_context Context to pass to routine.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  timer.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_allocate_timer_work_item(
        _Outptr_ ebpf_timer_work_item_t** timer,
        _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
        _Inout_opt_ void* work_item_context);

    /**
     * @brief Schedule a work item to be executed after elapsed_microseconds.
     *
     * @param[in, out] timer Pointer to timer to schedule.
     * @param[in] elapsed_microseconds Microseconds to delay before executing
     *   work item.
     */
    void
    ebpf_schedule_timer_work_item(_Inout_ ebpf_timer_work_item_t* timer, uint32_t elapsed_microseconds);

    /**
     * @brief Free a timer.
     *
     * @param[in] timer Timer to be freed.
     */
    void
    ebpf_free_timer_work_item(_Frees_ptr_opt_ ebpf_timer_work_item_t* timer);

    typedef struct _ebpf_hash_table ebpf_hash_table_t;

    typedef enum _ebpf_hash_table_notification_type
    {
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_ALLOCATE, //< A key + value have been allocated.
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_FREE,     //< A key + value have been freed.
        EBPF_HASH_TABLE_NOTIFICATION_TYPE_USE,      //< A key + value have been used.
    } ebpf_hash_table_notification_type_t;

    typedef void (*ebpf_hash_table_notification_function)(
        _Inout_ void* context,
        _In_ ebpf_hash_table_notification_type_t type,
        _In_ const uint8_t* key,
        _Inout_ uint8_t* value);

    /**
     * @brief Options to pass to ebpf_hash_table_create.
     *
     * Some fields are required, others are optional.  If an optional field is
     * not specified, a default value will be used.
     */
    typedef struct _ebpf_hash_table_creation_options
    {
        // Required fields.
        size_t key_size;   //< Size of key in bytes.
        size_t value_size; //< Size of value in bytes.
        // Optional fields.
        void (*extract_function)(
            _In_ const uint8_t* value,
            _Outptr_result_buffer_((*length_in_bits + 7) / 8) const uint8_t** data,
            _Out_ size_t* length_in_bits); //< Function to extract key from stored value.
        void* (*allocate)(size_t size);    //< Function to allocate memory - defaults to ebpf_epoch_allocate.
        void (*free)(void* memory);        //< Function to free memory - defaults to ebpf_epoch_free.
        size_t bucket_count; //< Number of buckets to use - defaults to EBPF_HASH_TABLE_DEFAULT_BUCKET_COUNT.
        size_t max_entries;  //< Maximum number of entries in the hash table - defaults to EBPF_HASH_TABLE_NO_LIMIT.
        size_t supplemental_value_size; //< Size of supplemental value to store in each entry - defaults to 0.
        void* notification_context;     //< Context to pass to notification functions.
        ebpf_hash_table_notification_function
            notification_callback; //< Function to call when value storage is allocated or freed.
    } ebpf_hash_table_creation_options_t;

    /**
     * @brief Allocate and initialize a hash table.
     *
     * @param[out] hash_table Pointer to memory that will contain hash table on
     *   success.
     * @param[in] options Options to control hash table creation.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  hash table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_create(
        _Out_ ebpf_hash_table_t** hash_table, _In_ const ebpf_hash_table_creation_options_t* options);

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_find(_In_ const ebpf_hash_table_t* hash_table, _In_ const uint8_t* key, _Outptr_ uint8_t** value);

    /**
     * @brief Insert or update an entry in the hash table.
     *
     * @param[in, out] hash_table Hash-table to update.
     * @param[in] key Key to find and insert or update.
     * @param[in] value Value to insert into hash table or NULL to insert zero entry.
     * @param[in] operation One of ebpf_hash_table_operations_t operations.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate memory for this
     *  entry in the hash table.
     * @retval EBPF_OUT_OF_SPACE Unable to insert this entry in the hash table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_update(
        _Inout_ ebpf_hash_table_t* hash_table,
        _In_ const uint8_t* key,
        _In_opt_ const uint8_t* value,
        ebpf_hash_table_operations_t operation);

    /**
     * @brief Remove an entry from the hash table.
     *
     * @param[in, out] hash_table Hash-table to update.
     * @param[in] key Key to find and remove.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NOT_FOUND Key not found in hash table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_delete(_Inout_ ebpf_hash_table_t* hash_table, _In_ const uint8_t* key);

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key(
        _In_ const ebpf_hash_table_t* hash_table, _In_opt_ const uint8_t* previous_key, _Out_ uint8_t* next_key);

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key_and_value(
        _In_ const ebpf_hash_table_t* hash_table,
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
    _Must_inspect_result_ ebpf_result_t
    ebpf_hash_table_next_key_pointer_and_value(
        _In_ const ebpf_hash_table_t* hash_table,
        _In_opt_ const uint8_t* previous_key,
        _Outptr_ uint8_t** next_key_pointer,
        _Outptr_opt_ uint8_t** next_value);

    /**
     * @brief Get the number of keys in the hash table
     *
     * @param[in] hash_table Hash-table to query.
     * @return Count of entries in the hash table.
     */
    size_t
    ebpf_hash_table_key_count(_In_ const ebpf_hash_table_t* hash_table);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in, out] addend Value to increase by 1.
     * @return The new value.
     */
    int32_t
    ebpf_interlocked_increment_int32(_Inout_ volatile int32_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in, out] addend Value to decrease by 1.
     * @return The new value.
     */
    int32_t
    ebpf_interlocked_decrement_int32(_Inout_ volatile int32_t* addend);

    /**
     * @brief Atomically increase the value of addend by 1 and return the new
     *  value.
     *
     * @param[in, out] addend Value to increase by 1.
     * @return The new value.
     */
    int64_t
    ebpf_interlocked_increment_int64(_Inout_ volatile int64_t* addend);

    /**
     * @brief Atomically decrease the value of addend by 1 and return the new
     *  value.
     *
     * @param[in, out] addend Value to increase by 1.
     * @return The new value.
     */
    int64_t
    ebpf_interlocked_decrement_int64(_Inout_ volatile int64_t* addend);

    /**
     * @brief Performs an atomic operation that compares the input value pointed
     *  to by destination with the value of comparand and replaces it with
     *  exchange.
     *
     * @param[in, out] destination A pointer to the input value that is compared
     *  with the value of comparand.
     * @param[in] exchange Specifies the output value pointed to by destination
     *  if the input value pointed to by destination equals the value of
     *  comparand.
     * @param[in] comparand Specifies the value that is compared with the input
     *  value pointed to by destination.
     * @return Returns the original value of memory pointed to by
     *  destination.
     */
    int32_t
    ebpf_interlocked_compare_exchange_int32(_Inout_ volatile int32_t* destination, int32_t exchange, int32_t comparand);

    /**
     * @brief Performs an atomic operation that compares the input value pointed
     *  to by destination with the value of comparand and replaces it with
     *  exchange.
     *
     * @param[in, out] destination A pointer to the input value that is compared
     *  with the value of comparand.
     * @param[in] exchange Specifies the output value pointed to by destination
     *  if the input value pointed to by destination equals the value of
     *  comparand.
     * @param[in] comparand Specifies the value that is compared with the input
     *  value pointed to by destination.
     * @return Returns the original value of memory pointed to by
     *  destination.
     */
    void*
    ebpf_interlocked_compare_exchange_pointer(
        _Inout_ void* volatile* destination, _In_opt_ const void* exchange, _In_opt_ const void* comparand);

    /**
     * @brief Performs an atomic OR of the value stored at destination with mask and stores the result in destination.
     *
     * @param[in, out] destination A pointer to the memory for this operation to be applied to.
     * @param[in] mask Value to be applied to the value stored at the destination.
     * @return The original value stored at destination.
     */
    int32_t
    ebpf_interlocked_or_int32(_Inout_ volatile int32_t* destination, int32_t mask);

    /**
     * @brief Performs an atomic AND of the value stored at destination with mask and stores the result in destination.
     *
     * @param[in, out] destination A pointer to the memory for this operation to be applied to.
     * @param[in] mask Value to be applied to the value stored at the destination.
     * @return The original value stored at destination.
     */
    int32_t
    ebpf_interlocked_and_int32(_Inout_ volatile int32_t* destination, int32_t mask);

    /**
     * @brief Performs an atomic XOR of the value stored at destination with mask and stores the result in destination.
     *
     * @param[in, out] destination A pointer to the memory for this operation to be applied to.
     * @param[in] mask Value to be applied to the value stored at the destination.
     * @return The original value stored at destination.
     */
    int32_t
    ebpf_interlocked_xor_int32(_Inout_ volatile int32_t* destination, int32_t mask);

    /**
     * @brief Performs an atomic OR of the value stored at destination with mask and stores the result in destination.
     *
     * @param[in, out] destination A pointer to the memory for this operation to be applied to.
     * @param[in] mask Value to be applied to the value stored at the destination.
     * @return The original value stored at destination.
     */
    int64_t
    ebpf_interlocked_or_int64(_Inout_ volatile int64_t* destination, int64_t mask);

    /**
     * @brief Performs an atomic AND of the value stored at destination with mask and stores the result in destination.
     *
     * @param[in, out] destination A pointer to the memory for this operation to be applied to.
     * @param[in] mask Value to be applied to the value stored at the destination.
     * @return The original value stored at destination.
     */
    int64_t
    ebpf_interlocked_and_int64(_Inout_ volatile int64_t* destination, int64_t mask);

    /**
     * @brief Performs an atomic XOR of the value stored at destination with mask and stores the result in destination.
     *
     * @param[in, out] destination A pointer to the memory for this operation to be applied to.
     * @param[in] mask Value to be applied to the value stored at the destination.
     * @return The original value stored at destination.
     */
    int64_t
    ebpf_interlocked_xor_int64(_Inout_ volatile int64_t* destination, int64_t mask);

    typedef ebpf_result_t (*ebpf_extension_change_callback_t)(
        _In_ const void* client_binding_context, _In_opt_ const ebpf_extension_data_t* provider_data);

    /**
     * @brief Load an extension and get its dispatch table.
     *
     * @param[out] client_context Context used to unload the extension.
     * @param[in] interface_id GUID representing the identity of the extension interface.
     * @param[in] expected_provider_module_id GUID representing the expected identity of the provider.
     * @param[in] client_module_id GUID representing the identity of the client.
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
    _Must_inspect_result_ ebpf_result_t
    ebpf_extension_load(
        _Outptr_ ebpf_extension_client_t** client_context,
        _In_ const GUID* interface_id,
        _In_ const GUID* expected_provider_module_id,
        _In_ const GUID* client_module_id,
        _In_ const void* extension_client_context,
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

    GUID
    ebpf_extension_get_provider_guid(_In_ const void* extension_client_binding_context);

    /**
     * @brief Unload an extension.
     *
     * @param[in] client_context Context of the extension to unload.
     */
    void
    ebpf_extension_unload(_Frees_ptr_opt_ ebpf_extension_client_t* client_context);

    /**
     * @brief Prevent extension provider from unloading.
     *
     * @param[in,out] client_context Client context to reference.
     */
    _Must_inspect_result_ bool
    ebpf_extension_reference_provider_data(_Inout_ ebpf_extension_client_t* client_context);

    /**
     * @brief Allow extension provider to unload.
     *
     * @param[in,out] client_context Client context to dereference.
     */
    void
    ebpf_extension_dereference_provider_data(_Inout_ ebpf_extension_client_t* client_context);

    /**
     * @brief Register as an extension provider.
     *
     * @param[out] provider_context Context used to unload the provider.
     * @param[in] interface_id GUID representing the identity of the interface.
     * @param[in] provider_module_id GUID representing the identity of the provider.
     * @param[in, out] provider_binding_context Provider binding context.
     * @param[in] provider_data Opaque provider data.
     * @param[in] provider_dispatch_table Table of function pointers the
     *  provider exposes.
     * @param[in, out] callback_context Opaque per-instance pointer passed to the callback functions.
     * @param[in] attach_client_callback Function invoked when a client attaches.
     * @param[in] detach_client_callback Function invoked when a client detaches.
     * @param[in] provider_cleanup_binding_context_callback Function invoked when a binding context can be cleaned up.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_ERROR_EXTENSION_FAILED_TO_LOAD The provider was unable to
     *  load.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_provider_load(
        _Outptr_ ebpf_extension_provider_t** provider_context,
        _In_ const GUID* interface_id,
        _In_ const GUID* provider_module_id,
        _Inout_opt_ void* provider_binding_context,
        _In_opt_ const ebpf_extension_data_t* provider_data,
        _In_opt_ const ebpf_extension_dispatch_table_t* provider_dispatch_table,
        _Inout_opt_ void* callback_context,
        _In_ NPI_PROVIDER_ATTACH_CLIENT_FN attach_client_callback,
        _In_ NPI_PROVIDER_DETACH_CLIENT_FN detach_client_callback,
        _In_opt_ PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN provider_cleanup_binding_context_callback);

    /**
     * @brief Unload a provider.
     *
     * @param[in] provider_context Provider to unload.
     */
    void
    ebpf_provider_unload(_Frees_ptr_opt_ ebpf_extension_provider_t* provider_context);

    _Must_inspect_result_ ebpf_result_t
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
    _Must_inspect_result_ ebpf_result_t
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
     * @param[in, out] trampoline_table Trampoline table to populate.
     * @param[in] helper_function_count Count of helper functions.
     * @param[in] helper_function_ids Array of helper function IDs.
     * @param[in] dispatch_table Dispatch table to populate from.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_update_trampoline_table(
        _Inout_ ebpf_trampoline_table_t* trampoline_table,
        uint32_t helper_function_count,
        _In_reads_(helper_function_count) const uint32_t* helper_function_ids,
        _In_ const ebpf_helper_function_addresses_t* helper_function_addresses);

    /**
     * @brief Get the address of a trampoline function.
     *
     * @param[in] trampoline_table Trampoline table to query.
     * @param[in] helper_id Id of the helper function to get.
     * @param[out] function Pointer to memory that contains the function on success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for this
     *  operation.
     * @retval EBPF_INVALID_ARGUMENT An invalid argument was supplied.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_get_trampoline_function(
        _In_ const ebpf_trampoline_table_t* trampoline_table, size_t helper_id, _Outptr_ void** function);

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_get_trampoline_helper_address(
        _In_ const ebpf_trampoline_table_t* trampoline_table, size_t index, _Outptr_ void** helper_address);

    typedef struct _ebpf_program_info ebpf_program_info_t;

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
    _Must_inspect_result_ ebpf_result_t
    ebpf_access_check(
        _In_ const ebpf_security_descriptor_t* security_descriptor,
        ebpf_security_access_mask_t request_access,
        _In_ const ebpf_security_generic_mapping_t* generic_mapping);

    /**
     * @brief Check the validity of the provided security descriptor.
     *
     * @param[in] security_descriptor Security descriptor to verify.
     * @param[in] security_descriptor_length Length of security descriptor.
     * @retval EBPF_SUCCESS Security descriptor is well formed.
     * @retval EBPF_INVALID_ARGUMENT Security descriptor is malformed.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_validate_security_descriptor(
        _In_ const ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length);

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
     * @param[in] include_suspended_time Include time the system spent in a suspended state.
     * @return Time elapsed since boot in 100 nanosecond units.
     */
    uint64_t
    ebpf_query_time_since_boot(bool include_suspended_time);

    _Must_inspect_result_ ebpf_result_t
    ebpf_set_current_thread_affinity(uintptr_t new_thread_affinity_mask, _Out_ uintptr_t* old_thread_affinity_mask);

    void
    ebpf_restore_current_thread_affinity(uintptr_t old_thread_affinity_mask);

    typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

    /**
     * @brief Map an ebpf_result_t to a generic NTSTATUS code.
     *
     * @param[in] result ebpf_result_t to map.
     * @return The generic NTSTATUS code.
     */
    NTSTATUS
    ebpf_result_to_ntstatus(ebpf_result_t result);

    /**
     * @brief Map an ebpf_result_t to a generic Win32 error code.
     *
     * @param[in] result ebpf_result_t to map.
     * @return The generic Win32 error code.
     */
    uint32_t
    ebpf_result_to_win32_error_code(ebpf_result_t result);

    /**
     * @brief Output a debug message.
     *
     * @param[in] format Format string.
     * @param[in] arg_list Argument list.
     *
     * @returns Number of bytes written, or -1 on error.
     */
    long
    ebpf_platform_printk(_In_z_ const char* format, va_list arg_list);

    /**
     * @brief Get the current process ID.
     *
     * @returns Process ID.
     */
    uint32_t
    ebpf_platform_process_id();

    /**
     * @brief Get the current thread ID.
     *
     * @returns Thread ID.
     */
    uint32_t
    ebpf_platform_thread_id();

    TRACELOGGING_DECLARE_PROVIDER(ebpf_tracelog_provider);

    _Must_inspect_result_ ebpf_result_t
    ebpf_trace_initiate();

    void
    ebpf_trace_terminate();

    /**
     * @brief Update global helper information in eBPF store.
     *
     * @param[in] helper_info Pointer to an array of helper function prototypes.
     * @param[in] helper_info_count Count of helper function prototypes.
     *
     * @returns Status of the operation.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_update_global_helpers(
        _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count);

    typedef struct _ebpf_cryptographic_hash ebpf_cryptographic_hash_t;

    /**
     * @brief Create a cryptographic hash object.
     *
     * @param[in] algorithm The algorithm to use. Recommended values are "SHA256".
     * @param[out] hash The hash object.
     * @return EBPF_SUCCESS The hash object was created.
     * @return EBPF_NO_MEMORY Unable to allocate memory for the hash object.
     * @return EBPF_INVALID_ARGUMENT The algorithm is not supported.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_cryptographic_hash_create(_In_z_ const wchar_t* algorithm, _Outptr_ ebpf_cryptographic_hash_t** hash);

    /**
     * @brief Destroy a cryptographic hash object.
     *
     * @param[in] hash The hash object to destroy.
     */
    void
    ebpf_cryptographic_hash_destroy(_In_opt_ _Frees_ptr_opt_ ebpf_cryptographic_hash_t* hash);

    /**
     * @brief Append data to a cryptographic hash object.
     *
     * @param[in] hash The hash object to update.
     * @param[in] buffer The data to append.
     * @param[in] length The length of the data to append.
     * @return EBPF_SUCCESS The hash object was created.
     * @return EBPF_INVALID_ARGUMENT An error occurred while computing the hash.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_cryptographic_hash_append(
        _Inout_ ebpf_cryptographic_hash_t* hash, _In_reads_bytes_(length) const uint8_t* buffer, size_t length);

    /**
     * @brief Finalize the hash and return the hash value.
     *
     * @param[in, out] hash The hash object to finalize.
     * @param[out] buffer The buffer to receive the hash value.
     * @param[in] input_length The length of the buffer.
     * @param[out] output_length The length of the hash value.
     * @return EBPF_SUCCESS The hash object was created.
     * @return EBPF_INVALID_ARGUMENT An error occurred while computing the hash.
     * @return EBPF_INSUFFICIENT_BUFFER The buffer is not large enough to receive the hash value.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_cryptographic_hash_get_hash(
        _Inout_ ebpf_cryptographic_hash_t* hash,
        _Out_writes_to_(input_length, *output_length) uint8_t* buffer,
        size_t input_length,
        _Out_ size_t* output_length);

    /**
     * @brief Should the current thread yield the processor?
     *
     * @retval true Thread should yield the processor.
     * @retval false Thread should not yield the processor.
     */
    bool
    ebpf_should_yield_processor();

/**
 * @brief Append a value to a cryptographic hash object.
 * @param[in] hash The hash object to update.
 * @param[in] value The value to append. Size is determined by the type of the value.
 */
#define EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(hash, value) \
    ebpf_cryptographic_hash_append(hash, (const uint8_t*)&(value), sizeof((value)))

/**
 * @brief Append a value to a cryptographic hash object.
 * @param[in] hash The hash object to update.
 * @param[in] string The string to append. Size is determined by the length of the string.
 */
#define EBPF_CRYPTOGRAPHIC_HASH_APPEND_STR(hash, string) \
    ebpf_cryptographic_hash_append(hash, (const uint8_t*)(string), strlen(string))

    /**
     * @brief Get 64-bit Authentication ID for the current user.
     *
     * @param[out] authentication_id The authentication ID.
     *
     * @return result of the operation.
     */
    _IRQL_requires_max_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
        ebpf_platform_get_authentication_id(_Out_ uint64_t* authentication_id);

    /**
     * @brief Query the current execution context state.
     *
     * @param[out] state The captured execution context state.
     */
    void
    ebpf_get_execution_context_state(_Out_ ebpf_execution_context_state_t* state);

    typedef struct _ebpf_semaphore ebpf_semaphore_t;

    /**
     * @brief Create a semaphore.
     *
     * @param[out] semaphore Pointer to the memory that contains the semaphore.
     * @param[in] initial_count Initial count of the semaphore.
     * @param[in] maximum_count Maximum count of the semaphore.
     * @retval EBPF_SUCCESS The hash object was created.
     * @retval EBPF_NO_MEMORY Unable to allocate resources for the semaphore.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_semaphore_create(_Outptr_ ebpf_semaphore_t** semaphore, int initial_count, int maximum_count);

    /**
     * @brief Destroy a semaphore.
     *
     * @param[in] semaphore Semaphore to destroy.
     */
    void
    ebpf_semaphore_destroy(_Frees_ptr_opt_ ebpf_semaphore_t* semaphore);

    /**
     * @brief Wait on a semaphore.
     *
     * @param[in] semaphore Semaphore to wait on.
     */
    void
    ebpf_semaphore_wait(_In_ ebpf_semaphore_t* semaphore);

    /**
     * @brief Release a semaphore.
     *
     * @param[in] semaphore Semaphore to release.
     */
    void
    ebpf_semaphore_release(_In_ ebpf_semaphore_t* semaphore);

#define EBPF_TRACELOG_EVENT_SUCCESS "EbpfSuccess"
#define EBPF_TRACELOG_EVENT_RETURN "EbpfReturn"
#define EBPF_TRACELOG_EVENT_GENERIC_ERROR "EbpfGenericError"
#define EBPF_TRACELOG_EVENT_GENERIC_MESSAGE "EbpfGenericMessage"
#define EBPF_TRACELOG_EVENT_API_ERROR "EbpfApiError"

#define EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT 0x1
#define EBPF_TRACELOG_KEYWORD_BASE 0x2
#define EBPF_TRACELOG_KEYWORD_ERROR 0x4
#define EBPF_TRACELOG_KEYWORD_EPOCH 0x8
#define EBPF_TRACELOG_KEYWORD_CORE 0x10
#define EBPF_TRACELOG_KEYWORD_LINK 0x20
#define EBPF_TRACELOG_KEYWORD_MAP 0x40
#define EBPF_TRACELOG_KEYWORD_PROGRAM 0x80
#define EBPF_TRACELOG_KEYWORD_API 0x100
#define EBPF_TRACELOG_KEYWORD_PRINTK 0x200
#define EBPF_TRACELOG_KEYWORD_NATIVE 0x400

#define EBPF_TRACELOG_LEVEL_LOG_ALWAYS WINEVENT_LEVEL_LOG_ALWAYS
#define EBPF_TRACELOG_LEVEL_CRITICAL WINEVENT_LEVEL_CRITICAL
#define EBPF_TRACELOG_LEVEL_ERROR WINEVENT_LEVEL_ERROR
#define EBPF_TRACELOG_LEVEL_WARNING WINEVENT_LEVEL_WARNING
#define EBPF_TRACELOG_LEVEL_INFO WINEVENT_LEVEL_INFO
#define EBPF_TRACELOG_LEVEL_VERBOSE WINEVENT_LEVEL_VERBOSE

#define EBPF_LOG_FUNCTION_SUCCESS()                      \
    TraceLoggingWrite(                                   \
        ebpf_tracelog_provider,                          \
        EBPF_TRACELOG_EVENT_SUCCESS,                     \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
        TraceLoggingString(__FUNCTION__ " returned success", "Message"));

#define EBPF_LOG_FUNCTION_ERROR(result)                                     \
    TraceLoggingWrite(                                                      \
        ebpf_tracelog_provider,                                             \
        EBPF_TRACELOG_EVENT_GENERIC_ERROR,                                  \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                            \
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_ERROR),                   \
        TraceLoggingString(__FUNCTION__ " returned error", "ErrorMessage"), \
        TraceLoggingLong(result, "Error"));

#define EBPF_LOG_ENTRY()                                                \
    TraceLoggingWrite(                                                  \
        ebpf_tracelog_provider,                                         \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                      \
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
        TraceLoggingOpcode(WINEVENT_OPCODE_START),                      \
        TraceLoggingString(__FUNCTION__, "<=="));

#define EBPF_LOG_EXIT()                                                 \
    TraceLoggingWrite(                                                  \
        ebpf_tracelog_provider,                                         \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                      \
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
        TraceLoggingOpcode(WINEVENT_OPCODE_STOP),                       \
        TraceLoggingString(__FUNCTION__, "==>"));

#define EBPF_RETURN_RESULT(status)                 \
    do {                                           \
        ebpf_result_t local_result = (status);     \
        if (local_result == EBPF_SUCCESS) {        \
            EBPF_LOG_FUNCTION_SUCCESS();           \
        } else {                                   \
            EBPF_LOG_FUNCTION_ERROR(local_result); \
        }                                          \
        return local_result;                       \
    } while (false);

#define EBPF_RETURN_NTSTATUS(status)               \
    do {                                           \
        ebpf_result_t local_result = (status);     \
        if (NT_SUCCESS(status)) {                  \
            EBPF_LOG_FUNCTION_SUCCESS();           \
        } else {                                   \
            EBPF_LOG_FUNCTION_ERROR(local_result); \
        }                                          \
        return local_result;                       \
    } while (false);

#define EBPF_RETURN_POINTER(type, pointer)                   \
    do {                                                     \
        type local_result = (type)(pointer);                 \
        TraceLoggingWrite(                                   \
            ebpf_tracelog_provider,                          \
            EBPF_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),    \
            TraceLoggingPointer(local_result, #pointer));    \
        return local_result;                                 \
    } while (false);

#define EBPF_RETURN_BOOL(flag)                               \
    do {                                                     \
        bool local_result = (flag);                          \
        TraceLoggingWrite(                                   \
            ebpf_tracelog_provider,                          \
            EBPF_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),    \
            TraceLoggingBool(!!local_result, #flag));        \
        return local_result;                                 \
    } while (false);

#define EBPF_RETURN_FD(fd)                                   \
    do {                                                     \
        fd_t local_fd = (fd);                                \
        TraceLoggingWrite(                                   \
            ebpf_tracelog_provider,                          \
            EBPF_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),       \
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),    \
            TraceLoggingInt32(local_fd, #fd));               \
        return local_fd;                                     \
    } while (false);

#define EBPF_RETURN_VOID() \
    do {                   \
        EBPF_LOG_EXIT();   \
        return;            \
    } while (false);

#define EBPF_LOG_MESSAGE(trace_level, keyword, message) \
    TraceLoggingWrite(                                  \
        ebpf_tracelog_provider,                         \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,            \
        TraceLoggingLevel(trace_level),                 \
        TraceLoggingKeyword((keyword)),                 \
        TraceLoggingString(message, "Message"));

#define EBPF_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status) \
    TraceLoggingWrite(                                                   \
        ebpf_tracelog_provider,                                          \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                             \
        TraceLoggingLevel(trace_level),                                  \
        TraceLoggingKeyword((keyword)),                                  \
        TraceLoggingString(message, "Message"),                          \
        TraceLoggingNTStatus(status));

#define EBPF_LOG_MESSAGE_UTF8_STRING(trace_level, keyword, message, string) \
    TraceLoggingWrite(                                                      \
        ebpf_tracelog_provider,                                             \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                \
        TraceLoggingLevel(trace_level),                                     \
        TraceLoggingKeyword((keyword)),                                     \
        TraceLoggingString(message, "Message"),                             \
        TraceLoggingCountedUtf8String((const char*)(string).value, (unsigned long)(string).length, #string));

#define EBPF_LOG_MESSAGE_UINT64(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                \
        ebpf_tracelog_provider,                                       \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                          \
        TraceLoggingLevel((trace_level)),                             \
        TraceLoggingKeyword((keyword)),                               \
        TraceLoggingString((message), "Message"),                     \
        TraceLoggingUInt64((value), (#value)));

#define EBPF_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2) \
    TraceLoggingWrite(                                                                \
        ebpf_tracelog_provider,                                                       \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                          \
        TraceLoggingLevel((trace_level)),                                             \
        TraceLoggingKeyword((keyword)),                                               \
        TraceLoggingString((message), "Message"),                                     \
        TraceLoggingUInt64((value1), (#value1)),                                      \
        TraceLoggingUInt64((value2), (#value2)));

#define EBPF_LOG_MESSAGE_POINTER_ENUM(trace_level, keyword, message, pointer, enum) \
    TraceLoggingWrite(                                                              \
        ebpf_tracelog_provider,                                                     \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                        \
        TraceLoggingLevel((trace_level)),                                           \
        TraceLoggingKeyword((keyword)),                                             \
        TraceLoggingString((message), "Message"),                                   \
        TraceLoggingPointer((pointer), (#pointer)),                                 \
        TraceLoggingUInt32((enum), (#enum)));

#define EBPF_LOG_MESSAGE_GUID(trace_level, keyword, message, guid) \
    TraceLoggingWrite(                                             \
        ebpf_tracelog_provider,                                    \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                       \
        TraceLoggingLevel((trace_level)),                          \
        TraceLoggingKeyword((keyword)),                            \
        TraceLoggingString((message), "Message"),                  \
        TraceLoggingGuid((guid), (#guid)));

#define EBPF_LOG_MESSAGE_GUID_GUID(trace_level, keyword, message, guid1, guid2) \
    TraceLoggingWrite(                                                          \
        ebpf_tracelog_provider,                                                 \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                    \
        TraceLoggingLevel((trace_level)),                                       \
        TraceLoggingKeyword((keyword)),                                         \
        TraceLoggingString((message), "Message"),                               \
        TraceLoggingGuid((guid1), (#guid1)),                                    \
        TraceLoggingGuid((guid2), (#guid2)));

#define EBPF_LOG_MESSAGE_GUID_GUID_STRING(trace_level, keyword, message, string, guid1, guid2) \
    TraceLoggingWrite(                                                                         \
        ebpf_tracelog_provider,                                                                \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                                                   \
        TraceLoggingLevel((trace_level)),                                                      \
        TraceLoggingKeyword((keyword)),                                                        \
        TraceLoggingString((message), "Message"),                                              \
        TraceLoggingString(string, #string),                                                   \
        TraceLoggingGuid((guid1), (#guid1)),                                                   \
        TraceLoggingGuid((guid2), (#guid2)));

#define EBPF_LOG_MESSAGE_STRING(trace_level, keyword, message, string) \
    TraceLoggingWrite(                                                 \
        ebpf_tracelog_provider,                                        \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                \
        TraceLoggingKeyword((keyword)),                                \
        TraceLoggingString(message, "Message"),                        \
        TraceLoggingString(string, #string));

#define EBPF_LOG_MESSAGE_WSTRING(trace_level, keyword, message, wstring) \
    TraceLoggingWrite(                                                   \
        ebpf_tracelog_provider,                                          \
        EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,                             \
        TraceLoggingLevel(trace_level),                                  \
        TraceLoggingKeyword((keyword)),                                  \
        TraceLoggingString(message, "Message"),                          \
        TraceLoggingWideString(wstring, #wstring));

#define EBPF_LOG_WIN32_API_FAILURE(keyword, api)          \
    do {                                                  \
        unsigned long last_error = GetLastError();        \
        TraceLoggingWrite(                                \
            ebpf_tracelog_provider,                       \
            EBPF_TRACELOG_EVENT_API_ERROR,                \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR), \
            TraceLoggingKeyword((keyword)),               \
            TraceLoggingString(#api, "Api"),              \
            TraceLoggingWinError(last_error));            \
    } while (false);

#define EBPF_LOG_WIN32_STRING_API_FAILURE(keyword, message, api) \
    do {                                                         \
        unsigned long last_error = GetLastError();               \
        TraceLoggingWrite(                                       \
            ebpf_tracelog_provider,                              \
            EBPF_TRACELOG_EVENT_API_ERROR,                       \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),        \
            TraceLoggingKeyword((keyword)),                      \
            TraceLoggingString(message, "Message"),              \
            TraceLoggingString(#api, "Api"),                     \
            TraceLoggingWinError(last_error));                   \
    } while (false);

#define EBPF_LOG_WIN32_WSTRING_API_FAILURE(keyword, wstring, api) \
    do {                                                          \
        unsigned long last_error = GetLastError();                \
        TraceLoggingWrite(                                        \
            ebpf_tracelog_provider,                               \
            EBPF_TRACELOG_EVENT_API_ERROR,                        \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),         \
            TraceLoggingKeyword((keyword)),                       \
            TraceLoggingWideString(wstring, "Message"),           \
            TraceLoggingString(#api, "Api"),                      \
            TraceLoggingWinError(last_error));                    \
    } while (false);

#define EBPF_LOG_WIN32_GUID_API_FAILURE(keyword, guid, api) \
    do {                                                    \
        unsigned long last_error = GetLastError();          \
        TraceLoggingWrite(                                  \
            ebpf_tracelog_provider,                         \
            EBPF_TRACELOG_EVENT_API_ERROR,                  \
            TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),   \
            TraceLoggingKeyword((keyword)),                 \
            TraceLoggingGuid((guid), (#guid)),              \
            TraceLoggingString(#api, "Api"),                \
            TraceLoggingWinError(last_error));              \
    } while (false);

#define EBPF_LOG_NTSTATUS_API_FAILURE(keyword, api, status) \
    TraceLoggingWrite(                                      \
        ebpf_tracelog_provider,                             \
        EBPF_TRACELOG_EVENT_API_ERROR,                      \
        TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),       \
        TraceLoggingKeyword((keyword)),                     \
        TraceLoggingString(#api, "api"),                    \
        TraceLoggingNTStatus(status));

#define EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(keyword, api, status, message) \
    TraceLoggingWrite(                                                       \
        ebpf_tracelog_provider,                                              \
        EBPF_TRACELOG_EVENT_API_ERROR,                                       \
        TraceLoggingLevel(EBPF_TRACELOG_LEVEL_ERROR),                        \
        TraceLoggingKeyword((keyword)),                                      \
        TraceLoggingString(#api, "api"),                                     \
        TraceLoggingNTStatus(status),                                        \
        TraceLoggingString(message, "Message"));

#define EBPF_LOG_NTSTATUS_WSTRING_API(keyword, wstring, api, status) \
    TraceLoggingWrite(                                               \
        ebpf_tracelog_provider,                                      \
        EBPF_TRACELOG_EVENT_API_ERROR,                               \
        TraceLoggingLevel(EBPF_TRACELOG_LEVEL_INFO),                 \
        TraceLoggingKeyword((keyword)),                              \
        TraceLoggingWideString(wstring, "Message"),                  \
        TraceLoggingString(#api, "api"),                             \
        TraceLoggingNTStatus(status));

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
