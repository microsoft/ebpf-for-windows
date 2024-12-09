// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Identifier for the file that is referencing the object. Each file that references an object is assigned
     * a unique identifier. This identifier is used to track the reference count of the object. The file identifier is
     * recorded in the _ebpf_object_reference_history table along with the line number of the reference. This allows
     * for tracking down use-after-free bugs and leaks of objects.
     */
    typedef enum _ebpf_file_id
    {
        EBPF_FILE_ID_UNKNOWN,
        EBPF_FILE_ID_CORE,
        EBPF_FILE_ID_MAPS,
        EBPF_FILE_ID_LINK,
        EBPF_FILE_ID_PROGRAM,
        EBPF_FILE_ID_NATIVE,
        EBPF_FILE_ID_PINNING_TABLE,
        EBPF_FILE_ID_HANDLE,
        EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS,
        EBPF_FILE_ID_PLATFORM_UNIT_TESTS,
        EBPF_FILE_ID_PERFORMANCE_TESTS,
        EBPF_FILE_ID_CORE_HELPER_FUZZER,
    } ebpf_file_id_t;

/**
 * @brief Macro to acquire a reference on an object and record the file and line number of the reference.
 */
#define EBPF_OBJECT_ACQUIRE_REFERENCE(object) ebpf_object_acquire_reference(object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to release a reference on an object and record the file and line number of the reference.
 */
#define EBPF_OBJECT_RELEASE_REFERENCE(object) ebpf_object_release_reference(object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to locate the next object in the object list and acquire a reference on it and record the file and
 * line number of the reference.
 */
#define EBPF_OBJECT_REFERENCE_NEXT_OBJECT(object, type, next_object) \
    ebpf_object_reference_next_object(object, type, next_object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to locate an object by its ID and acquire a reference on it and record the file and line number of
 * the reference.
 */
#define EBPF_OBJECT_REFERENCE_BY_ID(object_id, type, object) \
    ebpf_object_reference_by_id(object_id, type, object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to locate an object by its handle and acquire a reference on it and record the file and line number
 * of the reference.
 */
#define EBPF_OBJECT_REFERENCE_BY_HANDLE(object_handle, type, object) \
    ebpf_object_reference_by_handle(object_handle, type, object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to acquire a reference on an object ID and record the file and line number of the reference.
 *
 */
#define EBPF_OBJECT_ACQUIRE_ID_REFERENCE(object_id, type) \
    ebpf_object_acquire_id_reference(object_id, type, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to release a reference on an object ID and record the file and line number of the reference.
 *
 */
#define EBPF_OBJECT_RELEASE_ID_REFERENCE(object_id, type) \
    ebpf_object_release_id_reference(object_id, type, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to acquire a reference on an object via it's function pointers and record the file and line number
 * of the reference.
 */
#define EBPF_OBJECT_ACQUIRE_REFERENCE_INDIRECT(base_object) \
    base_object->acquire_reference(base_object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to release a reference on an object via it's function pointers and record the file and line number
 * of the reference.
 */
#define EBPF_OBJECT_RELEASE_REFERENCE_INDIRECT(base_object) \
    base_object->release_reference(base_object, EBPF_FILE_ID, __LINE__)

/**
 * @brief Macro to initialize an object and record the file and line number of the reference.
 *EBPF_OBJECT_INITIALIZE
 */
#define EBPF_OBJECT_INITIALIZE(                \
    object,                                    \
    object_type,                               \
    free_function,                             \
    zero_ref_function,                         \
    get_program_type_function,                 \
    get_context_header_support_function)       \
    ebpf_object_initialize(                    \
        (ebpf_core_object_t*)(object),         \
        (object_type),                         \
        (free_function),                       \
        (zero_ref_function),                   \
        (get_program_type_function),           \
        (get_context_header_support_function), \
        EBPF_FILE_ID,                          \
        __LINE__)

    typedef struct _ebpf_base_object ebpf_base_object_t;
    typedef void (*ebpf_base_release_reference_t)(_Inout_ void* base_object, ebpf_file_id_t file_id, uint32_t line);
    typedef void (*ebpf_base_acquire_reference_t)(_Inout_ void* base_object, ebpf_file_id_t file_id, uint32_t line);

    typedef struct _ebpf_core_object ebpf_core_object_t;
    typedef void (*ebpf_zero_ref_count_t)(ebpf_core_object_t* object);
    typedef void (*ebpf_free_object_t)(ebpf_core_object_t* object);
    typedef const ebpf_program_type_t (*ebpf_object_get_program_type_t)(_In_ const ebpf_core_object_t* object);
    typedef const bool (*ebpf_object_get_context_header_support_t)(_In_ const ebpf_core_object_t* object);

    /**
     * @brief Base object for all reference counted eBPF objects. This struct is embedded as the first entry in all
     * reference counted eBPF objects. The reference count is 64bit to allow for atomic operations on 32bit and 64bit
     * systems. The reference count is 8-byte aligned to avoid false sharing. The marker is used to detect
     * use-after-free bugs. The marker is set to 'eobj' when the object is valid and is inverted when the object is
     * freed. This allows for a fast check to see if the object is valid. The acquire_reference and release_reference
     * functions are used to acquire and release a reference on the object.
     */
    typedef struct _ebpf_base_object
    {
        uint32_t marker; ///< Contains the 32bit value 'eobj' when the object is valid and is inverted when the object
                         ///< is freed.
        uint32_t zero_fill;                              ///< Zero fill to make the reference count is 8-byte aligned.
        volatile int64_t reference_count;                ///< Reference count for the object.
        ebpf_base_acquire_reference_t acquire_reference; ///< Function to acquire a reference on this object.
        ebpf_base_release_reference_t release_reference; ///< Function to release a reference on this object.
    } ebpf_base_object_t;

    typedef struct _ebpf_core_object
    {
        ebpf_base_object_t base;              ///< Base object for all reference counted eBPF objects.
        ebpf_object_type_t type;              ///< Type of this object.
        ebpf_free_object_t free_function;     ///< Function to free this object.
        ebpf_zero_ref_count_t zero_ref_count; ///< Function to notify the object that the reference count has reached
                                              ///< zero.
        ebpf_object_get_program_type_t get_program_type; ///< Function to get the program type of this object.
        ebpf_object_get_context_header_support_t
            get_context_header_support;               ///< Function to get context header support for this object.
        ebpf_id_t id;                                 ///< ID of this object.
        ebpf_list_entry_t object_list_entry;          ///< Entry in the object list.
        volatile int32_t pinned_path_count;           ///< Number of pinned paths for this object.
        struct _ebpf_epoch_work_item* free_work_item; ///< Work item to free this object when the epoch ends.
    } ebpf_core_object_t;

    /**
     * @brief Initiate object tracking.
     *
     */
    ebpf_result_t
    ebpf_object_tracking_initiate();

    /**
     * @brief Terminate object tracking.
     *
     */
    void
    ebpf_object_tracking_terminate();

    /**
     * @brief Initialize an ebpf_core_object_t structure. This function must be called after all the fields of the
     * structure have been initialized as this will publish the object to the tracking table which can be used to
     * enumerate all objects of a given type.
     *
     * @param[in, out] object ebpf_core_object_t structure to initialize.
     * @param[in] object_type The type of the object.
     * @param[in] free_function The function used to free the object.
     * @param[in] get_program_type_function The function used to get a program type, or NULL.  Each program
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     * has a program type, and hence so do maps that can contain programs, whether directly (like
     * BPF_MAP_TYPE_PROG_ARRAY) or indirectly (like BPF_MAP_TYPE_ARRAY_OF_MAPS containing a BPF_MAP_TYPE_PROG_ARRAY).
     * @retval EBPF_SUCCESS Initialization succeeded.
     * @retval EBPF_NO_MEMORY Could not insert into the tracking table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_initialize(
        _Inout_ ebpf_core_object_t* object,
        ebpf_object_type_t object_type,
        _In_ ebpf_free_object_t free_function,
        _In_opt_ ebpf_zero_ref_count_t zero_ref_count_function,
        ebpf_object_get_program_type_t get_program_type_function,
        ebpf_object_get_context_header_support_t get_context_header_support_function,
        ebpf_file_id_t file_id,
        uint32_t line);

    /**
     * @brief Acquire a reference to this object.
     *
     * @param[in,out] object Object on which to acquire a reference.
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     */
    void
    ebpf_object_acquire_reference(_Inout_ ebpf_core_object_t* object, ebpf_file_id_t file_id, uint32_t line);

    /**
     * @brief Release a reference on this object. If the reference count reaches
     *  zero, the free_function is invoked on the object.
     *
     * @param[in,out] object Object on which to release a reference.
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     */
    void
    ebpf_object_release_reference(_Inout_opt_ ebpf_core_object_t* object, ebpf_file_id_t file_id, uint32_t line);

    /**
     * @brief Query the stored type of the object.
     *
     * @param[in] object Object to be queried.
     * @return Type of the object.
     */
    ebpf_object_type_t
    ebpf_object_get_type(_In_ const ebpf_core_object_t* object);

    /**
     * @brief Find the next object that is of this type and acquire reference
     *  on it.
     *
     * @param[in] previous_object Previous object that was found. Can be NULL
     *  to find first object.
     * @param[in] type Type of object to find.
     * @param[out] next_object Pointer to memory containing the next object or
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     *  NULL if there are no more objects of that type.
     */
    void
    ebpf_object_reference_next_object(
        _In_opt_ const ebpf_core_object_t* previous_object,
        ebpf_object_type_t type,
        _Outptr_result_maybenull_ ebpf_core_object_t** next_object,
        ebpf_file_id_t file_id,
        uint32_t line);

    /**
     * @brief Find an ID in the ID table, verify the type matches,
     *  acquire a reference to the object and return it.
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @param[out] object Pointer to memory that contains object success.
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_reference_by_id(
        ebpf_id_t id,
        ebpf_object_type_t object_type,
        _Outptr_ ebpf_core_object_t** object,
        ebpf_file_id_t file_id,
        uint32_t line);

    /**
     * @brief Obtain pointer to object given its ID and type and do not acquire a reference.
     * Note: The object returned may have a zero reference count and may be freed at the end of the current epoch.
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @param[out] object Pointer to memory that contains object success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_pointer_by_id(ebpf_id_t id, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object);

    /**
     * @brief Find the object of a given type with the next ID greater than a given ID.
     *
     * @param[in] start_id ID to look for an ID after.  The start_id
     * need not exist.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No such IDs found.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_get_next_id(ebpf_id_t start_id, ebpf_object_type_t object_type, _Out_ ebpf_id_t* next_id);

    /**
     * @brief Find the corresponding handle in the handle table, verify the type matches,
     *  acquire a reference to the object and return it.
     *
     * @param[in] handle Handle to find in table.
     * @param[in] object_type Object type to match.
     * @param[out] object Pointer to memory that contains object success.
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_OBJECT The provided handle is not valid.
     */
    ebpf_result_t
    ebpf_object_reference_by_handle(
        ebpf_handle_t handle,
        ebpf_object_type_t object_type,
        _Outptr_ struct _ebpf_core_object** object,
        ebpf_file_id_t file_id,
        uint32_t line);

    /**
     * @brief Find an ID in the ID table, verify the type matches,
     *  and acquire a reference on the id table entry for this
     *  id
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_acquire_id_reference(
        ebpf_id_t start_id, ebpf_object_type_t object_type, ebpf_file_id_t file_id, uint32_t line);

    /**
     * @brief Find an ID in the ID table, verify the type matches,
     *  and release the id table entry reference previously acquired
     *  via ebpf_object_reference_by_id.
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @param[in] file_id The file ID of the caller.
     * @param[in] line The line number of the caller.
     */
    void
    ebpf_object_release_id_reference(
        ebpf_id_t start_id, ebpf_object_type_t object_type, ebpf_file_id_t file_id, uint32_t line);

#ifdef __cplusplus
}
#endif
