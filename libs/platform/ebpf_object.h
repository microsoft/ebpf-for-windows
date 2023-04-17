// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum _ebpf_object_type
    {
        EBPF_OBJECT_UNKNOWN,
        EBPF_OBJECT_MAP,
        EBPF_OBJECT_LINK,
        EBPF_OBJECT_PROGRAM,
    } ebpf_object_type_t;

    typedef struct _ebpf_base_object ebpf_base_object_t;
    typedef void (*ebpf_base_release_reference_t)(_Inout_ void* base_object);
    typedef void (*ebpf_base_acquire_reference_t)(_Inout_ void* base_object);

    typedef struct _ebpf_core_object ebpf_core_object_t;
    typedef void (*ebpf_free_object_t)(ebpf_core_object_t* object);
    typedef const ebpf_program_type_t (*ebpf_object_get_program_type_t)(_In_ const ebpf_core_object_t* object);

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
        uint32_t marker; // Contains the 32bit value 'eobj' when the object is valid and is inverted when the object is
                         // freed.
        uint32_t zero_fill; // Zero fill to make the reference count is 8-byte aligned.
        volatile int64_t reference_count;
        ebpf_base_acquire_reference_t acquire_reference;
        ebpf_base_release_reference_t release_reference;
    } ebpf_base_object_t;

    typedef struct _ebpf_core_object
    {
        ebpf_base_object_t base;
        ebpf_object_type_t type;
        ebpf_free_object_t free_function;
        ebpf_object_get_program_type_t get_program_type;
        // ID for this object.
        ebpf_id_t id;
        // Used to insert object in an object specific list.
        ebpf_list_entry_t object_list_entry;
        // # of pinned paths, for diagnostic purposes.
        volatile int32_t pinned_path_count;
    } ebpf_core_object_t;

    /**
     * @brief Initiate object tracking.
     *
     */
    void
    ebpf_object_tracking_initiate();

    /**
     * @brief Terminate object tracking.
     *
     */
    void
    ebpf_object_tracking_terminate();

    /**
     * @brief Initialize an ebpf_core_object_t structure.
     *
     * @param[in, out] object ebpf_core_object_t structure to initialize.
     * @param[in] object_type The type of the object.
     * @param[in] free_function The function used to free the object.
     * @param[in] get_program_type_function The function used to get a program type, or NULL.  Each program
     * has a program type, and hence so do maps that can contain programs, whether directly (like
     * BPF_MAP_TYPE_PROG_ARRAY) or indirectly (like BPF_MAP_TYPE_ARRAY_OF_MAPS containing a BPF_MAP_TYPE_PROG_ARRAY).
     * @retval EBPF_SUCCESS Initialization succeeded.
     * @retval EBPF_NO_MEMORY Could not insert into the tracking table.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_initialize(
        _Inout_ ebpf_core_object_t* object,
        ebpf_object_type_t object_type,
        ebpf_free_object_t free_function,
        ebpf_object_get_program_type_t get_program_type_function);

    /**
     * @brief Acquire a reference to this object.
     *
     * @param[in,out] object Object on which to acquire a reference.
     */
    void
    ebpf_object_acquire_reference(_Inout_ ebpf_core_object_t* object);

    /**
     * @brief Release a reference on this object. If the reference count reaches
     *  zero, the free_function is invoked on the object.
     *
     * @param[in,out] object Object on which to release a reference.
     */
    void
    ebpf_object_release_reference(_Inout_opt_ ebpf_core_object_t* object);

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
     *  NULL if there are no more objects of that type.
     */
    void
    ebpf_object_reference_next_object(
        _In_opt_ const ebpf_core_object_t* previous_object,
        ebpf_object_type_t type,
        _Outptr_result_maybenull_ ebpf_core_object_t** next_object);

    /**
     * @brief Find an ID in the ID table, verify the type matches,
     *  acquire a reference to the object and return it.
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @param[out] object Pointer to memory that contains object success.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_reference_by_id(ebpf_id_t id, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object);

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
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_OBJECT The provided handle is not valid.
     */
    ebpf_result_t
    ebpf_object_reference_by_handle(
        ebpf_handle_t handle, ebpf_object_type_t object_type, _Outptr_ struct _ebpf_core_object** object);

    /**
     * @brief Find an ID in the ID table, verify the type matches,
     *  and acquire a reference on the id table entry for this
     *  id
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_acquire_id_reference(ebpf_id_t start_id, ebpf_object_type_t object_type);

    /**
     * @brief Find an ID in the ID table, verify the type matches,
     *  and release the id table entry reference previously acquired
     *  via ebpf_object_reference_by_id.
     *
     * @param[in] id ID to find in table.
     * @param[in] object_type Object type to match.
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND The provided ID is not valid.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_object_release_id_reference(ebpf_id_t start_id, ebpf_object_type_t object_type);

#ifdef __cplusplus
}
#endif
