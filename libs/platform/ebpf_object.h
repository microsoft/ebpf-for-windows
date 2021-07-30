// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_platform.h"
#include "framework.h"

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

    typedef struct _ebpf_object ebpf_object_t;
    typedef void (*ebpf_free_object_t)(ebpf_object_t* object);

    typedef struct _ebpf_object
    {
        uint32_t marker;
        volatile int32_t reference_count;
        ebpf_object_type_t type;
        ebpf_free_object_t free_function;
        ebpf_list_entry_t entry;
        ebpf_list_entry_t list_entry;
    } ebpf_object_t;

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
     * @brief Initialize an ebpf_object_t structure.
     *
     * @param[in,out] object ebpf_object_t structure to initialize.
     * @param[in] object_type The type of the object.
     * @param[in] free_function The function used to free the object.
     */
    void
    ebpf_object_initialize(ebpf_object_t* object, ebpf_object_type_t object_type, ebpf_free_object_t free_function);

    /**
     * @brief Acquire a reference to this object.
     *
     * @param[in] object Object on which to acquire a reference.
     */
    void
    ebpf_object_acquire_reference(ebpf_object_t* object);

    /**
     * @brief Release a reference on this object. If the reference count reaches
     *  zero, the free_function is invoked on the object.
     *
     * @param[in] object Object on which to release a reference.
     */
    void
    ebpf_object_release_reference(ebpf_object_t* object);

    /**
     * @brief Query the stored type of the object.
     *
     * @param[in] object Object to be queried.
     * @return Type of the object.
     */
    ebpf_object_type_t
    ebpf_object_get_type(ebpf_object_t* object);

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
        ebpf_object_t* previous_object, ebpf_object_type_t type, ebpf_object_t** next_object);

#ifdef __cplusplus
}
#endif
