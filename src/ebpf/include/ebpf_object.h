/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum _ebpf_object_type
    {
        EBPF_OBJECT_MAP,
        EBPF_OBJECT_HOOK_INSTANCE,
        EBPF_OBJECT_PROGRAM,
    } ebpf_object_type;

    typedef struct _ebpf_object ebpf_object_t;
    typedef void (*ebfp_free_object_t)(ebpf_object_t* object);

    typedef struct _ebpf_object
    {
        uint32_t marker;
        volatile int32_t reference_count;
        ebpf_object_type type;
        ebfp_free_object_t free_function;
    } ebpf_object_t;

    /**
     * @brief Initialize a ebpf_object_t structure.
     *
     * @param[in,out] object ebpf_object_t structure to initialize.
     * @param[in] object_type The type of the object.
     * @param[in] free_function The function used to free the object.
     */
    void
    ebpf_object_initiate(ebpf_object_t* object, ebpf_object_type object_type, ebfp_free_object_t free_function);

    /**
     * @brief Acquire a reference to this object.
     *
     * @param object Object on which to acquire a reference.
     */
    void
    ebpf_object_acquire_reference(ebpf_object_t* object);

    /**
     * @brief Release a reference on this object. If the reference count reaches
     *  zero, the free_function is invoked on the object.
     *
     * @param object Object on which to release a reference.
     */
    void
    ebpf_object_release_reference(ebpf_object_t* object);

    /**
     * @brief Query the stored type of the object.
     *
     * @param object Object to be queried.
     * @return Type of the object.
     */
    ebpf_object_type
    ebpf_object_get_type(ebpf_object_t* object);

#ifdef __cplusplus
}
#endif
