/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_object.h"

static const uint32_t _ebpf_object_marker = 0x67453201;

void
ebpf_object_initiate(ebpf_object_t* object, ebpf_object_type object_type, ebfp_free_object_t free_function)
{
    object->marker = _ebpf_object_marker;
    object->reference_count = 1;
    object->type = object_type;
    object->free_function = free_function;
}

void
ebpf_object_acquire_reference(ebpf_object_t* object)
{
    ebpf_assert(object->marker == _ebpf_object_marker);
    ebpf_assert(object->reference_count != 0);
    ebpf_interlocked_increment_int32(&object->reference_count);
}

void
ebpf_object_release_reference(ebpf_object_t* object)
{
    uint32_t new_ref_count;
    ebpf_assert(object->marker == _ebpf_object_marker);
    ebpf_assert(object->reference_count != 0);

    new_ref_count = ebpf_interlocked_decrement_int32(&object->reference_count);

    if (new_ref_count == 0) {
        object->marker = ~object->marker;
        object->free_function(object);
    }
}

ebpf_object_type
ebpf_object_get_type(ebpf_object_t* object)
{
    return object->type;
}
