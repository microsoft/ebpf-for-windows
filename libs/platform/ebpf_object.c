/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#include "ebpf_object.h"

static const uint32_t _ebpf_object_marker = 0x67453201;

static ebpf_lock_t _ebpf_object_tracking_list_lock = {0};

/**
 * @brief Objects are added to the list when they are initialized and removed
 * from the list when they are freed. Objects in the list always have a
 *  ref-count > 0.
 *
 * Map objects can have references due to one of the following:
 * 1) An open handle holds a reference on it.
 * 2) A pinning table entry holds a reference on it.
 * 3) Program holds a reference on the map when it is associated with it.
 *
 * Program objects can have references due to one of the following:
 * 1) An open handle holds a reference on it.
 * 2) A pinning table entry holds a reference on it.
 * 3) A link object can hold a reference when it is associated with a hook.
 *
 * A link object can have a reference due to on of the following:
 * 1) An open handle holds a reference on it.
 * 2) A pinning table entry holds a reference on it.
 *
 */
static _Requires_lock_held_(&_ebpf_object_tracking_list_lock) ebpf_list_entry_t _ebpf_object_tracking_list;

static void
_ebpf_object_tracking_list_insert(ebpf_object_t* object)
{
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
    ebpf_list_insert_tail(&_ebpf_object_tracking_list, &object->entry);
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
}

static void
_ebpf_object_tracking_list_remove(ebpf_object_t* object)
{
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
    ebpf_list_remove_entry(&object->entry);
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
}

void
ebpf_object_tracking_initiate()
{
    ebpf_lock_create(&_ebpf_object_tracking_list_lock);
    ebpf_list_initialize(&_ebpf_object_tracking_list);
}

void
ebpf_object_tracking_terminate()
{
    ebpf_assert(ebpf_list_is_empty(&_ebpf_object_tracking_list));
}

void
ebpf_object_initialize(ebpf_object_t* object, ebpf_object_type_t object_type, ebpf_free_object_t free_function)
{
    object->marker = _ebpf_object_marker;
    object->reference_count = 1;
    object->type = object_type;
    object->free_function = free_function;
    ebpf_list_initialize(&object->entry);
    _ebpf_object_tracking_list_insert(object);
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

    if (!object)
        return;

    ebpf_assert(object->marker == _ebpf_object_marker);
    ebpf_assert(object->reference_count != 0);

    new_ref_count = ebpf_interlocked_decrement_int32(&object->reference_count);

    if (new_ref_count == 0) {
        _ebpf_object_tracking_list_remove(object);
        object->marker = ~object->marker;
        object->free_function(object);
    }
}

ebpf_object_type_t
ebpf_object_get_type(ebpf_object_t* object)
{
    return object->type;
}

ebpf_result_t
ebpf_duplicate_utf8_string(_Out_ ebpf_utf8_string_t* destination, _In_ const ebpf_utf8_string_t* source)
{
    if (!source->value) {
        destination->value = NULL;
        destination->length = 0;
        return EBPF_SUCCESS;
    } else {
        destination->value = ebpf_allocate(source->length);
        if (!destination->value)
            return EBPF_NO_MEMORY;
        memcpy(destination->value, source->value, source->length);
        destination->length = source->length;
        return EBPF_SUCCESS;
    }
}

void
ebpf_object_reference_next_object(ebpf_object_t* previous_object, ebpf_object_type_t type, ebpf_object_t** next_object)
{
    ebpf_lock_state_t state;
    ebpf_list_entry_t* entry;
    *next_object = NULL;

    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
    if (previous_object == NULL)
        entry = _ebpf_object_tracking_list.Flink;
    else
        entry = previous_object->entry.Flink;

    for (; entry != &_ebpf_object_tracking_list; entry = entry->Flink) {
        ebpf_object_t* object = EBPF_FROM_FIELD(ebpf_object_t, entry, entry);
        if (object->type == type) {
            *next_object = object;
            ebpf_object_acquire_reference(object);
            break;
        }
    }
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
}
