// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_object.h"

static const uint32_t _ebpf_object_marker = 0x67453201;

static ebpf_lock_t _ebpf_object_tracking_list_lock = {0};

/**
 * @brief Objects are added to the ID table when they are initialized and removed
 * from the table when they are freed. Objects in the table always have a
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
 * A link object can have a reference due to one of the following:
 * 1) An open handle holds a reference on it.
 * 2) A pinning table entry holds a reference on it.
 *
 * Libbpf has APIs like bpf_prog_get_next_id, bpf_map_get_next_id,
 * and bpf_link_get_next_id to enumerate object IDs so every
 * object gets a unique ID upon creation.
 */

typedef struct _ebpf_id_entry
{
    // Counter incremented each time a new object is stored here.
    uint16_t counter;

    // Pointer to object.
    ebpf_core_object_t* object;
} ebpf_id_entry_t;

// Currently we allow a maximum of 1024 objects (links, maps,
// and programs combined).  This can be increased in the future
// if needed by making each array element store a linked list of
// entries in order by ID, rather than a single entry, in which
// case this becomes a hash table.
static _Requires_lock_held_(&_ebpf_object_tracking_list_lock) ebpf_id_entry_t _ebpf_id_table[1024];

// Get the ID last stored at a given index.
static inline ebpf_id_t
_get_id_from_index(uint32_t index)
{
    if (index >= EBPF_COUNT_OF(_ebpf_id_table)) {
        return EBPF_ID_NONE;
    }

    // Put the index in the high 2 bytes and the counter in the low 2 bytes.
    // This allows us to more easily detect stale IDs while
    // still keeping IDs in order by index.
    return (index << 16) | _ebpf_id_table[index].counter;
}

// Get the index at which a given ID is stored.
static inline ebpf_result_t
_get_index_from_id(ebpf_id_t id, _Out_ uint32_t* index)
{
    uint32_t possible_index = id >> 16;
    if (id != _get_id_from_index(possible_index)) {
        return EBPF_KEY_NOT_FOUND;
    }

    *index = possible_index;
    return EBPF_SUCCESS;
}

static ebpf_result_t
_ebpf_object_tracking_list_insert(_Inout_ ebpf_core_object_t* object)
{
    int new_index;
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
    for (new_index = 1; new_index < EBPF_COUNT_OF(_ebpf_id_table); new_index++) {
        if (_ebpf_id_table[new_index].object == NULL) {
            break;
        }
    }
    if (new_index == EBPF_COUNT_OF(_ebpf_id_table)) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // Generate a new ID.
    _ebpf_id_table[new_index].counter++;
    _ebpf_id_table[new_index].object = object;
    object->id = _get_id_from_index(new_index);

    return_value = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);

    return EBPF_SUCCESS;
}

_Requires_lock_held_(&_ebpf_object_tracking_list_lock) static void _ebpf_object_tracking_list_remove(
    ebpf_core_object_t* object)
{
    uint32_t index;
    ebpf_result_t return_value = _get_index_from_id(object->id, &index);
    ebpf_assert(return_value == EBPF_SUCCESS);

    // In a release build, ebpf_assert is a no-op so we
    // need to avoid an unreferenced variable warning.
    UNREFERENCED_PARAMETER(return_value);

    _ebpf_id_table[index].object = NULL;
}

void
ebpf_object_tracking_initiate()
{
    ebpf_lock_create(&_ebpf_object_tracking_list_lock);
    memset(_ebpf_id_table, 0, sizeof(_ebpf_id_table));
}

void
ebpf_object_tracking_terminate()
{
    for (int index = 0; index < EBPF_COUNT_OF(_ebpf_id_table); index++) {
        ebpf_assert(_ebpf_id_table[index].object == NULL || ebpf_fuzzing_enabled);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_initialize(
    ebpf_core_object_t* object,
    ebpf_object_type_t object_type,
    ebpf_free_object_t free_function,
    ebpf_object_get_program_type_t get_program_type_function)
{
    EBPF_LOG_MESSAGE_POINTER_ENUM(
        EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object initialized", object, object_type);
    object->marker = _ebpf_object_marker;
    object->reference_count = 1;
    object->type = object_type;
    object->free_function = free_function;
    object->get_program_type = get_program_type_function;
    ebpf_list_initialize(&object->object_list_entry);

    return _ebpf_object_tracking_list_insert(object);
}

void
ebpf_object_acquire_reference(ebpf_core_object_t* object)
{
    ebpf_assert(object->marker == _ebpf_object_marker);
    ebpf_assert(object->reference_count != 0);
    ebpf_interlocked_increment_int32(&object->reference_count);
}

_Requires_lock_held_(&_ebpf_object_tracking_list_lock) void _ebpf_object_release_reference_under_lock(
    ebpf_core_object_t* object)
{
    uint32_t new_ref_count;

    if (!object)
        return;

    ebpf_assert(object->marker == _ebpf_object_marker);
    ebpf_assert(object->reference_count != 0);

    new_ref_count = ebpf_interlocked_decrement_int32(&object->reference_count);

    if (new_ref_count == 0) {
        EBPF_LOG_MESSAGE_POINTER_ENUM(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object terminated", object, object->type);

        _ebpf_object_tracking_list_remove(object);
        object->marker = ~object->marker;
        object->free_function(object);
    }
}

void
ebpf_object_release_reference(ebpf_core_object_t* object)
{
    uint32_t new_ref_count;

    if (!object)
        return;

    ebpf_assert(object->marker == _ebpf_object_marker);
    ebpf_assert(object->reference_count != 0);

    new_ref_count = ebpf_interlocked_decrement_int32(&object->reference_count);

    if (new_ref_count == 0) {
        EBPF_LOG_MESSAGE_POINTER_ENUM(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object terminated", object, object->type);
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
        _ebpf_object_tracking_list_remove(object);
        ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
        object->marker = ~object->marker;
        object->free_function(object);
    }
}

ebpf_object_type_t
ebpf_object_get_type(ebpf_core_object_t* object)
{
    return object->type;
}

_Must_inspect_result_ ebpf_result_t
ebpf_duplicate_utf8_string(_Out_ ebpf_utf8_string_t* destination, _In_ const ebpf_utf8_string_t* source)
{
    if (!source->value || !source->length) {
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

_Requires_lock_held_(&_ebpf_object_tracking_list_lock) static ebpf_core_object_t* _get_next_object_by_id(
    ebpf_id_t start_id, ebpf_object_type_t object_type)
{
    // The start_id need not exist, so we can't call _get_index_from_id().
    uint32_t index = (start_id >> 16);
    if (_get_id_from_index(index) == start_id) {
        index++;
    }
    while (index < EBPF_COUNT_OF(_ebpf_id_table)) {
        ebpf_core_object_t* object = _ebpf_id_table[index].object;
        if ((object != NULL) && (object->type == object_type)) {
            return object;
        }
        index++;
    }
    return NULL;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_get_next_id(ebpf_id_t start_id, ebpf_object_type_t object_type, _Out_ ebpf_id_t* next_id)
{
    ebpf_result_t return_value = EBPF_NO_MORE_KEYS;

    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    ebpf_core_object_t* object = _get_next_object_by_id(start_id, object_type);
    if (object != NULL) {
        *next_id = object->id;
        return_value = EBPF_SUCCESS;
    }

    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    return return_value;
}

void
ebpf_object_reference_next_object(
    ebpf_core_object_t* previous_object, ebpf_object_type_t type, ebpf_core_object_t** next_object)
{
    ebpf_lock_state_t state;
    *next_object = NULL;

    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    ebpf_id_t start_id = (previous_object) ? previous_object->id : 0;
    ebpf_core_object_t* object = _get_next_object_by_id(start_id, type);
    if (object != NULL) {
        *next_object = object;
        ebpf_object_acquire_reference(object);
    }

    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_reference_by_id(ebpf_id_t id, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    uint32_t index;
    ebpf_result_t return_value = _get_index_from_id(id, &index);
    if (return_value == EBPF_SUCCESS) {
        if (index >= EBPF_COUNT_OF(_ebpf_id_table)) {
            return_value = EBPF_KEY_NOT_FOUND;
        } else {
            ebpf_core_object_t* found = _ebpf_id_table[index].object;
            if ((found != NULL) && (found->type == object_type)) {
                ebpf_object_acquire_reference(found);
                *object = found;
            } else
                return_value = EBPF_KEY_NOT_FOUND;
        }
    }

    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_dereference_by_id(ebpf_id_t id, ebpf_object_type_t object_type)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    uint32_t index;
    ebpf_result_t return_value = _get_index_from_id(id, &index);
    if (return_value == EBPF_SUCCESS) {
        ebpf_core_object_t* found = _ebpf_id_table[index].object;
        if ((found != NULL) && (found->type == object_type)) {
            _ebpf_object_release_reference_under_lock(found);
        } else
            return_value = EBPF_KEY_NOT_FOUND;
    }

    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    return return_value;
}
