// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_handle.h"
#include "ebpf_object.h"

static const uint32_t _ebpf_object_marker = 'eobj';

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

static _Must_inspect_result_ ebpf_result_t
_ebpf_object_weak_reference_associate(_In_ ebpf_core_object_t* object, _Outptr_ ebpf_weak_reference_t** weak_reference)
{
    ebpf_result_t result;
    ebpf_weak_reference_t* local_weak_reference;

    local_weak_reference = ebpf_allocate(sizeof(ebpf_weak_reference_t));
    if (local_weak_reference == NULL) {
        result = EBPF_NO_MEMORY;
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Weak reference object allocation failed.", result);
        goto Done;
    }

    ebpf_lock_create(&local_weak_reference->lock);
    local_weak_reference->object = object;
    (void)ebpf_interlocked_increment_int64(&local_weak_reference->reference_count);
    result = EBPF_SUCCESS;

Done:
    *weak_reference = local_weak_reference;
    return result;
}

static void
_ebpf_object_weak_reference_disassociate(_In_ ebpf_weak_reference_t* weak_reference)
{
    if (!weak_reference) {
        return;
    }

    // Mark the weak_ref as 'disassociating' by clearing the object pointer.  From this point on, it won't hand out
    // a valid object pointer but will hang around until its own ref count goes to zero, is freed and thereby
    // completing its disassociation from the object.
    ebpf_interlocked_compare_exchange_pointer(&weak_reference->object, NULL, weak_reference->object);
    int64_t new_ref_count = ebpf_interlocked_decrement_int64(&weak_reference->reference_count);
    if (new_ref_count == 0) {
        ebpf_lock_destroy(&weak_reference->lock);
        ebpf_free(weak_reference);
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
    object->base.marker = _ebpf_object_marker;
    object->base.reference_count = 1;
    object->base.acquire_reference = ebpf_object_acquire_reference;
    object->base.release_reference = ebpf_object_release_reference;
    object->type = object_type;
    object->free_function = free_function;
    object->get_program_type = get_program_type_function;
    ebpf_list_initialize(&object->object_list_entry);

    ebpf_result_t result = _ebpf_object_weak_reference_associate(object, &object->self_weak_reference);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    result = _ebpf_object_tracking_list_insert(object);
    if (result != EBPF_SUCCESS) {
        _ebpf_object_weak_reference_disassociate(object->self_weak_reference);
    }

Done:
    return result;
}

void
ebpf_object_acquire_reference(ebpf_core_object_t* object)
{
    ebpf_assert(object->base.marker == _ebpf_object_marker);
    int32_t new_ref_count = ebpf_interlocked_increment_int32(&object->base.reference_count);
    ebpf_assert(new_ref_count != 1);
}

_Requires_lock_held_(&_ebpf_object_tracking_list_lock) static void _ebpf_object_release_reference_under_lock(
    ebpf_core_object_t* object)
{
    int32_t new_ref_count;

    if (!object)
        return;

    ebpf_assert(object->base.marker == _ebpf_object_marker);

    new_ref_count = ebpf_interlocked_decrement_int32(&object->base.reference_count);
    ebpf_assert(new_ref_count != -1);

    if (new_ref_count == 0) {
        EBPF_LOG_MESSAGE_POINTER_ENUM(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object terminated", object, object->type);

        _ebpf_object_tracking_list_remove(object);
        object->base.marker = ~object->base.marker;
        _ebpf_object_weak_reference_disassociate(object->self_weak_reference);
        object->free_function(object);
    }
}

void
ebpf_object_release_reference(ebpf_core_object_t* object)
{
    int32_t new_ref_count;

    if (!object)
        return;

    ebpf_assert(object->base.marker == _ebpf_object_marker);

    new_ref_count = ebpf_interlocked_decrement_int32(&object->base.reference_count);
    ebpf_assert(new_ref_count != -1);

    if (new_ref_count == 0) {
        EBPF_LOG_MESSAGE_POINTER_ENUM(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object terminated", object, object->type);
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
        _ebpf_object_tracking_list_remove(object);
        ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
        object->base.marker = ~object->base.marker;
        _ebpf_object_weak_reference_disassociate(object->self_weak_reference);
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

static bool
_ebpf_object_compare(_In_ const ebpf_base_object_t* object, _In_ const void* context)
{
    ebpf_assert(context != NULL);
    __analysis_assume(context != NULL);

    if (object->marker != _ebpf_object_marker) {
        return false;
    }

    ebpf_core_object_t* local_object = (ebpf_core_object_t*)object;
    ebpf_object_type_t object_type = *((ebpf_object_type_t*)context);
    if ((object_type != EBPF_OBJECT_UNKNOWN) && (ebpf_object_get_type(local_object) != object_type)) {
        return false;
    }

    return true;
}

ebpf_result_t
ebpf_object_reference_by_handle(
    ebpf_handle_t handle, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object)
{
    return ebpf_reference_base_object_by_handle(
        handle, _ebpf_object_compare, &object_type, (ebpf_base_object_t**)object);
}

_Must_inspect_result_ char*
ebpf_duplicate_string(_In_z_ const char* source)
{
    size_t length = strlen(source) + 1;
    char* destination = ebpf_allocate(length);
    if (destination == NULL) {
        return NULL;
    }
    memcpy(destination, source, length);
    return destination;
}

_Must_inspect_result_ ebpf_weak_reference_t*
ebpf_object_weak_reference_get_reference(_In_ ebpf_core_object_t* object)
{
    ebpf_assert(object);
    (void)ebpf_interlocked_increment_int64(&object->self_weak_reference->reference_count);

    return object->self_weak_reference;
}

_Must_inspect_result_ _Ret_maybenull_ ebpf_core_object_t*
ebpf_object_weak_reference_get_object_reference(_In_ ebpf_weak_reference_t* weak_reference)
{
    ebpf_core_object_t* object;

    ebpf_assert(weak_reference);

    // A weak reference's lifetime is independent from that of the (primary) object it is associated with, so this call
    // cannot guarantee the return of a valid pointer for the associated primary object.  The logic below ensures that
    // we return a valid pointer *iff* the primary object has since not been destroyed _and_ is not in the process of
    // being destroyed.
    //
    // This is ensured by incrementing the object ref-count *iff* it is non-zero (and returning its pointer), else
    // returning NULL.
    for (;;) {

        // If the primary object has been marked for destruction, it will (sooner or later) disassociate itself
        // from its weak pointer (amongst other things, weak_reference->object is set to NULL), thus the loop will
        // eventually converge.
        object = ebpf_interlocked_compare_exchange_pointer(&weak_reference->object, NULL, NULL);
        if (object == NULL) {
            break;
        }

        // Object is is process of being destroyed. Can't give out a pointer to this object, so return NULL.
        volatile int32_t old_ref_count = object->base.reference_count;
        if (old_ref_count == 0) {
            object = NULL;
            break;
        }

        // At this point, the object pointer is non-null and old_ref_count is non-zero.  Also, by the time we get
        // to the compare-exchange operation below, object->base.reference_count could be in one of 3 possible states,
        // thus affecting the cmp-exch operation:
        //
        // 1. object->base.reference_count goes to 0:
        //    The cmp-exch operation will fail, it's return value will != old_ref_count, so we continue in the loop
        //    and break out when we see it to be zero (above).
        //
        // 2. object->base.reference_count gets incremented or decremented:
        //    The cmp-exch operation will fail, its return value will != old_ref_count, so we continue in the loop
        //    and do the cmp-exch again.
        //
        // 3. object->base.reference_count remains un-changed:
        //    The cmp-exch operation will succeed (also increment the ref-count), its return value is == old_ref_count,
        //    so we break out if the loop, and end up returning a valid pointer to the primary object.
        if (ebpf_interlocked_compare_exchange_int32(&object->base.reference_count, old_ref_count + 1, old_ref_count) ==
            old_ref_count) {
            break;
        }
    }

    return object;
}

void
ebpf_object_weak_reference_acquire_reference(_In_ ebpf_weak_reference_t* weak_reference)
{
    ebpf_assert(weak_reference);
    (void)ebpf_interlocked_increment_int64(&weak_reference->reference_count);
}

void
ebpf_object_weak_reference_release_reference(_In_ ebpf_weak_reference_t* weak_reference)
{
    ebpf_assert(weak_reference);
    int64_t new_ref_count = ebpf_interlocked_decrement_int64(&weak_reference->reference_count);
    ebpf_assert(new_ref_count != -1);
    if (new_ref_count == 0) {
        ebpf_free(weak_reference);
    }
}
