// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_handle.h"
#include "ebpf_object.h"

#include <intrin.h>

static const uint32_t _ebpf_object_marker = 'eobj';

static ebpf_lock_t _ebpf_object_tracking_list_lock = {0};

/**
 * @brief Objects are allocated an entry in the the ID
 * table when they are initialized.  Along with a pointer to the
 * object, each id table entry maintains its own ref-count that
 * starts off at 1 when it is assigned to a new object. The
 * entry ref-count indicates the number of other objects
 * holding a reference to the corresponding object's id.  On the
 * destruction of an object, the object pointer in the
 * corresponding id table entry is reset to NULL and the entry
 * ref-count is also decremented. Note that the entry will
 * continue to be considered 'in use' until all other objects
 * are done with the associated object (they let go of their
 * references to this entry).  When the entry ref-count goes
 * down to 0 _and_ the object pointer is NULL, it is eligible
 * for re-use. Note that either of these events can occur first.
 *
 * Map objects can have references due to one of the following:
 * 1) An open handle holds a reference on it.
 * 2) A pinning table entry holds a reference on it.
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

    // Reference count for this entry itself. This will be 1 when the pointed-to object (below) is created and
    // incremented for every other object that holds a reference to this entry.
    //
    // If the pointed-to object gets destroyed first:
    // - the object pointer will be nulled out and the id entry ref count will be decremented. After this point,
    //   other objects that continue to hold a reference to this id entry, will fail to acquire a reference to the
    //   pointed-to object (via its id) and will need to handle the failure gracefully.
    //
    // If the id references get dropped first:
    // - the id entry count gets decremented.  Even after all the other objects holding a reference to this id entry
    //   drop their references, the final ref-count will be 1 as the object is still around.  When the object is
    //   finally destroyed, the entry id ref count goes to zero and and the entry can now be re-used.
    int64_t reference_count;

    // Pointer to object.
    ebpf_core_object_t* object;
} ebpf_id_entry_t;

// Currently we allow a maximum of 1024 objects (links, maps,
// and programs combined).  This can be increased in the future
// if needed by making each array element store a linked list of
// entries in order by ID, rather than a single entry, in which
// case this becomes a hash table.
static _Guarded_by_(_ebpf_object_tracking_list_lock) ebpf_id_entry_t _ebpf_id_table[1024];

/**
 * @brief An enum of operations that can be performed on an object reference.
 */
typedef enum _ebpf_object_reference_operationEBPF_OBJECT_INITIALIZE
{
    EBPF_OBJECT_CREATE,
    EBPF_OBJECT_ACQUIRE,
    EBPF_OBJECT_RELEASE,
    EBPF_OBJECT_DESTROY,
} ebpf_object_reference_operation_t;

/**
 * @brief A history of object references. This is used to track
 * down the source of a reference leak and use after free bugs.
 * This is a circular buffer of the last 1024 references with the
 * next index to write to stored in _ebpf_object_reference_history_index.
 */
static _Guarded_by_(_ebpf_object_reference_history_lock) struct _ebpf_object_reference_entry
{
    uintptr_t object : 64;
    ebpf_file_id_t file_id : 16;
    unsigned int line : 32;
    ebpf_object_reference_operation_t operation : 16;
} _ebpf_object_reference_history[1024];

/**
 * @brief The index of the next entry to write to in the reference history.
 * This is updated atomically using interlocked operations and should be used
 * modulo count of _ebpf_object_reference_history.
 */
static _Guarded_by_(_ebpf_object_reference_history_lock) size_t _ebpf_object_reference_history_index = 0;

static ebpf_lock_t _ebpf_object_reference_history_lock = {0};

static inline void
_update_reference_history(void* object, ebpf_object_reference_operation_t operation, uint32_t file_id, uint32_t line)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_reference_history_lock);

    size_t index = _ebpf_object_reference_history_index++;
    index %= EBPF_COUNT_OF(_ebpf_object_reference_history);

    _ebpf_object_reference_history[index].object = (uintptr_t)object;
    _ebpf_object_reference_history[index].operation = operation;
    _ebpf_object_reference_history[index].file_id = file_id;
    _ebpf_object_reference_history[index].line = line;

    ebpf_lock_unlock(&_ebpf_object_reference_history_lock, state);
}

/**
 * @brief Add an entry to the reference history.
 *
 * @param[in] object Object being referenced.
 * @param[in] acquire True if this is an acquire reference, false if it is a release reference.
 * @param[in] file_id Id of the file where the reference was acquired or released.
 * @param[in] line Line number in the file where the reference was acquired or released.
 */
void
ebpf_object_update_reference_history(void* object, bool acquire, uint32_t file_id, uint32_t line)
{
    _update_reference_history(object, acquire ? EBPF_OBJECT_ACQUIRE : EBPF_OBJECT_RELEASE, file_id, line);
}

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
_ebpf_object_tracking_list_insert(_Inout_ ebpf_core_object_t* object, ebpf_file_id_t file_id, uint32_t line)
{
    int new_index;
    ebpf_result_t return_value;
    ebpf_lock_state_t state;
    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
    for (new_index = 1; new_index < EBPF_COUNT_OF(_ebpf_id_table); new_index++) {
        if (_ebpf_id_table[new_index].object == NULL && _ebpf_id_table[new_index].reference_count == 0) {
            break;
        }
    }
    if (new_index == EBPF_COUNT_OF(_ebpf_id_table)) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // Generate a new ID.
    _ebpf_id_table[new_index].counter++;
    _ebpf_id_table[new_index].reference_count = 1;
    _ebpf_id_table[new_index].object = object;
    _update_reference_history(&_ebpf_id_table[new_index], EBPF_OBJECT_CREATE, file_id, line);
    object->id = _get_id_from_index(new_index);

    return_value = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);

    return return_value;
}

_Requires_lock_held_(&_ebpf_object_tracking_list_lock) static void _ebpf_object_tracking_list_remove(
    _In_ const ebpf_core_object_t* object, ebpf_file_id_t file_id, uint32_t line)
{
    uint32_t index;
    ebpf_result_t return_value = _get_index_from_id(object->id, &index);
    ebpf_assert(return_value == EBPF_SUCCESS);

    // In a release build, ebpf_assert is a no-op so we need to avoid an unreferenced variable warning.
    UNREFERENCED_PARAMETER(return_value);

    // Under lock, so un-protected access is ok.
    _ebpf_id_table[index].reference_count--;
    _update_reference_history(&_ebpf_id_table[index], EBPF_OBJECT_RELEASE, file_id, line);
    ebpf_assert(_ebpf_id_table[index].reference_count >= 0);
    _ebpf_id_table[index].object = NULL;
}

void
ebpf_object_tracking_initiate()
{
    ebpf_lock_create(&_ebpf_object_tracking_list_lock);
    memset(_ebpf_id_table, 0, sizeof(_ebpf_id_table));
    memset(_ebpf_object_reference_history, 0, sizeof(_ebpf_object_reference_history));
    _ebpf_object_reference_history_index = 0;
}

void
ebpf_object_tracking_terminate()
{
    for (int index = 0; index < EBPF_COUNT_OF(_ebpf_id_table); index++) {
        ebpf_assert(_ebpf_id_table[index].object == NULL || ebpf_fuzzing_enabled);
        ebpf_assert(_ebpf_id_table[index].reference_count == 0 || ebpf_fuzzing_enabled);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_initialize(
    _Inout_ ebpf_core_object_t* object,
    ebpf_object_type_t object_type,
    ebpf_free_object_t free_function,
    ebpf_object_get_program_type_t get_program_type_function,
    ebpf_file_id_t file_id,
    uint32_t line)
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
    _update_reference_history(object, EBPF_OBJECT_CREATE, file_id, line);

    return _ebpf_object_tracking_list_insert(object, file_id, line);
}

void
ebpf_object_acquire_reference(_Inout_ ebpf_core_object_t* object, uint32_t file_id, uint32_t line)
{
    _update_reference_history(object, EBPF_OBJECT_ACQUIRE, file_id, line);
    if (object->base.marker != _ebpf_object_marker) {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }
    int64_t new_ref_count = ebpf_interlocked_increment_int64(&object->base.reference_count);
    if (new_ref_count == 1) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }
}

/**
 * @brief Try to acquire a reference on an object. If the object is in the process of being freed, this function will
 * fail.
 *
 * @param[in,out] object Object to acquire a reference on.
 * @retval true Reference was acquired.
 * @retval false Reference was not acquired.
 */
static bool
_ebpf_object_try_acquire_reference(_Inout_ ebpf_base_object_t* object, uint32_t file_id, uint32_t line)
{
    if (object->marker != _ebpf_object_marker) {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    for (;;) {
        int64_t new_ref_count = object->reference_count;
        if (new_ref_count < 0) {
            __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
        }

        if (new_ref_count == 0) {
            return false;
        }

        if (ebpf_interlocked_compare_exchange_int64(&object->reference_count, new_ref_count + 1, new_ref_count) ==
            new_ref_count) {
            _update_reference_history(object, EBPF_OBJECT_ACQUIRE, file_id, line);
            return true;
        }
    }
}

void
ebpf_object_release_reference(_Inout_opt_ ebpf_core_object_t* object, uint32_t file_id, uint32_t line)
{
    int64_t new_ref_count;
    _update_reference_history(object, EBPF_OBJECT_RELEASE, file_id, line);

    if (!object) {
        return;
    }

    if (object->base.marker != _ebpf_object_marker) {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    ebpf_assert(object->base.marker == _ebpf_object_marker);

    new_ref_count = ebpf_interlocked_decrement_int64(&object->base.reference_count);
    if (new_ref_count < 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    // Remove from object tracking list under the lock.
    if (new_ref_count == 0) {
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
        EBPF_LOG_MESSAGE_POINTER_ENUM(
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object terminated", object, object->type);
        _ebpf_object_tracking_list_remove(object, file_id, line);
        ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    }

    // Free the object outside the lock.
    if (new_ref_count == 0) {
        _update_reference_history(object, EBPF_OBJECT_DESTROY, file_id, line);
        object->base.marker = ~object->base.marker;
        object->free_function(object);
    }
}

ebpf_object_type_t
ebpf_object_get_type(_In_ const ebpf_core_object_t* object)
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
        if (!destination->value) {
            return EBPF_NO_MEMORY;
        }
        memcpy(destination->value, source->value, source->length);
        destination->length = source->length;
        return EBPF_SUCCESS;
    }
}

void
ebpf_utf8_string_free(_Inout_ ebpf_utf8_string_t* string)
{
    ebpf_free(string->value);
    string->value = NULL;
    string->length = 0;
}

/**
 * @brief Get the next object ID of a given type.
 *
 * @param[in] start_id ID to start searching from.
 * @param[in] object_type Type of object to search for.
 * @param[out] next_id Next object ID of the given type.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MORE_KEYS No more objects of the given type exist.
 */
_Requires_lock_held_(&_ebpf_object_tracking_list_lock) static ebpf_result_t
    _get_next_object_id_by_type(ebpf_id_t start_id, ebpf_object_type_t object_type, _Out_ ebpf_id_t* next_id)
{
    // The start_id need not exist, so we can't call _get_index_from_id().
    uint32_t index = (start_id >> 16);
    if (_get_id_from_index(index) == start_id) {
        index++;
    }
    while (index < EBPF_COUNT_OF(_ebpf_id_table)) {
        ebpf_core_object_t* object = _ebpf_id_table[index].object;
        if ((object != NULL) && (object->type == object_type)) {
            *next_id = _get_id_from_index(index);
            return EBPF_SUCCESS;
        }
        index++;
    }
    return EBPF_NO_MORE_KEYS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_get_next_id(ebpf_id_t start_id, ebpf_object_type_t object_type, _Out_ ebpf_id_t* next_id)
{
    ebpf_result_t return_value = EBPF_NO_MORE_KEYS;
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);
    return_value = _get_next_object_id_by_type(start_id, object_type, next_id);
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    return return_value;
}

void
ebpf_object_reference_next_object(
    _In_opt_ const ebpf_core_object_t* previous_object,
    ebpf_object_type_t type,
    _Outptr_result_maybenull_ ebpf_core_object_t** next_object,
    uint32_t file_id,
    uint32_t line)
{
    ebpf_result_t return_value = EBPF_SUCCESS;
    ebpf_lock_state_t state;
    *next_object = NULL;

    state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    ebpf_id_t start_id = (previous_object) ? previous_object->id : 0;

    while (*next_object == NULL) {
        uint32_t index;

        return_value = _get_next_object_id_by_type(start_id, type, &start_id);
        if (return_value != EBPF_SUCCESS) {
            break;
        }
        return_value = _get_index_from_id(start_id, &index);
        ebpf_assert(return_value == EBPF_SUCCESS);
        if (_ebpf_id_table[index].object == NULL) {
            continue;
        }
        if (!_ebpf_object_try_acquire_reference(&_ebpf_id_table[index].object->base, file_id, line)) {
            continue;
        }
        *next_object = _ebpf_id_table[index].object;
        break;
    }

    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    if (*next_object != NULL) {
        _update_reference_history(*next_object, EBPF_OBJECT_ACQUIRE, file_id, line);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_reference_by_id(
    ebpf_id_t id, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object, uint32_t file_id, uint32_t line)
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
                if (_ebpf_object_try_acquire_reference(&found->base, file_id, line)) {
                    *object = found;
                } else {
                    return_value = EBPF_KEY_NOT_FOUND;
                }
            } else {
                return_value = EBPF_KEY_NOT_FOUND;
            }
        }
    }

    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    if (return_value == EBPF_SUCCESS) {
        _update_reference_history(*object, EBPF_OBJECT_ACQUIRE, file_id, line);
    }
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
    ebpf_handle_t handle,
    ebpf_object_type_t object_type,
    _Outptr_ ebpf_core_object_t** object,
    uint32_t file_id,
    uint32_t line)
{
    return ebpf_reference_base_object_by_handle(
        handle, _ebpf_object_compare, &object_type, (ebpf_base_object_t**)object, file_id, line);
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

_Must_inspect_result_ ebpf_result_t
ebpf_object_acquire_id_reference(ebpf_id_t id, ebpf_object_type_t object_type, uint32_t file_id, uint32_t line)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    uint32_t index;
    ebpf_result_t result = _get_index_from_id(id, &index);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_id_entry_t* entry = &_ebpf_id_table[index];
    if (entry->reference_count <= 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    // ref count is non-zero
    if (entry->object == NULL) {

        // The object at this entry has been deleted and all that remains are (the now stale) references to this entry
        // held by other objects.  This is a non-reversible situation and there's no point in giving out references
        // for such entries, so deny with a suitable error code.
        result = EBPF_STALE_ID;
        goto Done;
    }

    ebpf_assert(entry->object->type == object_type);
    if (entry->object->type != object_type) {
        result = EBPF_INVALID_OBJECT;
        goto Done;
    }

    // We have a live object of the matching type and with an existing non-zero ref count, so we're good.
    // We're under lock so un-protected access is ok.
    entry->reference_count++;
    result = EBPF_SUCCESS;
    _update_reference_history(entry, EBPF_OBJECT_ACQUIRE, file_id, line);

Done:
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_release_id_reference(ebpf_id_t id, ebpf_object_type_t object_type, uint32_t file_id, uint32_t line)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_tracking_list_lock);

    uint32_t index;
    ebpf_result_t result = _get_index_from_id(id, &index);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    ebpf_id_entry_t* entry = &_ebpf_id_table[index];
    if (entry->reference_count <= 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    // ref count is non-zero
    if (entry->object != NULL) {

        // If the object is still around, it needs to be of the expected type.
        ebpf_assert(entry->object->type == object_type);
        if (entry->object->type != object_type) {
            result = EBPF_INVALID_OBJECT;
            goto Done;
        }
    }

    // Either we don't have an object or we have one of the matching type.  In either case, the existing entry
    // ref count is non-zero, so we're ok to decrement it.
    // We're also still under lock so un-protected updates are ok.
    entry->reference_count--;
    ebpf_assert(entry->reference_count >= 0);
    result = EBPF_SUCCESS;
    _update_reference_history(entry, EBPF_OBJECT_RELEASE, file_id, line);

Done:
    ebpf_lock_unlock(&_ebpf_object_tracking_list_lock, state);

    return result;
}
