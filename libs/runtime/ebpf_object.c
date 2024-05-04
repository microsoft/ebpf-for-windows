// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "cxplat.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_hash_table.h"
#include "ebpf_object.h"
#include "ebpf_shared_framework.h"
#include "ebpf_tracelog.h"

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
 * down to 0 it is eligible.
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
    int64_t reference_count;    ///< Number of references to this entry.
    ebpf_object_type_t type;    ///< Type of object.
    ebpf_core_object_t* object; ///< Pointer to the object associated with this entry.
} ebpf_id_entry_t;

static ebpf_hash_table_t* _ebpf_id_table = NULL; ///< Table of object IDs to object pointers.
static volatile ebpf_id_t _ebpf_next_id = 1;     ///< Next ID to assign to an object.

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

cxplat_rundown_reference_t _ebpf_object_rundown_ref;

static inline void
_update_reference_history(void* object, ebpf_object_reference_operation_t operation, uint32_t file_id, uint32_t line)
{
#if !defined(NDEBUG)
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_object_reference_history_lock);

    size_t index = _ebpf_object_reference_history_index++;
    index %= EBPF_COUNT_OF(_ebpf_object_reference_history);

    _ebpf_object_reference_history[index].object = (uintptr_t)object;
    _ebpf_object_reference_history[index].operation = operation;
    _ebpf_object_reference_history[index].file_id = file_id;
    _ebpf_object_reference_history[index].line = line;

    ebpf_lock_unlock(&_ebpf_object_reference_history_lock, state);
#else
    UNREFERENCED_PARAMETER(object);
    UNREFERENCED_PARAMETER(operation);
    UNREFERENCED_PARAMETER(file_id);
    UNREFERENCED_PARAMETER(line);
#endif
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

static void
_ebpf_object_tracking_list_remove(_In_ const ebpf_core_object_t* object, ebpf_file_id_t file_id, uint32_t line)
{
    ebpf_id_entry_t* entry = NULL;
    ebpf_result_t return_value = ebpf_hash_table_find(_ebpf_id_table, (const uint8_t*)&object->id, (uint8_t**)&entry);
    ebpf_assert(return_value == EBPF_SUCCESS);

    ebpf_assert(entry->object == object);
    entry->object = NULL;

    ebpf_object_release_id_reference(object->id, object->type, file_id, line);
}

ebpf_result_t
ebpf_object_tracking_initiate()
{
    _ebpf_next_id = 1;
    ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(ebpf_id_t),
        .value_size = sizeof(ebpf_id_entry_t),
        .max_entries = EBPF_HASH_TABLE_NO_LIMIT,
        .minimum_bucket_count = 1024,
    };

    memset(_ebpf_object_reference_history, 0, sizeof(_ebpf_object_reference_history));
    _ebpf_object_reference_history_index = 0;

    cxplat_initialize_rundown_protection(&_ebpf_object_rundown_ref);

    return ebpf_hash_table_create(&_ebpf_id_table, &options);
}

void
ebpf_object_tracking_terminate()
{
    if (!_ebpf_id_table) {
        return;
    }

    cxplat_wait_for_rundown_protection_release(&_ebpf_object_rundown_ref);

    ebpf_hash_table_destroy(_ebpf_id_table);
    _ebpf_id_table = NULL;
}

static void
_ebpf_object_epoch_free(_Inout_ void* context)
{
    ebpf_core_object_t* object = (ebpf_core_object_t*)context;
    EBPF_LOG_MESSAGE_POINTER_ENUM(
        EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object terminated", object, object->type);

    object->base.marker = ~object->base.marker;
    object->free_function(object);
    cxplat_release_rundown_protection(&_ebpf_object_rundown_ref);
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_initialize(
    _Inout_ ebpf_core_object_t* object,
    ebpf_object_type_t object_type,
    _In_ ebpf_free_object_t free_function,
    _In_opt_ ebpf_zero_ref_count_t zero_ref_count_function,
    ebpf_object_get_program_type_t get_program_type_function,
    ebpf_file_id_t file_id,
    uint32_t line)
{
    ebpf_result_t result;

    EBPF_LOG_MESSAGE_POINTER_ENUM(
        EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_BASE, "eBPF object initialized", object, object_type);
    object->base.marker = _ebpf_object_marker;
    object->base.reference_count = 1;
    object->base.acquire_reference = ebpf_object_acquire_reference;
    object->base.release_reference = ebpf_object_release_reference;
    object->type = object_type;
    object->free_function = free_function;
    object->zero_ref_count = zero_ref_count_function;
    object->get_program_type = get_program_type_function;
    object->id = ebpf_interlocked_increment_int32((volatile int32_t*)&_ebpf_next_id);
    // Skip invalid IDs.
    while (object->id == 0 || object->id == EBPF_ID_NONE) {
        object->id = ebpf_interlocked_increment_int32((volatile int32_t*)&_ebpf_next_id);
    }
    ebpf_list_initialize(&object->object_list_entry);
    ebpf_epoch_work_item_t* free_work_item = NULL;

    free_work_item = ebpf_epoch_allocate_work_item(object, _ebpf_object_epoch_free);
    if (!free_work_item) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    _update_reference_history(object, EBPF_OBJECT_CREATE, file_id, line);

    ebpf_id_entry_t entry = {.reference_count = 1, .type = object_type, .object = object};

    // Use EBPF_HASH_TABLE_OPERATION_INSERT so that it fails if the key already exists.
    result = ebpf_hash_table_update(
        _ebpf_id_table, (const uint8_t*)&object->id, (const uint8_t*)&entry, EBPF_HASH_TABLE_OPERATION_INSERT);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_POINTER_ENUM(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "eBPF object failed to initialize due to insert in _ebpf_id_table failure",
            object,
            object_type);
        goto Done;
    }

#if !defined(NDEBUG)
    ebpf_id_entry_t* new_entry = NULL;
    result = ebpf_hash_table_find(_ebpf_id_table, (const uint8_t*)&object->id, (uint8_t**)&new_entry);
    if (result != EBPF_SUCCESS) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }
    _update_reference_history(new_entry, EBPF_OBJECT_CREATE, file_id, line);
#endif

    cxplat_acquire_rundown_protection(&_ebpf_object_rundown_ref);

    object->free_work_item = free_work_item;
    free_work_item = NULL;

Done:
    ebpf_epoch_cancel_work_item(free_work_item);
    return result;
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
    if (!object) {
        return;
    }

    _update_reference_history(object, EBPF_OBJECT_RELEASE, file_id, line);

    if (object->base.marker != _ebpf_object_marker) {
        __fastfail(FAST_FAIL_INVALID_ARG);
    }

    ebpf_assert(object->base.marker == _ebpf_object_marker);

    new_ref_count = ebpf_interlocked_decrement_int64(&object->base.reference_count);
    if (new_ref_count < 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    if (new_ref_count == 0) {
        _ebpf_object_tracking_list_remove(object, file_id, line);
        _update_reference_history(object, EBPF_OBJECT_DESTROY, file_id, line);
        if (object->zero_ref_count) {
            object->zero_ref_count(object);
        }
        ebpf_epoch_schedule_work_item(object->free_work_item);
    }
}

ebpf_object_type_t
ebpf_object_get_type(_In_ const ebpf_core_object_t* object)
{
    return object->type;
}

_Must_inspect_result_ ebpf_result_t
ebpf_duplicate_utf8_string(_Out_ cxplat_utf8_string_t* destination, _In_ const cxplat_utf8_string_t* source)
{
    cxplat_status_t status = cxplat_duplicate_utf8_string(destination, source);
    return ebpf_result_from_cxplat_status(status);
}

static bool
_ebpf_object_match_object_type(_In_ void* filter_context, _In_ const uint8_t* key, _In_ const uint8_t* value)
{
    ebpf_object_type_t* object_type = (ebpf_object_type_t*)filter_context;
    ebpf_id_entry_t* entry = (ebpf_id_entry_t*)value;
    UNREFERENCED_PARAMETER(key);
    return (entry->type == *object_type);
}

static int
_ebpf_object_id_sort(_In_ const uint8_t* key1, _In_ const uint8_t* key2)
{
    ebpf_id_t id1 = *(ebpf_id_t*)key1;
    ebpf_id_t id2 = *(ebpf_id_t*)key2;
    if (id1 < id2) {
        return -1;
    } else if (id1 > id2) {
        return 1;
    } else {
        return 0;
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_get_next_id(ebpf_id_t start_id, ebpf_object_type_t object_type, _Out_ ebpf_id_t* next_id)
{
    // TODO: https://github.com/microsoft/ebpf-for-windows/issues/2985
    // Switch this to a data structure that supports sorted iteration.
    ebpf_id_entry_t* entry = NULL;
    ebpf_result_t result = ebpf_hash_table_next_key_and_value_sorted(
        _ebpf_id_table,
        start_id ? (const uint8_t*)&start_id : NULL,
        _ebpf_object_id_sort,
        &object_type,
        _ebpf_object_match_object_type,
        (uint8_t*)next_id,
        (uint8_t**)&entry);
    if (result != EBPF_SUCCESS) {
        return EBPF_NO_MORE_KEYS;
    } else {
        return EBPF_SUCCESS;
    }
}

void
ebpf_object_reference_next_object(
    _In_opt_ const ebpf_core_object_t* previous_object,
    ebpf_object_type_t object_type,
    _Outptr_result_maybenull_ ebpf_core_object_t** next_object,
    uint32_t file_id,
    uint32_t line)
{
    ebpf_id_entry_t* entry = NULL;
    ebpf_result_t result;
    ebpf_id_t previous_key = previous_object ? previous_object->id : 0;
    ebpf_id_t next_key;
    ebpf_core_object_t* object = NULL;
    *next_object = NULL;

    for (;;) {
        result = ebpf_hash_table_next_key_and_value(
            _ebpf_id_table,
            previous_key ? (const uint8_t*)&previous_key : NULL,
            (uint8_t*)&next_key,
            (uint8_t**)&entry);
        if (result != EBPF_SUCCESS) {
            break;
        }
        previous_key = next_key;

        object = entry->object;

        // Skip entries that have been deleted.
        if (object == NULL) {
            continue;
        }

        // Skip entries that are not of the requested type.
        if (entry->type != object_type) {
            continue;
        }

        // Try to acquire a reference on the object.
        if (!_ebpf_object_try_acquire_reference(&object->base, file_id, line)) {
            continue;
        }

        // Return this entry.
        *next_object = object;
        break;
    }

    if (*next_object != NULL) {
        _update_reference_history(*next_object, EBPF_OBJECT_ACQUIRE, file_id, line);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_reference_by_id(
    ebpf_id_t id, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object, uint32_t file_id, uint32_t line)
{
    ebpf_result_t result;
    ebpf_id_entry_t* entry = NULL;
    ebpf_core_object_t* found_object = NULL;

    result = ebpf_hash_table_find(_ebpf_id_table, (const uint8_t*)&id, (uint8_t**)&entry);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    found_object = entry->object;
    // Skip entries that have been deleted.
    if (found_object == NULL) {
        result = EBPF_KEY_NOT_FOUND;
        goto Done;
    }

    // Skip entries that are not of the requested type.
    if (entry->type != object_type) {
        result = EBPF_KEY_NOT_FOUND;
        goto Done;
    }

    // Try to acquire a reference on the object.
    if (!_ebpf_object_try_acquire_reference(&found_object->base, file_id, line)) {
        result = EBPF_KEY_NOT_FOUND;
        goto Done;
    }

    _update_reference_history(found_object, EBPF_OBJECT_ACQUIRE, file_id, line);

    // Return this entry.
    *object = found_object;
Done:

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_pointer_by_id(ebpf_id_t id, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object)
{
    ebpf_result_t result;
    ebpf_id_entry_t* entry = NULL;
    ebpf_core_object_t* found_object = NULL;

    result = ebpf_hash_table_find(_ebpf_id_table, (const uint8_t*)&id, (uint8_t**)&entry);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    found_object = entry->object;
    // Skip entries that have been deleted.
    if (found_object == NULL) {
        result = EBPF_KEY_NOT_FOUND;
        goto Done;
    }

    // If the type is wrong, then the caller's reference is invalid.
    // This is a bug in the caller, so we fail fast.
    if (entry->type != object_type) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    result = EBPF_SUCCESS;
    *object = found_object;

Done:
    return result;
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

_Must_inspect_result_ ebpf_result_t
ebpf_object_acquire_id_reference(ebpf_id_t id, ebpf_object_type_t object_type, uint32_t file_id, uint32_t line)
{
    ebpf_id_entry_t* entry = NULL;
    ebpf_result_t result = ebpf_hash_table_find(_ebpf_id_table, (const uint8_t*)&id, (uint8_t**)&entry);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Skip entries that have been deleted.
    if (entry->object == NULL) {
        result = EBPF_INVALID_OBJECT;
        goto Done;
    }

    // Skip entries that are not of the requested type.
    if (entry->type != object_type) {
        result = EBPF_INVALID_OBJECT;
        goto Done;
    }

    // Acquire a reference on the entry.
    int64_t new_refcount = ebpf_interlocked_increment_int64(&entry->reference_count);
    if (new_refcount <= 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    // Update the reference history.
    ebpf_object_update_reference_history(entry, EBPF_OBJECT_ACQUIRE, file_id, line);

Done:
    return result;
}

void
ebpf_object_release_id_reference(ebpf_id_t id, ebpf_object_type_t object_type, uint32_t file_id, uint32_t line)
{
    ebpf_id_entry_t* entry = NULL;
    // Find the entry in the ID table.
    ebpf_result_t result = ebpf_hash_table_find(_ebpf_id_table, (const uint8_t*)&id, (uint8_t**)&entry);
    if (result != EBPF_SUCCESS) {
        // This should never happen as it means the caller is trying to release a reference
        // to an entry that does not exist.
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    if (entry->type != object_type) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    int64_t new_refcount = ebpf_interlocked_decrement_int64(&entry->reference_count);
    if (new_refcount < 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }
    ebpf_object_update_reference_history(entry, EBPF_OBJECT_RELEASE, file_id, line);

    if (new_refcount == 0) {
        result = ebpf_hash_table_delete(_ebpf_id_table, (const uint8_t*)&id);
        if (result != EBPF_SUCCESS) {
            __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
        }
        ebpf_object_update_reference_history(entry, EBPF_OBJECT_DESTROY, file_id, line);
    }
}
