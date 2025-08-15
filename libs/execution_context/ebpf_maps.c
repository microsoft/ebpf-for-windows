// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_MAPS

#include "ebpf_async.h"
#include "ebpf_bitmap.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_hash_table.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_core_map
{
    ebpf_core_object_t object;
    cxplat_utf8_string_t name;
    ebpf_map_definition_in_memory_t ebpf_map_definition;
    uint32_t original_value_size;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_core_object_map
{
    ebpf_core_map_t core_map;
    ebpf_lock_t lock;
    ebpf_map_definition_in_memory_t inner_template_map_definition;
    bool is_program_type_set;
    ebpf_program_type_t program_type;
} ebpf_core_object_map_t;

// Generations:
// 0: Uninitialized.
// 1 to 2^64-2: Valid generations.
// 2^64-1: Invalid generation (being deleted).

#define EBPF_LRU_INITIAL_GENERATION 1
#define EBPF_LRU_INVALID_GENERATION 0xFFFFFFFFFFFFFFFF

// Define the granularity at which the LRU list is updated.
#define EBPF_LRU_GENERATION_COUNT 10

// Limit maximum number of partitions to 8 as a trade-off between memory usage and performance.
// Fewer partitions will result in more contention on the lock, but more partitions will consume more memory.
#define EBPF_LRU_MAXIMUM_PARTITIONS 8

// Limit maximum map allocation size to 128GB.
#define EBPF_MAP_MAXIMUM_ALLOCATION (((uint64_t)1) << 37)

/**
 * @brief The BPF_MAP_TYPE_LRU_HASH is a hash table that stores a limited number of entries. When the map is full, the
 * least recently used entry is removed to make room for a new entry. The map is implemented as a hash table with a pair
 * of doubly-linked lists per partition. The hot list contains entries that have been accessed in the current
 * generation (where a generation is defined as a period of time during which max_entries /
 * (EBPF_LRU_GENERATION_COUNT*partition_count) elements have been accessed in the map), and the cold list contains
 * entries that have not been accessed in the current generation. When entries in the cold list are accessed, they are
 * moved to the hot list. When the hot list reaches max_entries/EBPF_LRU_GENERATION_COUNT, the hot list is merged into
 * the cold list, a new generation is started, and the hot list is cleared. When space is needed an entry is selected
 * from a cold list and is removed from the hash table.
 *
 * key history is stored along with the value in the map. The hash table then provides callbacks to the map to update
 * the key history when an entry is accessed, updated, or deleted.
 *
 * key history can be in multiple partitions, with different generation and last-used-time values. To determine
 * the actual last used time of a key, the map must iterate over all the partitions and find the maximum last-used-time.
 *
 * The link in the ebpf_lru_entry_t with the highest corresponding last-used-time is the actual last used time of the
 * key. All other links in that ebpf_lru_entry_t are considered stale and are ignored.
 *
 * Key history is stored in a separate partition from the value and is returned as an opaque blob of memory.
 *
 * ebpf_lru_entry_partition_t is an untyped block of memory containing the following:
 * struct ebpf_lru_entry_t {
 *  ebpf_list_entry_t list_entry[partition_count];
 *  size_t generation[partition_count];
 *  size_t last_used_time[partition_count];
 *  uint8_t key[key_size];
 * };
 *
 * This structure is not expressible in C, so we use macros to calculate the offsets of the fields in the structure and
 * access them.
 */

/**
 * @brief Opaque type for an LRU map key history entry.
 * Macros are used to access the fields in the key history entry.
 */
typedef uint8_t* ebpf_lru_entry_t;

/**
 * @brief Macro to calculate the offset of list entry in the key history entry.
 */
#define EBPF_LRU_ENTRY_LIST_ENTRY_OFFSET(partition_count) 0

/**
 * @brief Macro to calculate the offset of generation in the key history entry.
 */
#define EBPF_LRU_ENTRY_GENERATION_OFFSET(partition_count) \
    (EBPF_LRU_ENTRY_LIST_ENTRY_OFFSET(partition_count) + (partition_count) * sizeof(ebpf_list_entry_t))

/**
 * @brief Macro to calculate the offset of last used time in the key history entry.
 */
#define EBPF_LRU_ENTRY_LAST_USED_TIME_OFFSET(partition_count) \
    (EBPF_LRU_ENTRY_GENERATION_OFFSET(partition_count) + (partition_count) * sizeof(size_t))

/**
 * @brief Macro to calculate the offset of key in the key history entry.
 */
#define EBPF_LRU_ENTRY_KEY_OFFSET(partition_count) \
    (EBPF_LRU_ENTRY_LAST_USED_TIME_OFFSET(partition_count) + (partition_count) * sizeof(size_t))

/**
 * @brief Macro to compute the size of the key history entry.
 */
#define EBPF_LRU_ENTRY_SIZE(partition_count, key_size) (EBPF_LRU_ENTRY_KEY_OFFSET(partition_count) + key_size)

/**
 * @brief Macro to get a pointer to an array of list entries in the key history entry.
 */
#define EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry) \
    ((ebpf_list_entry_t*)(((uint8_t*)entry) + EBPF_LRU_ENTRY_LIST_ENTRY_OFFSET(map->partition_count)))

/**
 * @brief Macro to get a pointer to an array of generations in the key history entry.
 */
#define EBPF_LRU_ENTRY_GENERATION_PTR(map, entry) \
    ((size_t*)(((uint8_t*)entry) + EBPF_LRU_ENTRY_GENERATION_OFFSET(map->partition_count)))

/**
 * @brief Macro to get a pointer to an array of last used times in the key history entry.
 */
#define EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(map, entry) \
    ((size_t*)(((uint8_t*)entry) + EBPF_LRU_ENTRY_LAST_USED_TIME_OFFSET(map->partition_count)))

/**
 * @brief Macro to get a pointer to the key in the key history entry.
 */
#define EBPF_LRU_ENTRY_KEY_PTR(map, entry) \
    ((uint8_t*)(((uint8_t*)entry) + EBPF_LRU_ENTRY_KEY_OFFSET(map->partition_count)))

#define EBPF_LOG_MAP_OPERATION(flags, operation, map, key)                                            \
    if (((flags) & EBPF_MAP_FLAG_HELPER) && (map)->ebpf_map_definition.key_size != 0) {               \
        EBPF_LOG_MESSAGE_UTF8_STRING(                                                                 \
            EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_MAP, "Map "##operation, &(map)->name); \
        EBPF_LOG_MESSAGE_BINARY(                                                                      \
            EBPF_TRACELOG_LEVEL_VERBOSE,                                                              \
            EBPF_TRACELOG_KEYWORD_MAP,                                                                \
            "Key",                                                                                    \
            (key),                                                                                    \
            (map)->ebpf_map_definition.key_size);                                                     \
    }

/**
 * @brief The partition of the LRU map key history.
 */
__declspec(align(EBPF_CACHE_LINE_SIZE)) typedef struct _ebpf_lru_partition
{
    ebpf_list_entry_t hot_list; //< List of ebpf_lru_entry_t containing keys accessed in the current generation.
    ebpf_list_entry_t
        cold_list; //< List of ebpf_lru_entry_t containing keys accessed in previous generations, sorted by generation.
    ebpf_lock_t lock;          //< Lock to protect access to the hot, cold lists, current generation, and hot list size.
    size_t current_generation; //< Current generation. Updated when the hot list is merged into the cold list.
    size_t hot_list_size;      //< Current size of the hot list.
    size_t hot_list_limit;     //< Maximum size of the hot list.
} ebpf_lru_partition_t;

static_assert(sizeof(ebpf_lru_partition_t) % EBPF_CACHE_LINE_SIZE == 0, "ebpf_core_lru_map_t is not cache aligned.");

/**
 * @brief The map definition for an LRU map.
 */
typedef struct _ebpf_core_lru_map
{
    ebpf_core_map_t core_map; //< Core map structure.
    size_t partition_count;   //< Number of LRU partitions. Limited to a maximum of EBPF_LRU_MAXIMUM_PARTITIONS.
    uint8_t padding[24];      //< Required to ensure partitions are cache aligned.
    ebpf_lru_partition_t
        partitions[1]; //< Array of LRU partitions. Limited to a maximum of EBPF_LRU_MAXIMUM_PARTITIONS.
} ebpf_core_lru_map_t;

/**
 * @brief Operation being performed on the LRU maps key history.
 *
 */
typedef enum _ebpf_lru_key_operation
{
    EBPF_LRU_KEY_OPERATION_INSERT, //< Insert an uninitialized key into the LRU map key history and initialize it.
    EBPF_LRU_KEY_OPERATION_UPDATE, //< Update an existing key in the LRU map key history.
    EBPF_LRU_KEY_OPERATION_DELETE  //< Delete an existing key from the LRU map key history.
} ebpf_lru_key_operation_t;

/**
 * @brief LRU keys follow a lifecycle of being uninitialized, hot, cold, and deleted. The state of the key is used to
 * determine how to update the LRU map key history. Given that the keys are not directly controlled, the state of the
 * key can transition to the deleted state at any point. Excluding transitions to the deleted state, the state
 * transitions are as follows: Uninitialized -> Hot -> Cold -> Hot -> Cold -> ... -> Deleted.
 */
typedef enum _ebpf_lru_key_state
{
    EBPF_LRU_KEY_UNINITIALIZED, //< Key is uninitialized. It has been inserted into the LRU map, but the key history has
                                //< not been updated yet.
    EBPF_LRU_KEY_COLD,          //< Key is cold. It has not been accessed in the current generation.
    EBPF_LRU_KEY_HOT,           //< Key is hot. It has been accessed in the current generation.
    EBPF_LRU_KEY_DELETED //< The key and value have been deleted from the LRU map. The backing store for this memory
                         // will be freed when the current epoch is retired.
} ebpf_lru_key_state_t;

typedef struct _ebpf_core_lpm_map
{
    ebpf_core_map_t core_map;
    uint32_t max_prefix;
    // Bitmap of prefix lengths inserted into the map.
    uint64_t data[1];
} ebpf_core_lpm_map_t;

typedef struct _ebpf_core_lpm_key
{
    // Length of the prefix in bits.
    uint32_t prefix_length;
    // The prefix starts from prefix[0] and is prefix_length bits long.
    uint8_t prefix[1];
} ebpf_core_lpm_key_t;

typedef struct _ebpf_core_map_async_contexts
{
    ebpf_lock_t lock;
    // Flag that is set the first time an async operation is queued to the map.
    // This flag only transitions from off -> on. When this flag is set,
    // updates to the map acquire the lock and check the async_contexts list.
    // Note that queueing an async operation thus causes a perf degradation
    // for all subsequent updates, so should only be allowed by admin.
    bool trip_wire;
    ebpf_list_entry_t contexts;
} ebpf_core_map_async_contexts_t;

typedef struct _ebpf_core_ring_buffer_map
{
    ebpf_core_map_t core_map;
    ebpf_core_map_async_contexts_t async;
} ebpf_core_ring_buffer_map_t;

#pragma warning(disable : 4324) // Structure was padded due to alignment specifier.

__declspec(align(EBPF_CACHE_LINE_SIZE)) typedef struct _ebpf_core_perf_ring
{
    ebpf_ring_buffer_t ring;
    volatile size_t lost_records;
    ebpf_core_map_async_contexts_t async;
} ebpf_core_perf_ring_t;

__declspec(align(EBPF_CACHE_LINE_SIZE)) typedef struct _ebpf_core_perf_event_array_map
{
    ebpf_core_map_t core_map;
    uint32_t ring_count;
    ebpf_core_perf_ring_t rings[1];
} ebpf_core_perf_event_array_map_t;

#pragma warning(pop)

// Validate cache-alignment of the per-cpu perf event array rings so there isn't any false sharing.
static_assert(sizeof(ebpf_core_perf_ring_t) % EBPF_CACHE_LINE_SIZE == 0, "ebpf_core_perf_ring_t is not cache aligned.");
static_assert(
    sizeof(ebpf_core_perf_event_array_map_t) % EBPF_CACHE_LINE_SIZE == 0,
    "ebpf_core_perf_event_array_map_t is not cache aligned.");

typedef struct _ebpf_core_map_async_query_context
{
    ebpf_list_entry_t entry;
    ebpf_core_map_t* map;
    uint64_t index;
    ebpf_map_async_query_result_t* async_query_result;
    void* async_context;
} ebpf_core_map_async_query_context_t;

/**
 * Core map structure for BPF_MAP_TYPE_QUEUE and BPF_MAP_TYPE_STACK
 * ebpf_core_circular_map_t stores an array of uint8_t* pointers. Each pointer
 * stores a version of a value that has been pushed to the queue or stack. The
 * structure can't store the map values directly as the caller expects items
 * returned from peek to remain unmodified. If items are stored directly in
 * the array, then a sequence of:
 * 1) push
 * 2) peek
 * 3) pop
 * 4) push
 * can result in aliasing the record, which would result in unexpected behavior.
 */

typedef struct _ebpf_core_circular_map
{
    ebpf_core_map_t core_map;
    ebpf_lock_t lock;
    size_t begin;
    size_t end;
    enum
    {
        EBPF_CORE_QUEUE = 1,
        EBPF_CORE_STACK = 2,
    } type;
    uint8_t* slots[1];
} ebpf_core_circular_map_t;

static size_t
_ebpf_core_circular_map_add(_In_ const ebpf_core_circular_map_t* map, size_t value, int delta)
{
    return (map->core_map.ebpf_map_definition.max_entries + value + (size_t)delta) %
           map->core_map.ebpf_map_definition.max_entries;
}

static uint8_t*
_ebpf_core_circular_map_peek_or_pop(_Inout_ ebpf_core_circular_map_t* map, bool pop)
{
    uint8_t* return_value = NULL;

    if (map->type == EBPF_CORE_QUEUE) {
        // Remove from the beginning.
        return_value = map->slots[map->begin];
        if (return_value == NULL) {
            ebpf_assert(map->begin == map->end);
            goto Done;
        }
        if (pop) {
            map->slots[map->begin] = NULL;
            map->begin = _ebpf_core_circular_map_add(map, map->begin, 1);
        }
    } else {
        // Remove from the end.
        size_t new_end = _ebpf_core_circular_map_add(map, map->end, -1);
        return_value = map->slots[new_end];
        if (return_value == NULL) {
            ebpf_assert(map->begin == map->end);
            goto Done;
        }
        if (pop) {
            map->slots[new_end] = NULL;
            map->end = new_end;
        }
    }
    if (pop) {
        // The return_value is not freed until the current epoch is retired.
        ebpf_epoch_free(return_value);
    }
Done:
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory 'return_value'.
    return return_value;
#pragma warning(pop)
}

static ebpf_result_t
_ebpf_core_circular_map_push(_Inout_ ebpf_core_circular_map_t* map, _In_ const uint8_t* data, bool replace)
{
    ebpf_result_t return_value;
    uint8_t* new_data = NULL;
    uint8_t* old_data = NULL;
    new_data = ebpf_epoch_allocate_with_tag(map->core_map.ebpf_map_definition.value_size, EBPF_POOL_TAG_MAP);
    if (new_data == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }
    memcpy(new_data, data, map->core_map.ebpf_map_definition.value_size);

    if (map->slots[map->end] != NULL) {
        ebpf_assert(map->begin == map->end);
        if (replace) {
            old_data = map->slots[map->end];
            map->slots[map->end] = NULL;
            map->begin = _ebpf_core_circular_map_add(map, map->begin, 1);
        } else {
            return_value = EBPF_OUT_OF_SPACE;
            goto Done;
        }
    }

    // Insert at the end.
    map->slots[map->end] = new_data;
    new_data = NULL;
    map->end = _ebpf_core_circular_map_add(map, map->end, 1);

    return_value = EBPF_SUCCESS;

Done:
    if (new_data) {
        ebpf_epoch_free(new_data);
    }
    if (old_data) {
        ebpf_epoch_free(old_data);
    }
    return return_value;
}

static ebpf_program_type_t
_get_map_program_type(_In_ const ebpf_core_object_t* object)
{
    const ebpf_core_object_map_t* map = (const ebpf_core_object_map_t*)object;
    return map->program_type;
}

typedef struct _ebpf_map_metadata_table
{
    ebpf_map_type_t map_type;
    ebpf_result_t (*create_map)(
        _In_ const ebpf_map_definition_in_memory_t* map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_core_map_t** map);
    void (*delete_map)(_In_ _Post_invalid_ ebpf_core_map_t* map);
    ebpf_result_t (*associate_program)(_Inout_ ebpf_map_t* map, _In_ const ebpf_program_t* program);
    ebpf_result_t (*find_entry)(
        _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data);
    ebpf_core_object_t* (*get_object_from_entry)(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*update_entry)(
        _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_with_handle)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_per_cpu)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*delete_entry)(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key_and_value)(
        _Inout_ ebpf_core_map_t* map,
        _In_ const uint8_t* previous_key,
        _Out_ uint8_t* next_key,
        _Inout_opt_ uint8_t** next_value);
    ebpf_result_t (*query_buffer)(
        _In_ const ebpf_core_map_t* map, uint64_t index, _Outptr_ uint8_t** data, _Out_ uint64_t* consumer_offset);
    ebpf_result_t (*return_buffer)(_In_ const ebpf_core_map_t* map, uint64_t index, uint64_t consumer_offset);
    ebpf_result_t (*write_data)(_Inout_ ebpf_core_map_t* map, uint64_t flags, _In_ uint8_t* data, size_t data_size);
    ebpf_result_t (*async_query)(
        _In_ const ebpf_core_map_t* map,
        uint64_t index,
        _Inout_ ebpf_map_async_query_result_t* async_query_result,
        _Inout_ void* async_context);
    void (*query_ring_buffer)(
        _In_ const ebpf_core_map_t* map, uint64_t index, _Inout_ ebpf_map_async_query_result_t* async_query_result);
    ebpf_result_t (*map_ring_buffer)(
        _In_ const ebpf_core_map_t* map,
        _Outptr_ void** consumer,
        _Outptr_ void** producer,
        _Outptr_result_buffer_(*data_size) uint8_t** data,
        _Out_ size_t* data_size);
    ebpf_result_t (*unmap_ring_buffer)(
        _In_ const ebpf_core_map_t* map, _In_ const void* consumer, _In_ const void* producer, _In_ const void* data);
    ebpf_result_t (*set_wait_handle)(
        _In_ const ebpf_core_map_t* map, uint64_t index, _In_ ebpf_handle_t handle, uint64_t flags);
    int zero_length_key : 1;
    int zero_length_value : 1;
    int per_cpu : 1;
    int key_history : 1;
} ebpf_map_metadata_table_t;

const ebpf_map_metadata_table_t ebpf_map_metadata_tables[];

// ebpf_map_get_table(type) - get the metadata table for the given map type.
//
// type is checked on map creation and not user writeable, so in release mode we don't need to check it.
// In debug mode, we assert that the type is within the table bounds.
static inline _Ret_notnull_ const ebpf_map_metadata_table_t*
ebpf_map_get_table(_In_range_(0, EBPF_COUNT_OF(ebpf_map_metadata_tables) - 1) const ebpf_map_type_t type);

const ebpf_map_definition_in_memory_t*
ebpf_map_get_definition(_In_ const ebpf_map_t* map)
{
    return &map->ebpf_map_definition;
}

uint32_t
ebpf_map_get_effective_value_size(_In_ const ebpf_map_t* map)
{
    return map->original_value_size;
}

static ebpf_result_t
_create_array_map_with_map_struct_size(
    size_t map_struct_size, _In_ const ebpf_map_definition_in_memory_t* map_definition, _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t retval;
    size_t map_data_size = 0;
    ebpf_core_map_t* local_map = NULL;

    *map = NULL;

    retval = ebpf_safe_size_t_multiply(map_definition->max_entries, map_definition->value_size, &map_data_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    size_t full_map_size;
    retval = ebpf_safe_size_t_add(EBPF_PAD_CACHE(map_struct_size), map_data_size, &full_map_size);
    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    // Prevent allocation larger than 128GB (default maximum non-paged pool size).
    if (full_map_size > EBPF_MAP_MAXIMUM_ALLOCATION) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    local_map = ebpf_epoch_allocate_with_tag(full_map_size, EBPF_POOL_TAG_MAP);
    if (local_map == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }
    memset(local_map, 0, full_map_size);

    local_map->ebpf_map_definition = *map_definition;
    local_map->data = ((uint8_t*)local_map) + EBPF_PAD_CACHE(map_struct_size);

    *map = local_map;

Done:
    return retval;
}

static ebpf_result_t
_create_array_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    if (inner_map_handle != ebpf_handle_invalid) {
        return EBPF_INVALID_ARGUMENT;
    }
    return _create_array_map_with_map_struct_size(sizeof(ebpf_core_map_t), map_definition, map);
}

static void
_delete_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    ebpf_epoch_free(map);
}

static ebpf_result_t
_find_array_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data)
{
    uint32_t key_value;
    if (!map || !key || delete_on_success) {
        return EBPF_INVALID_ARGUMENT;
    }

    key_value = *(uint32_t*)key;

    if (key_value >= map->ebpf_map_definition.max_entries) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    *data = &map->data[key_value * map->ebpf_map_definition.value_size];

    return EBPF_SUCCESS;
}

static ebpf_result_t
_find_array_map_entry_with_reference(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data)
{
    ebpf_assert(map->ebpf_map_definition.value_size == sizeof(ebpf_id_t));

    ebpf_result_t result = _find_array_map_entry(map, key, delete_on_success, data);

    if (result != EBPF_SUCCESS) {
        return result;
    }

    ebpf_id_t* id = (ebpf_id_t*)(*data);
    if (id != NULL && *id == 0) {
        // Turn zero ID into EBPF_OBJECT_NOT_FOUND.
        *data = NULL;
        return EBPF_OBJECT_NOT_FOUND;
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_update_array_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option)
{
    uint32_t key_value;

    if (!map || !key || (option == EBPF_NOEXIST)) {
        return EBPF_INVALID_ARGUMENT;
    }

    key_value = *(uint32_t*)key;

    if (key_value >= map->ebpf_map_definition.max_entries) {
        return EBPF_INVALID_ARGUMENT;
    }

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];
    if (data) {
        memcpy(entry, data, map->ebpf_map_definition.value_size);
    } else {
        memset(entry, 0, map->ebpf_map_definition.value_size);
    }
    return EBPF_SUCCESS;
}

static ebpf_result_t
_delete_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    uint32_t key_value;
    if (!map || !key) {
        return EBPF_INVALID_ARGUMENT;
    }

    key_value = *(uint32_t*)key;

    if (key_value >= map->ebpf_map_definition.max_entries) {
        return EBPF_INVALID_ARGUMENT;
    }

    uint8_t* entry = &map->data[key_value * map->ebpf_map_definition.value_size];

    memset(entry, 0, map->ebpf_map_definition.value_size);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_next_array_map_key_and_value(
    _In_ const ebpf_core_map_t* map,
    _In_ const uint8_t* previous_key,
    _Out_ uint8_t* next_key,
    _Inout_opt_ uint8_t** value)
{
    uint32_t key_value;
    if (!map || !next_key) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (previous_key) {
        key_value = *(uint32_t*)previous_key;
        key_value++;
    } else {
        key_value = 0;
    }

    if (key_value >= map->ebpf_map_definition.max_entries) {
        return EBPF_NO_MORE_KEYS;
    }

    *(uint32_t*)next_key = key_value;

    // Copy the value of requested.
    if (value) {
        *value = &map->data[key_value * map->ebpf_map_definition.value_size];
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
_associate_inner_map(_Inout_ ebpf_core_object_map_t* object_map, ebpf_handle_t inner_map_handle)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_definition_in_memory_t local_map_definition = object_map->core_map.ebpf_map_definition;
    ebpf_core_object_t* inner_map_template_object = NULL;

    if (local_map_definition.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
        local_map_definition.type != BPF_MAP_TYPE_HASH_OF_MAPS) {
        goto Exit;
    }

    if (inner_map_handle == ebpf_handle_invalid) {

        // Must have a valid inner_map_handle.
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Map in map must have a valid inner_map_handle");
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Convert value handle to an object pointer.
    result = EBPF_OBJECT_REFERENCE_BY_HANDLE(inner_map_handle, EBPF_OBJECT_MAP, &inner_map_template_object);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Get object ref by handle failed.", result);
        goto Exit;
    }

    ebpf_core_map_t* template_core_map = (ebpf_core_map_t*)inner_map_template_object;
    template_core_map = EBPF_FROM_FIELD(ebpf_core_map_t, object, inner_map_template_object);

    object_map->inner_template_map_definition = template_core_map->ebpf_map_definition;
    object_map->core_map.ebpf_map_definition.inner_map_id = template_core_map->object.id;

Exit:
    if (inner_map_template_object) {
        EBPF_OBJECT_RELEASE_REFERENCE(inner_map_template_object);
    }

    return result;
}

static void
_delete_object_array_map(_Inout_ _Post_invalid_ ebpf_core_map_t* map, ebpf_object_type_t value_type)
{
    // Release all entry references.
    for (uint32_t i = 0; i < map->ebpf_map_definition.max_entries; i++) {
        ebpf_id_t id = *(ebpf_id_t*)&map->data[i * map->ebpf_map_definition.value_size];
        if (id) {
            EBPF_OBJECT_RELEASE_ID_REFERENCE(id, value_type);
        }
    }

    _delete_array_map(map);
}

static ebpf_result_t
_create_object_array_map(
    _Inout_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_core_map_t* local_map = NULL;
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_LOG_ENTRY();

    *map = NULL;

    if (map_definition->value_size != sizeof(ebpf_id_t)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    result = _create_array_map_with_map_struct_size(sizeof(ebpf_core_object_map_t), map_definition, &local_map);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, local_map);
    result = _associate_inner_map(object_map, inner_map_handle);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    *map = local_map;
    local_map = NULL;

Exit:
    if (local_map != NULL) {
        ebpf_object_type_t value_type =
            (map_definition->type == BPF_MAP_TYPE_PROG_ARRAY) ? EBPF_OBJECT_PROGRAM : EBPF_OBJECT_MAP;
        _delete_object_array_map(local_map, value_type);
        local_map = NULL;
    }
    EBPF_RETURN_RESULT(result);
}

static void
_delete_program_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    _delete_object_array_map(map, EBPF_OBJECT_PROGRAM);
}

static void
_delete_map_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    _delete_object_array_map(map, EBPF_OBJECT_MAP);
}

static ebpf_result_t
_associate_program_with_prog_array_map(_Inout_ ebpf_core_map_t* map, _In_ const ebpf_program_t* program)
{
    ebpf_assert(map->ebpf_map_definition.type == BPF_MAP_TYPE_PROG_ARRAY);
    ebpf_core_object_map_t* program_array = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, map);

    // Validate that the program type is not in conflict with the map's program type.
    ebpf_program_type_t program_type = ebpf_program_type_uuid(program);
    ebpf_result_t result = EBPF_SUCCESS;

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&program_array->lock);

    if (!program_array->is_program_type_set) {
        program_array->is_program_type_set = TRUE;
        program_array->program_type = program_type;
    } else if (memcmp(&program_array->program_type, &program_type, sizeof(program_type)) != 0) {
        result = EBPF_INVALID_FD;
    }

    ebpf_lock_unlock(&program_array->lock, lock_state);

    return result;
}

static bool // Returns true if ok, false if not.
_check_value_type(_In_ const ebpf_core_map_t* outer_map, _In_ const ebpf_core_object_t* value_object)
{
    if (outer_map->ebpf_map_definition.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
        outer_map->ebpf_map_definition.type != BPF_MAP_TYPE_HASH_OF_MAPS) {
        return true;
    }

    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, outer_map);
    const ebpf_map_t* value_map = (ebpf_map_t*)value_object;

    bool allowed =
        (value_map->ebpf_map_definition.type == object_map->inner_template_map_definition.type) &&
        (value_map->ebpf_map_definition.key_size == object_map->inner_template_map_definition.key_size) &&
        (value_map->ebpf_map_definition.value_size == object_map->inner_template_map_definition.value_size) &&
        (value_map->ebpf_map_definition.max_entries == object_map->inner_template_map_definition.max_entries);

    return allowed;
}

// Validate that a value object is appropriate for this map.
// Also set the program type if not yet set.
static _Requires_lock_held_(object_map->lock) ebpf_result_t _validate_map_value_object(
    _Inout_ ebpf_core_object_map_t* object_map,
    ebpf_object_type_t value_type,
    _In_ const ebpf_core_object_t* value_object)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_core_map_t* map = &object_map->core_map;

    ebpf_program_type_t value_program_type = {0};
    bool is_program_type_set = false;

    if (value_object->get_program_type) {
        value_program_type = value_object->get_program_type(value_object);
        is_program_type_set = true;
    }

    if (value_type == EBPF_OBJECT_MAP) {
        // Validate that the value is of the correct type.
        if (!_check_value_type(map, value_object)) {
            result = EBPF_INVALID_OBJECT;
            goto Error;
        }
    }

    // Validate that the value's program type (if any) is
    // not in conflict with the map's program type.
    if (is_program_type_set) {
        if (!object_map->is_program_type_set) {
            object_map->is_program_type_set = TRUE;
            object_map->program_type = value_program_type;
        } else if (memcmp(&object_map->program_type, &value_program_type, sizeof(value_program_type)) != 0) {
            result = EBPF_INVALID_FD;
            goto Error;
        }
    }

    return EBPF_SUCCESS;

Error:
    return result;
}

static ebpf_result_t
_update_array_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    ebpf_object_type_t value_type,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // The 'map' and 'key' arguments cannot be NULL due to caller's prior validations.
    ebpf_assert(map != NULL && key != NULL);

    if (option == EBPF_NOEXIST) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Invalid map option rejected", option);
        return EBPF_INVALID_ARGUMENT;
    }

    uint32_t index = *(uint32_t*)key;
    if (index >= map->ebpf_map_definition.max_entries) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Index larger than max entries rejected", index);
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_core_object_t* value_object = NULL;
    if (value_handle != (uintptr_t)ebpf_handle_invalid) {
        result = EBPF_OBJECT_REFERENCE_BY_HANDLE(value_handle, value_type, &value_object);
        if (result != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Invalid object handle rejected",
                value_handle,
                result);
            return result;
        }
    }

    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, map);
    bool locked = FALSE;

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&object_map->lock);
    locked = TRUE;

    if (value_handle != (uintptr_t)ebpf_handle_invalid) {
        result = _validate_map_value_object(object_map, value_type, value_object);
        if (result != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Object validation failed",
                value_object->id,
                result);
            goto Done;
        }
    }

    uint8_t* entry = &map->data[*(uint32_t*)key * map->ebpf_map_definition.value_size];
    ebpf_id_t old_id = *(ebpf_id_t*)entry;
    if (old_id) {
        EBPF_OBJECT_RELEASE_ID_REFERENCE(old_id, value_type);
    }

    if (value_object) {

        // Acquire a reference to the id table entry for the new incoming id. This operation _cannot_ fail as we
        // already have a valid pointer to the object.  A failure here is indicative of a fatal internal error.
        ebpf_assert_success(EBPF_OBJECT_ACQUIRE_ID_REFERENCE(value_object->id, value_type));
    }

    // Note that this could be an 'update to erase' operation where we don't have a valid (incoming) object.  In this
    // case, the 'id' value in the map entry is 'updated' to zero.
    ebpf_id_t id = value_object ? value_object->id : 0;
    memcpy(entry, &id, map->ebpf_map_definition.value_size);
    result = EBPF_SUCCESS;

Done:

    if (value_object != NULL) {

        // We have stored the id of the object, so let go of our reference on the object itself.  Going forward, we'll
        // use the id to get to the object, as and when required.  Note that this is with the explicit understanding
        // that the object may well have been since destroyed by the time we actually need to use this id. This is
        // perfectly valid and something we need to be prepared for.
        EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)value_object);
    }

    if (locked) {
        ebpf_lock_unlock(&object_map->lock, lock_state);
    }

    return result;
}

static ebpf_result_t
_update_prog_array_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option)
{
    return _update_array_map_entry_with_handle(map, key, EBPF_OBJECT_PROGRAM, value_handle, option);
}

static ebpf_result_t
_update_map_array_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option)
{
    return _update_array_map_entry_with_handle(map, key, EBPF_OBJECT_MAP, value_handle, option);
}

static ebpf_result_t
_delete_array_map_entry_with_reference(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, ebpf_object_type_t value_type)
{
    ebpf_assert(value_type == EBPF_OBJECT_PROGRAM || value_type == EBPF_OBJECT_MAP);

    ebpf_result_t result;
    uint8_t* entry;
    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, map);
    ebpf_lock_state_t lock_state = ebpf_lock_lock(&object_map->lock);
    result = _find_array_map_entry(map, key, false, &entry);
    if (result == EBPF_SUCCESS) {
        ebpf_id_t id = *(ebpf_id_t*)entry;
        if (id) {
            EBPF_OBJECT_RELEASE_ID_REFERENCE(id, value_type);
        }
        _delete_array_map_entry(map, key);
    }
    ebpf_lock_unlock(&object_map->lock, lock_state);

    return result;
}

static ebpf_result_t
_delete_program_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_array_map_entry_with_reference(map, key, EBPF_OBJECT_PROGRAM);
}

static ebpf_result_t
_delete_map_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    return _delete_array_map_entry_with_reference(map, key, EBPF_OBJECT_MAP);
}

/**
 * @brief Get an object from a map entry that holds objects, such
 * as a program array or array of maps.  The object returned holds a
 * reference that the caller is responsible for releasing.
 *
 * @param[in] map Array map to search.
 * @param[in] key Pointer to the key to search for.
 * @returns Object pointer, or NULL if none.
 */
static _Ret_maybenull_ ebpf_core_object_t*
_get_object_from_array_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    uint32_t index = *(uint32_t*)key;

    ebpf_core_object_t* object = NULL;
    uint8_t* value = NULL;
    if (_find_array_map_entry(map, (uint8_t*)&index, false, &value) == EBPF_SUCCESS) {
        ebpf_id_t id = *(ebpf_id_t*)&map->data[index * map->ebpf_map_definition.value_size];
        ebpf_object_type_t value_type =
            (map->ebpf_map_definition.type == BPF_MAP_TYPE_PROG_ARRAY) ? EBPF_OBJECT_PROGRAM : EBPF_OBJECT_MAP;
        if (id != 0) {
            // Find the object by id.
            // Ignore the returned status as the object may have been deleted.
            (void)ebpf_object_pointer_by_id(id, value_type, &object);
        }
    }

    return object;
}

static ebpf_result_t
_create_hash_map_internal(
    size_t map_struct_size,
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    size_t supplemental_value_size,
    bool fixed_size_map,
    _In_opt_ void (*extract_function)(
        _In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* length_in_bits),
    _In_opt_ ebpf_hash_table_notification_function notification_callback,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t retval;
    ebpf_core_map_t* local_map = NULL;
    *map = NULL;

    local_map = ebpf_epoch_allocate_cache_aligned_with_tag(map_struct_size, EBPF_POOL_TAG_MAP);
    if (local_map == NULL) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    local_map->ebpf_map_definition = *map_definition;
    local_map->data = NULL;

    const ebpf_hash_table_creation_options_t options = {
        .key_size = local_map->ebpf_map_definition.key_size,
        .value_size = local_map->ebpf_map_definition.value_size,
        .minimum_bucket_count = local_map->ebpf_map_definition.max_entries,
        .max_entries = fixed_size_map ? local_map->ebpf_map_definition.max_entries : EBPF_HASH_TABLE_NO_LIMIT,
        .extract_function = extract_function,
        .supplemental_value_size = supplemental_value_size,
        .notification_context = local_map,
        .notification_callback = notification_callback,
    };

    // Note:
    // ebpf_hash_table_t doesn't require synchronization as long as allocations
    // are performed using the epoch allocator.
    retval = ebpf_hash_table_create((ebpf_hash_table_t**)&local_map->data, &options);

    if (retval != EBPF_SUCCESS) {
        goto Done;
    }

    *map = local_map;
    local_map = NULL;
    retval = EBPF_SUCCESS;

Done:
    if (retval != EBPF_SUCCESS) {
        if (local_map && local_map->data) {
            ebpf_hash_table_destroy((ebpf_hash_table_t*)local_map->data);
        }
        ebpf_epoch_free_cache_aligned(local_map);
        local_map = NULL;
    }
    return retval;
}

static ebpf_result_t
_create_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    if (inner_map_handle != ebpf_handle_invalid) {
        return EBPF_INVALID_ARGUMENT;
    }
    return _create_hash_map_internal(sizeof(ebpf_core_map_t), map_definition, 0, false, NULL, NULL, map);
}

static void
_delete_hash_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    ebpf_hash_table_destroy((ebpf_hash_table_t*)map->data);
    ebpf_epoch_free_cache_aligned(map);
}

static void
_delete_object_hash_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    // Release all entry references.
    uint8_t* next_key;
    for (uint8_t* previous_key = NULL;; previous_key = next_key) {
        uint8_t* value;
        ebpf_result_t result =
            ebpf_hash_table_next_key_pointer_and_value((ebpf_hash_table_t*)map->data, previous_key, &next_key, &value);
        if (result != EBPF_SUCCESS) {
            break;
        }
        ebpf_id_t id = *(ebpf_id_t*)value;
        if (id) {
            EBPF_OBJECT_RELEASE_ID_REFERENCE(id, EBPF_OBJECT_MAP);
        }
    }

    _delete_hash_map(map);
}

static ebpf_result_t
_create_object_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_core_map_t* local_map = NULL;
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_LOG_ENTRY();

    if (map_definition->value_size != sizeof(ebpf_id_t)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    *map = NULL;

    result =
        _create_hash_map_internal(sizeof(ebpf_core_object_map_t), map_definition, 0, false, NULL, NULL, &local_map);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, local_map);
    result = _associate_inner_map(object_map, inner_map_handle);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *map = local_map;
    local_map = NULL;

Exit:
    if (result != EBPF_SUCCESS && local_map) {
        _delete_object_hash_map(local_map);
        local_map = NULL;
    }

    EBPF_RETURN_RESULT(result);
}

/**
 * @brief Given a pointer to a value, return a pointer to the supplemental value.
 *
 * @param[in] map Pointer to the map, used to determine the size of the value.
 * @param[in] value Pointer to the value.
 * @return Pointer to the supplemental value.
 */
static uint8_t*
_get_supplemental_value(_In_ const ebpf_core_map_t* map, _In_ uint8_t* value)
{
    return value + EBPF_PAD_8(map->ebpf_map_definition.value_size);
}

/**
 * @brief Helper function to translate generation into key state.
 *
 * @param[in] map Pointer to the map. Used to determine the current generation.
 * @param[in] entry LRU entry to get the key state for.
 * @return The key state.
 */
static ebpf_lru_key_state_t
_get_key_state(_In_ const ebpf_core_lru_map_t* map, size_t partition, _In_ const ebpf_lru_entry_t* entry)
{
    size_t generation = EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition];
    if (generation == 0) {
        return EBPF_LRU_KEY_UNINITIALIZED;
    } else if (generation == EBPF_LRU_INVALID_GENERATION) {
        return EBPF_LRU_KEY_DELETED;
    } else if (generation == map->partitions[partition].current_generation) {
        return EBPF_LRU_KEY_HOT;
    } else {
        return EBPF_LRU_KEY_COLD;
    }
}

/**
 * @brief Helper function to merge the hot list into the cold list if the hot list size exceeds the hot list limit.
 * Resets the hot list size and increments the current generation.
 *
 * @param[in,out] map Pointer to the map.
 */
_Requires_lock_held_(map->partitions[partition].lock) static void _merge_hot_into_cold_list_if_needed(
    _Inout_ ebpf_core_lru_map_t* map, size_t partition)
{
    if (map->partitions[partition].hot_list_size <= map->partitions[partition].hot_list_limit) {
        return;
    }

    ebpf_list_entry_t* list_entry = map->partitions[partition].hot_list.Flink;
    ebpf_list_remove_entry(&map->partitions[partition].hot_list);
    ebpf_list_append_tail_list(&map->partitions[partition].cold_list, list_entry);

    ebpf_list_initialize(&map->partitions[partition].hot_list);
    map->partitions[partition].hot_list_size = 0;
    map->partitions[partition].current_generation++;
}

/**
 * @brief Helper function to insert an entry into the hot list if it is in the cold list and update the hot list size.
 *
 * @param[in,out] map Pointer to the map.
 * @param[in] partition Partition to insert into.
 * @param[in,out] entry Entry to insert into the hot list.
 */
static void
_insert_into_hot_list(_Inout_ ebpf_core_lru_map_t* map, size_t partition, _Inout_ ebpf_lru_entry_t* entry)
{
    ebpf_lru_key_state_t key_state = _get_key_state(map, partition, entry);
    ebpf_lock_state_t state = 0;

    switch (key_state) {
    case EBPF_LRU_KEY_UNINITIALIZED:
        break;
    case EBPF_LRU_KEY_COLD:
        break;
    case EBPF_LRU_KEY_HOT:
        return;
    case EBPF_LRU_KEY_DELETED:
        return;
    }

    state = ebpf_lock_lock(&map->partitions[partition].lock);

    key_state = _get_key_state(map, partition, entry);

    switch (key_state) {
    case EBPF_LRU_KEY_UNINITIALIZED:
        EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition] = map->partitions[partition].current_generation;
        EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(map, entry)[partition] = cxplat_query_time_since_boot_approximate(false);
        ebpf_list_insert_tail(
            &map->partitions[partition].hot_list, &EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[partition]);
        map->partitions[partition].hot_list_size++;
        break;
    case EBPF_LRU_KEY_COLD:
        // Remove from cold list.
        EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition] = map->partitions[partition].current_generation;
        EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(map, entry)[partition] = cxplat_query_time_since_boot_approximate(false);
        ebpf_list_remove_entry(&EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[partition]);
        ebpf_list_insert_tail(
            &map->partitions[partition].hot_list, &EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[partition]);
        map->partitions[partition].hot_list_size++;
        break;
    case EBPF_LRU_KEY_HOT:
        break;
    case EBPF_LRU_KEY_DELETED:
        break;
    }

    _merge_hot_into_cold_list_if_needed(map, partition);
    ebpf_lock_unlock(&map->partitions[partition].lock, state);
}

/**
 * @brief Helper function to initialize an LRU entry that was created when an entry was inserted into the hash table.
 * Sets the current generation, populates the key, and inserts the entry into the hot list.
 *
 * @param[in,out] map Pointer to the map.
 * @param[in,out] entry Entry to initialize.
 * @param[in] key Key to initialize the entry with.
 */
static void
_initialize_lru_entry(
    _Inout_ ebpf_core_lru_map_t* map, _Inout_ ebpf_lru_entry_t* entry, size_t partition, _In_ const uint8_t* key)
{
    memcpy(EBPF_LRU_ENTRY_KEY_PTR(map, entry), key, map->core_map.ebpf_map_definition.key_size);

    for (size_t current_partition = 0; current_partition < map->partition_count; current_partition++) {
        // The ebpf_lru_entry_t should be zero initialized, so this assert should always pass.
        ebpf_assert(_get_key_state(map, current_partition, entry) == EBPF_LRU_KEY_UNINITIALIZED);
        ebpf_list_initialize(&EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[current_partition]);
    }

    // Only insert into the current partition's hot list.
    ebpf_lock_state_t state = ebpf_lock_lock(&map->partitions[partition].lock);
    EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition] = map->partitions[partition].current_generation;
    EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(map, entry)[partition] = cxplat_query_time_since_boot_approximate(false);
    ebpf_list_insert_tail(&map->partitions[partition].hot_list, &EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[partition]);
    map->partitions[partition].hot_list_size++;

    _merge_hot_into_cold_list_if_needed(map, partition);

    ebpf_lock_unlock(&map->partitions[partition].lock, state);
}

/**
 * @brief Helper function called when an entry is deleted from the hash table. Removes the entry from the hot or cold
 * list and sets the generation to EBPF_LRU_INVALID_GENERATION so that subsequent access doesn't reinsert it into the
 * hot list.
 *
 * @param[in,out] map Pointer to the map.
 * @param[in,out] entry Entry being deleted.
 */
static void
_uninitialize_lru_entry(_Inout_ ebpf_core_lru_map_t* map, _Inout_ ebpf_lru_entry_t* entry)
{
    for (size_t partition = 0; partition < map->partition_count; partition++) {
        ebpf_lock_state_t state = ebpf_lock_lock(&map->partitions[partition].lock);
        ebpf_lru_key_state_t key_state = _get_key_state(map, partition, entry);

        switch (key_state) {
        case EBPF_LRU_KEY_UNINITIALIZED:
            EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition] = EBPF_LRU_INVALID_GENERATION;
            break;
        case EBPF_LRU_KEY_COLD:
            ebpf_list_remove_entry(&EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[partition]);
            EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition] = EBPF_LRU_INVALID_GENERATION;
            break;
        case EBPF_LRU_KEY_HOT:
            ebpf_list_remove_entry(&EBPF_LRU_ENTRY_LIST_ENTRY_PTR(map, entry)[partition]);
            EBPF_LRU_ENTRY_GENERATION_PTR(map, entry)[partition] = EBPF_LRU_INVALID_GENERATION;
            map->partitions[partition].hot_list_size--;
            break;
        case EBPF_LRU_KEY_DELETED:
            ebpf_assert(!"Key already deleted");
            break;
        }

        ebpf_lock_unlock(&map->partitions[partition].lock, state);
    }
}

static void
_lru_hash_table_notification(
    _In_ void* context, _In_ ebpf_hash_table_notification_type_t type, _In_ const uint8_t* key, _In_ uint8_t* value)
{
    ebpf_core_lru_map_t* lru_map = (ebpf_core_lru_map_t*)context;
    ebpf_lru_entry_t* entry = (ebpf_lru_entry_t*)_get_supplemental_value(&lru_map->core_map, value);
    // Map the current CPU to a partition.
    uint32_t partition = ebpf_get_current_cpu() % lru_map->partition_count;
    switch (type) {
    case EBPF_HASH_TABLE_NOTIFICATION_TYPE_ALLOCATE:
        _initialize_lru_entry(lru_map, entry, partition, key);
        break;
    case EBPF_HASH_TABLE_NOTIFICATION_TYPE_FREE:
        _uninitialize_lru_entry(lru_map, entry);
        break;
    case EBPF_HASH_TABLE_NOTIFICATION_TYPE_USE:
        _insert_into_hot_list(lru_map, partition, entry);
        break;
    default:
        ebpf_assert(!"Invalid notification type");
    }
}

static ebpf_result_t
_create_lru_hash_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t retval = EBPF_SUCCESS;
    ebpf_core_lru_map_t* lru_map = NULL;
    uint32_t partition_count = min(ebpf_get_cpu_count(), EBPF_LRU_MAXIMUM_PARTITIONS);

    *map = NULL;

    EBPF_LOG_ENTRY();

    if (inner_map_handle != ebpf_handle_invalid) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    size_t lru_entry_size = EBPF_LRU_ENTRY_SIZE(partition_count, map_definition->key_size);

    // Add the key size to the entry size.
    retval = ebpf_safe_size_t_add(lru_entry_size, map_definition->key_size, &lru_entry_size);
    if (retval != EBPF_SUCCESS) {
        goto Exit;
    }

    // Align the supplemental value to 8 byte boundary.
    // Pad value_size to next 8 byte boundary and subtract the value_size to get the padding.
    size_t supplemental_value_size;
    retval = ebpf_safe_size_t_add(
        lru_entry_size, EBPF_PAD_8(map_definition->value_size) - map_definition->value_size, &supplemental_value_size);
    if (retval != EBPF_SUCCESS) {
        goto Exit;
    }

    size_t lru_map_size;
    retval = ebpf_safe_size_t_multiply(sizeof(ebpf_lru_partition_t), partition_count, &lru_map_size);
    if (retval != EBPF_SUCCESS) {
        goto Exit;
    }

    retval = ebpf_safe_size_t_add(lru_map_size, EBPF_OFFSET_OF(ebpf_core_lru_map_t, partitions), &lru_map_size);
    if (retval != EBPF_SUCCESS) {
        goto Exit;
    }

    retval = _create_hash_map_internal(
        lru_map_size,
        map_definition,
        supplemental_value_size,
        true,
        NULL,
        _lru_hash_table_notification,
        (ebpf_core_map_t**)&lru_map);
    if (retval != EBPF_SUCCESS) {
        goto Exit;
    }

    lru_map->partition_count = partition_count;

    for (size_t partition = 0; partition < lru_map->partition_count; partition++) {
        ebpf_list_initialize(&lru_map->partitions[partition].hot_list);
        ebpf_list_initialize(&lru_map->partitions[partition].cold_list);
        ebpf_lock_create(&lru_map->partitions[partition].lock);

        lru_map->partitions[partition].current_generation = EBPF_LRU_INITIAL_GENERATION;
        lru_map->partitions[partition].hot_list_size = 0;
        // Assuming that access is randomly distributed, each partition should have the same number of entries in its
        // cold and hot lists. Assume random distribution and divide the entries evenly among the partitions.
        uint32_t average_entries_per_partition = map_definition->max_entries / partition_count;

        // The hot list limit is the average number of entries per partition divided by the number of generations.
        lru_map->partitions[partition].hot_list_limit =
            max(average_entries_per_partition / EBPF_LRU_GENERATION_COUNT, 1);
    }

    *map = &lru_map->core_map;

Exit:
    if (retval != EBPF_SUCCESS) {
        if (lru_map && lru_map->core_map.data) {
            ebpf_hash_table_destroy((ebpf_hash_table_t*)lru_map->core_map.data);
        }
        ebpf_epoch_free_cache_aligned(lru_map);
        lru_map = NULL;
    }

    EBPF_RETURN_RESULT(retval);
}

static void
_delete_lru_hash_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    ebpf_core_lru_map_t* lru_map = EBPF_FROM_FIELD(ebpf_core_lru_map_t, core_map, map);
    ebpf_hash_table_destroy((ebpf_hash_table_t*)lru_map->core_map.data);
    ebpf_epoch_free_cache_aligned(map);
}

static ebpf_result_t
_delete_hash_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);

/**
 * @brief Walk the cold lists, removing secondary keys and finding the oldest primary key.
 *
 * @param[in] lru_map
 * @return Either the oldest primary key or NULL if no primary keys are present.
 */
static ebpf_lru_entry_t*
_reap_lru_cold_lists(ebpf_core_lru_map_t* lru_map)
{
    ebpf_lru_entry_t* oldest_entry = NULL;
    uint64_t oldest_timestamp = UINT64_MAX;
    bool non_empty_partition_found = true;

    // Scan all partitions until we find a non-empty cold list or we have an oldest entry.
    while (!oldest_entry && non_empty_partition_found) {
        non_empty_partition_found = false;
        // Scan each partition, removing secondary entries with higher timestamps until we find the oldest entry.
        for (size_t partition = 0; partition < lru_map->partition_count; partition++) {
            // If this cold list is empty, skip it.
            if (ebpf_list_is_empty(&lru_map->partitions[partition].cold_list)) {
                continue;
            }

            // Found a non-empty partition.
            non_empty_partition_found = true;

            // Lock the partition.
            ebpf_lock_state_t state = ebpf_lock_lock(&lru_map->partitions[partition].lock);

            // Check again after acquiring the lock.
            // If the cold list is empty, skip it.
            if (ebpf_list_is_empty(&lru_map->partitions[partition].cold_list)) {
                ebpf_lock_unlock(&lru_map->partitions[partition].lock, state);
                continue;
            }

            // Compute the start of the entry from the cold list entry.
            ebpf_list_entry_t* list_entry = lru_map->partitions[partition].cold_list.Flink - partition;
            ebpf_lru_entry_t* entry = (ebpf_lru_entry_t*)list_entry;

            // The effective age of an entry is the maximum of the last used time of all partitions.
            // Compute the highest timestamp for this entry.
            size_t highest_timestamp = 0;
            for (size_t inner_partition = 0; inner_partition < lru_map->partition_count; inner_partition++) {
                if (EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(lru_map, entry)[inner_partition] > highest_timestamp) {
                    highest_timestamp = EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(lru_map, entry)[inner_partition];
                }
            }

            // If this key is present in another partitions's cold list with a higher timestamp and is therefore
            // redundant, remove it. This prevents this code from examining the same key multiple times.
            if (highest_timestamp != EBPF_LRU_ENTRY_LAST_USED_TIME_PTR(lru_map, entry)[partition]) {
                ebpf_lru_key_state_t key_state = _get_key_state(lru_map, partition, entry);
                switch (key_state) {
                case EBPF_LRU_KEY_UNINITIALIZED:
                    break;
                case EBPF_LRU_KEY_COLD:
                    ebpf_list_remove_entry(&EBPF_LRU_ENTRY_LIST_ENTRY_PTR(lru_map, entry)[partition]);
                    EBPF_LRU_ENTRY_GENERATION_PTR(lru_map, entry)[partition] = EBPF_LRU_KEY_UNINITIALIZED;
                    break;
                case EBPF_LRU_KEY_HOT:
                    ebpf_assert(!"Key should not be in the hot list");
                    break;
                case EBPF_LRU_KEY_DELETED:
                    break;
                }
                ebpf_lock_unlock(&lru_map->partitions[partition].lock, state);
                continue;
            }

            // Check if the highest timestamp is the oldest.
            if (highest_timestamp < oldest_timestamp) {
                oldest_timestamp = highest_timestamp;
                oldest_entry = entry;
            }
            ebpf_lock_unlock(&lru_map->partitions[partition].lock, state);
        }
    }
    return oldest_entry;
}

/**
 * @brief Helper function to reap the oldest entry from the map.
 *
 * @param[in,out] map Pointer to the map.
 */
static void
_reap_oldest_map_entry(_Inout_ ebpf_core_map_t* map)
{
    ebpf_core_lru_map_t* lru_map;

    lru_map = EBPF_FROM_FIELD(ebpf_core_lru_map_t, core_map, map);

    ebpf_lru_entry_t* entry = _reap_lru_cold_lists(lru_map);

    if (entry) {
        // Attempt to delete the entry from the cold list.
        // This may fail if the entry has already been freed, but that's okay as the caller will
        // attempt to reap again if the next insert fails.
        (void)_delete_hash_map_entry(map, EBPF_LRU_ENTRY_KEY_PTR(lru_map, entry));
    }
}

static ebpf_result_t
_find_hash_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data)
{
    uint8_t* value = NULL;
    if (!map || !key) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &value) != EBPF_SUCCESS) {
        value = NULL;
    }

    if (delete_on_success) {
        // Delete is atomic.
        // Only return value of both find and delete succeeded.
        if (_delete_hash_map_entry(map, key) != EBPF_SUCCESS) {
            value = NULL;
        }
    }

    *data = value;
    return value == NULL ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
}

/**
 * @brief Get an object from a map entry that holds objects, such
 * as a hash of maps.  The object returned holds a
 * reference that the caller is responsible for releasing.
 *
 * @param[in] map Hash map to search.
 * @param[in] key Pointer to the key to search for.
 * @returns Object pointer, or NULL if none.
 */
static _Ret_maybenull_ ebpf_core_object_t*
_get_object_from_hash_map_entry(_In_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    ebpf_core_object_t* object = NULL;
    uint8_t* value = NULL;
    if (_find_hash_map_entry(map, key, false, &value) == EBPF_SUCCESS) {
        ebpf_id_t id = *(ebpf_id_t*)value;
        if (ebpf_object_pointer_by_id(id, EBPF_OBJECT_MAP, &object) != EBPF_SUCCESS) {
            object = NULL;
        }
    }

    return object;
}

volatile int32_t reap_attempt_counts[64] = {0};

static ebpf_result_t
_update_hash_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option)
{
    ebpf_result_t result;
    ebpf_hash_table_operations_t hash_table_operation;

    if (!map || !key) {
        return EBPF_INVALID_ARGUMENT;
    }

    switch (option) {
    case EBPF_ANY:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_ANY;
        break;
    case EBPF_NOEXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_INSERT;
        break;
    case EBPF_EXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_REPLACE;
        break;
    default:
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    // If the map is full, try to delete the oldest entry and try again.
    // Repeat while the insert fails with EBPF_NO_MEMORY.
    for (;;) {
        result = ebpf_hash_table_update((ebpf_hash_table_t*)map->data, key, data, hash_table_operation);
        if (result != EBPF_OUT_OF_SPACE) {
            break;
        }

        // If this is not an LRU map, break.
        if (!(table->key_history)) {
            break;
        }

        // Reap the oldest entry and try again.
        // Data from measurements shows that reaping one entry or many entries doesn't materially affect performance.
        // To make this simple, reap one entry at a time.
        _reap_oldest_map_entry(map);
    }

    return result;
}

static ebpf_result_t
_update_hash_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map,
    _In_ const uint8_t* key,
    ebpf_object_type_t value_type,
    ebpf_handle_t value_handle,
    ebpf_map_option_t option)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // The 'map' and 'key' arguments cannot be NULL due to caller's prior validations.
    ebpf_assert(map != NULL && key != NULL);

    ebpf_hash_table_operations_t hash_table_operation;
    switch (option) {
    case EBPF_ANY:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_ANY;
        break;
    case EBPF_NOEXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_INSERT;
        break;
    case EBPF_EXIST:
        hash_table_operation = EBPF_HASH_TABLE_OPERATION_REPLACE;
        break;
    default:
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Invalid map option rejected", option);
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, map);
    ebpf_core_object_t* value_object = NULL;
    result = EBPF_OBJECT_REFERENCE_BY_HANDLE(value_handle, value_type, &value_object);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Invalid Object handle rejected",
            value_handle,
            result);
        return result;
    }

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&object_map->lock);

    uint8_t* old_value = NULL;
    ebpf_result_t found_result = ebpf_hash_table_find((ebpf_hash_table_t*)map->data, key, &old_value);
    if ((found_result != EBPF_SUCCESS) && (found_result != EBPF_KEY_NOT_FOUND)) {
        // The hash table is already full.
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Failed to query existing entry");
        result = found_result;
        goto Done;
    }

    result = _validate_map_value_object(object_map, value_type, value_object);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Object validation failed", value_object->id, result);
        goto Done;
    }

    // Store the content of old object ID.
    ebpf_id_t old_id = (old_value) ? *(ebpf_id_t*)old_value : 0;
    // Store the new object ID as the value.
    result =
        ebpf_hash_table_update((ebpf_hash_table_t*)map->data, key, (uint8_t*)&value_object->id, hash_table_operation);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Hash table update failed.", result);
        goto Done;
    }

    // Release the reference on the old ID stored here, if any.
    if (old_id) {
        EBPF_OBJECT_RELEASE_ID_REFERENCE(old_id, value_type);
    }

    // Acquire a reference to the id table entry for the new incoming id. This operation _cannot_ fail as we already
    // have a valid pointer to the object.  A failure here is indicative of a fatal internal error.
    ebpf_assert_success(EBPF_OBJECT_ACQUIRE_ID_REFERENCE(value_object->id, value_type));

Done:
    if (value_object != NULL) {
        EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)value_object);
    }
    ebpf_lock_unlock(&object_map->lock, lock_state);
    return result;
}

static ebpf_result_t
_update_map_hash_map_entry_with_handle(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, uintptr_t value_handle, ebpf_map_option_t option)
{
    return _update_hash_map_entry_with_handle(map, key, EBPF_OBJECT_MAP, value_handle, option);
}

static ebpf_result_t
_delete_map_hash_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    // The 'map' and 'key' arguments cannot be NULL due to caller's prior validations.
    ebpf_assert(map != NULL && key != NULL);

    ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, map);

    ebpf_lock_state_t lock_state = ebpf_lock_lock(&object_map->lock);

    uint8_t* value = NULL;
    ebpf_result_t result = _find_hash_map_entry(map, key, true, &value);
    if (result == EBPF_SUCCESS) {
        ebpf_id_t id = *(ebpf_id_t*)value;
        if (id) {
            EBPF_OBJECT_RELEASE_ID_REFERENCE(id, EBPF_OBJECT_MAP);
        }
    }

    ebpf_lock_unlock(&object_map->lock, lock_state);

    return result;
}

static ebpf_result_t
_delete_hash_map_entry(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key)
{
    if (!map || !key) {
        return EBPF_INVALID_ARGUMENT;
    }

    return ebpf_hash_table_delete((ebpf_hash_table_t*)map->data, key);
}

static ebpf_result_t
_next_hash_map_key_and_value(
    _Inout_ ebpf_core_map_t* map,
    _In_opt_ const uint8_t* previous_key,
    _Inout_ uint8_t* next_key,
    _Inout_opt_ uint8_t** next_value)
{
    ebpf_result_t result;
    if (!map || !next_key) {
        return EBPF_INVALID_ARGUMENT;
    }

    result = ebpf_hash_table_next_key_and_value((ebpf_hash_table_t*)map->data, previous_key, next_key, next_value);
    return result;
}

static __forceinline ebpf_result_t
_ebpf_adjust_value_pointer(_In_ const ebpf_map_t* map, _Inout_ uint8_t** value)
{
    uint32_t current_cpu;

    if (!(ebpf_map_get_table(map->ebpf_map_definition.type)->per_cpu)) {
        return EBPF_SUCCESS;
    }

    current_cpu = ebpf_get_current_cpu();

    (*value) += EBPF_PAD_8((size_t)map->original_value_size) * current_cpu;
    return EBPF_SUCCESS;
}

/**
 * @brief Insert the supplied value into the per-cpu value buffer of the map.
 * If the map doesn't contain an existing value, create a new all-zero value,
 * insert it, then set the per-cpu value. Note: This races with updates to the
 * value buffer from user mode.
 *
 * @param[in] map Map to update.
 * @param[in] key Key to search for.
 * @param[in] value Value to insert.
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 *  entry.
 * @retval EBPF_INVALID_ARGUMENT Unable to perform this operation due to
 * current CPU > allocated value buffer size.
 */
_Must_inspect_result_ ebpf_result_t
_update_entry_per_cpu(
    _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key, _In_ const uint8_t* value, ebpf_map_option_t option)
{

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    uint8_t* target;
    if (table->find_entry(map, key, false, &target) != EBPF_SUCCESS) {
        ebpf_result_t return_value = table->update_entry(map, key, NULL, option);
        if (return_value != EBPF_SUCCESS) {
            return return_value;
        }
        if (table->find_entry(map, key, false, &target) != EBPF_SUCCESS) {
            return EBPF_NO_MEMORY;
        }
    }
    if (_ebpf_adjust_value_pointer(map, &target) != EBPF_SUCCESS) {
        return EBPF_INVALID_ARGUMENT;
    }

    memcpy(target, value, ebpf_map_get_effective_value_size(map));
    return EBPF_SUCCESS;
}

static void
_lpm_extract(_In_ const uint8_t* value, _Outptr_ const uint8_t** data, _Out_ size_t* length_in_bits)
{
    const ebpf_core_lpm_key_t* key = (const ebpf_core_lpm_key_t*)value;
    *data = value;
    // The length of the hash table key is the size of the prefix length (32 bits) plus the prefix length.
    *length_in_bits = sizeof(uint32_t) * 8 + key->prefix_length;
}

static ebpf_result_t
_create_lpm_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t result = EBPF_SUCCESS;
    // Key is uint32_t prefix length plus space for a max length prefix.
    // - Only the prefix length plus prefix_length bits are actually used in an lpm key.
    size_t max_prefix_length = (map_definition->key_size - sizeof(uint32_t)) * 8;
    ebpf_core_lpm_map_t* lpm_map = NULL;

    EBPF_LOG_ENTRY();

    *map = NULL;

    if (inner_map_handle != ebpf_handle_invalid) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    result = _create_hash_map_internal(
        EBPF_OFFSET_OF(ebpf_core_lpm_map_t, data) + ebpf_bitmap_size(max_prefix_length + 1),
        map_definition,
        0,
        false,
        _lpm_extract,
        NULL,
        (ebpf_core_map_t**)&lpm_map);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    lpm_map->max_prefix = (uint32_t)max_prefix_length;
    // Add one to max_prefix_length to account for max length prefixes in the prefix_length bitmap.
    ebpf_bitmap_initialize((ebpf_bitmap_t*)lpm_map->data, max_prefix_length + 1);

    *map = &lpm_map->core_map;

Exit:
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_find_lpm_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data)
{
    if (!map || !key || delete_on_success) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_core_lpm_map_t* trie_map = EBPF_FROM_FIELD(ebpf_core_lpm_map_t, core_map, map);
    ebpf_core_lpm_key_t* lpm_key = (ebpf_core_lpm_key_t*)key;
    if (!lpm_key || lpm_key->prefix_length > trie_map->max_prefix) {
        return EBPF_INVALID_ARGUMENT;
    }
    uint32_t original_prefix_length = lpm_key->prefix_length;
    uint8_t* value = NULL;

    ebpf_bitmap_cursor_t cursor;
    // Start the key size search from the size of the passed in key.
    // Iterate down through the inserted key lengths until we find a match.
    // - Uses the passed in key for iteration by overwriting the prefix length.
    ebpf_bitmap_start_reverse_search_at((ebpf_bitmap_t*)trie_map->data, &cursor, original_prefix_length);
    lpm_key->prefix_length = (uint32_t)ebpf_bitmap_reverse_search_next_bit(&cursor);
    while (lpm_key->prefix_length != MAXUINT32) {
        if (_find_hash_map_entry(map, key, false, &value) == EBPF_SUCCESS) {
            break;
        }
        lpm_key->prefix_length = (uint32_t)ebpf_bitmap_reverse_search_next_bit(&cursor);
    }

    // Restore the original prefix length.
    lpm_key->prefix_length = original_prefix_length;
    if (!value) {
        return EBPF_KEY_NOT_FOUND;
    } else {
        *data = value;
        return EBPF_SUCCESS;
    }
}

static ebpf_result_t
_delete_lpm_map_entry(_In_ ebpf_core_map_t* map, _Inout_ const uint8_t* key)
{
    ebpf_core_lpm_map_t* trie_map = EBPF_FROM_FIELD(ebpf_core_lpm_map_t, core_map, map);
    uint32_t prefix_length = *(uint32_t*)key;
    if (prefix_length > trie_map->max_prefix) {
        return EBPF_INVALID_ARGUMENT;
    }

    return _delete_hash_map_entry(map, key);
}

static ebpf_result_t
_update_lpm_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option)
{
    ebpf_core_lpm_map_t* trie_map = EBPF_FROM_FIELD(ebpf_core_lpm_map_t, core_map, map);
    if (!key) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_core_lpm_key_t* lpm_key = (ebpf_core_lpm_key_t*)key;
    if (lpm_key->prefix_length > trie_map->max_prefix) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_result_t result = _update_hash_map_entry(map, key, data, option);
    if (result == EBPF_SUCCESS) {
        // Test if the bit is set before setting it. This avoids the overhead of a the interlocked operation.
        if (!ebpf_bitmap_test_bit((ebpf_bitmap_t*)trie_map->data, lpm_key->prefix_length)) {
            ebpf_bitmap_set_bit((ebpf_bitmap_t*)trie_map->data, lpm_key->prefix_length, true);
        }
    }
    return result;
}

static ebpf_result_t
_next_lpm_map_key_and_value(
    _Inout_ ebpf_core_map_t* map,
    _In_opt_ const uint8_t* previous_key,
    _Inout_ uint8_t* next_key,
    _Inout_opt_ uint8_t** next_value)
{
    ebpf_core_lpm_map_t* trie_map = EBPF_FROM_FIELD(ebpf_core_lpm_map_t, core_map, map);
    ebpf_core_lpm_key_t* lpm_key = (ebpf_core_lpm_key_t*)next_key;
    ebpf_core_lpm_key_t* previous_lpm_key = (ebpf_core_lpm_key_t*)previous_key;

    // Validate prefix length.
    if (!lpm_key || lpm_key->prefix_length > trie_map->max_prefix) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (previous_lpm_key && previous_lpm_key->prefix_length > trie_map->max_prefix) {
        return EBPF_INVALID_ARGUMENT;
    }

    return _next_hash_map_key_and_value(map, previous_key, next_key, next_value);
}

static ebpf_result_t
_create_queue_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t result;
    if (inner_map_handle != ebpf_handle_invalid || map_definition->key_size != 0) {
        return EBPF_INVALID_ARGUMENT;
    }
    size_t circular_map_size =
        EBPF_OFFSET_OF(ebpf_core_circular_map_t, slots) + map_definition->max_entries * sizeof(uint8_t*);
    result = _create_array_map_with_map_struct_size(circular_map_size, map_definition, map);
    if (result == EBPF_SUCCESS) {
        ebpf_core_circular_map_t* circular_map = EBPF_FROM_FIELD(ebpf_core_circular_map_t, core_map, *map);
        circular_map->type = EBPF_CORE_QUEUE;
    }
    return result;
}

static ebpf_result_t
_create_stack_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t result;
    if (inner_map_handle != ebpf_handle_invalid || map_definition->key_size != 0) {
        return EBPF_INVALID_ARGUMENT;
    }
    size_t circular_map_size =
        EBPF_OFFSET_OF(ebpf_core_circular_map_t, slots) + map_definition->max_entries * sizeof(uint8_t*);
    result = _create_array_map_with_map_struct_size(circular_map_size, map_definition, map);
    if (result == EBPF_SUCCESS) {
        ebpf_core_circular_map_t* circular_map = EBPF_FROM_FIELD(ebpf_core_circular_map_t, core_map, *map);
        circular_map->type = EBPF_CORE_STACK;
    }
    return result;
}

static void
_delete_circular_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    ebpf_core_circular_map_t* circular_map = EBPF_FROM_FIELD(ebpf_core_circular_map_t, core_map, map);
    // Free all the elements stored in the stack.
    for (size_t i = 0; i < circular_map->core_map.ebpf_map_definition.max_entries; i++) {
        ebpf_epoch_free(circular_map->slots[i]);
    }
    ebpf_epoch_free(circular_map);
}

static ebpf_result_t
_find_circular_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, bool delete_on_success, _Outptr_ uint8_t** data)
{
    if (!map) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Queue uses no key, but the caller always passes in a non-null pointer (with a 0 key size)
    // so we cannot require key to be null.
    UNREFERENCED_PARAMETER(key);

    ebpf_core_circular_map_t* circular_map = EBPF_FROM_FIELD(ebpf_core_circular_map_t, core_map, map);
    ebpf_lock_state_t state = ebpf_lock_lock(&circular_map->lock);
    *data = _ebpf_core_circular_map_peek_or_pop(circular_map, delete_on_success);
    ebpf_lock_unlock(&circular_map->lock, state);
    return *data == NULL ? EBPF_OBJECT_NOT_FOUND : EBPF_SUCCESS;
}

static ebpf_result_t
_update_circular_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key, _In_opt_ const uint8_t* data, ebpf_map_option_t option)
{
    ebpf_result_t result;

    if (!map || !data) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Queue uses no key, but the caller always passes in a non-null pointer (with a 0 key size)
    // so we cannot require key to be null.
    UNREFERENCED_PARAMETER(key);

    ebpf_core_circular_map_t* circular_map = EBPF_FROM_FIELD(ebpf_core_circular_map_t, core_map, map);
    ebpf_lock_state_t state = ebpf_lock_lock(&circular_map->lock);
    result = _ebpf_core_circular_map_push(circular_map, data, option & BPF_EXIST);
    ebpf_lock_unlock(&circular_map->lock, state);
    return result;
}

typedef void
map_async_query_complete_t(
    _In_ _Requires_lock_held_(
        (EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, map))->async.lock ||
        (EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map))->rings[(uint32_t)index].async.lock)
        const ebpf_core_map_t* map,
    uint64_t index);
typedef void
map_async_query_cancel_t(_In_ _Frees_ptr_ ebpf_core_map_async_query_context_t* cancel_context);

/**
 * @brief Helper function to queue up an async query operation.
 *
 * @param[in] map Pointer to the map.
 * @param[in] index Buffer index to query.
 * @param[in,out] async_contexts Pointer to the async contexts for the map.
 * @param[in,out] async_query_result Pointer to the async query result.
 * @param[in] async_context Pointer to the async context.
 * @param[in] complete_callback Callback to call when the async query is complete.
 * @param[in] cancel_callback Callback to call if the async query is cancelled.
 * @retval EBPF_SUCCESS The operation was completed inline.
 * @retval EBPF_PENDING The operation is pending (was successfully submitted).
 * @retval EBPF_NO_MEMORY The operation failed due to insufficient memory.
 * @retval EBPF_INVALID_ARGUMENT The operation failed due to invalid arguments.
 */
inline static ebpf_result_t
_map_async_query(
    _In_ const ebpf_core_map_t* map,
    uint64_t index,
    _Inout_ ebpf_core_map_async_contexts_t* async_contexts,
    _Inout_ ebpf_map_async_query_result_t* async_query_result,
    _Inout_ void* async_context,
    _In_ map_async_query_complete_t* complete_callback,
    _In_ map_async_query_cancel_t* cancel_callback)
{
    EBPF_LOG_ENTRY();
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    ebpf_result_t result = EBPF_PENDING;

    ebpf_lock_state_t state = ebpf_lock_lock(&async_contexts->lock);

    // Fail the async query as there is already another async query operation queued.
    if (!ebpf_list_is_empty(&async_contexts->contexts)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Allocate and initialize the async query context and queue it up.
    ebpf_core_map_async_query_context_t* context =
        ebpf_allocate_with_tag(sizeof(ebpf_core_map_async_query_context_t), EBPF_POOL_TAG_ASYNC);
    if (!context) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    ebpf_list_initialize(&context->entry);
    context->map = (ebpf_core_map_t*)map;
    context->index = index;
    context->async_query_result = async_query_result;
    context->async_context = async_context;

    ebpf_assert_success(ebpf_async_set_cancel_callback(async_context, context, cancel_callback));

    ebpf_list_insert_tail(&async_contexts->contexts, &context->entry);
    async_contexts->trip_wire = true;

    // If there is already some data available in the ring buffer, indicate the results right away.
    size_t consumer = async_query_result->consumer;
    table->query_ring_buffer(map, index, async_query_result);
    if (consumer > async_query_result->consumer) {
        // Keep the latest consumer offset.
        async_query_result->consumer = consumer;
    }
    if (async_query_result->producer > async_query_result->consumer) {
        complete_callback(map, index);
    }

Exit:
    ebpf_lock_unlock(&async_contexts->lock, state);

    EBPF_RETURN_RESULT(result);
}

/**
 * @brief Helper function to complete the async query.
 *
 * @note Requires that async_contexts->lock is held.
 *  Missing SAL annotation due to the multiple callers passing different types.
 *  The only two possible callers do have the SAL annotation.
 *
 * @param[in] map Pointer to the map.
 * @param[in,out] async_contexts Pointer to the async contexts.
 */
static void
_map_async_query_complete(_In_ const ebpf_core_map_t* map, _Inout_ ebpf_core_map_async_contexts_t* async_contexts)
{
    EBPF_LOG_ENTRY();
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    // Skip if no async_contexts have ever been queued.
    if (!async_contexts->trip_wire) {
        return;
    }
    while (!ebpf_list_is_empty(&async_contexts->contexts)) {
        ebpf_core_map_async_query_context_t* context =
            EBPF_FROM_FIELD(ebpf_core_map_async_query_context_t, entry, async_contexts->contexts.Flink);
        ebpf_map_async_query_result_t* async_query_result = context->async_query_result;
        table->query_ring_buffer(map, context->index, async_query_result);
        ebpf_list_remove_entry(&context->entry);

        ebpf_operation_map_async_query_reply_t* reply =
            EBPF_FROM_FIELD(ebpf_operation_map_async_query_reply_t, async_query_result, async_query_result);
        ebpf_async_complete(context->async_context, sizeof(*reply), EBPF_SUCCESS);
        ebpf_free(context);
        context = NULL;
    }
    EBPF_LOG_EXIT();
}

/**
 * @brief Helper function to cancel an async query.
 *
 * @param[in,out] async_contexts Pointer to the async contexts.
 * @param[in] context Pointer to the async query context to cancel.
 */
static void
_map_async_query_cancel(
    _Inout_ ebpf_core_map_async_contexts_t* async_contexts, _In_ ebpf_core_map_async_query_context_t* context)
{
    ebpf_lock_state_t state = ebpf_lock_lock(&async_contexts->lock);
    ebpf_list_remove_entry(&context->entry);
    ebpf_lock_unlock(&async_contexts->lock, state);
    ebpf_async_complete(context->async_context, 0, EBPF_CANCELED);
    ebpf_free(context);
}

static void
_query_ring_buffer_map(
    _In_ const ebpf_core_map_t* map, uint64_t index, _Inout_ ebpf_map_async_query_result_t* async_query_result)
{
    UNREFERENCED_PARAMETER(index);
    ebpf_ring_buffer_query(
        (ebpf_ring_buffer_t*)map->data, &async_query_result->consumer, &async_query_result->producer);
}

static ebpf_result_t
_set_wait_handle_ring_buffer_map(
    _In_ const ebpf_core_map_t* map, uint64_t index, _In_ ebpf_handle_t wait_handle, uint64_t flags)
{
    if (index != 0) {
        return EBPF_INVALID_ARGUMENT;
    }
    return ebpf_ring_buffer_set_wait_handle((ebpf_ring_buffer_t*)map->data, wait_handle, flags);
}

static void
_query_perf_event_array_map(
    _In_ const ebpf_core_map_t* map, uint64_t index, _Inout_ ebpf_map_async_query_result_t* async_query_result)
{
    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[(uint32_t)index];
    ebpf_ring_buffer_query(&ring->ring, &async_query_result->consumer, &async_query_result->producer);
    async_query_result->lost_count = ring->lost_records;
}

static void
_ebpf_ring_buffer_map_cancel_async_query(_In_ _Frees_ptr_ ebpf_core_map_async_query_context_t* context)
{
    EBPF_LOG_ENTRY();
    ebpf_core_ring_buffer_map_t* ring_buffer_map = EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, context->map);
    _map_async_query_cancel(&ring_buffer_map->async, context);
    EBPF_LOG_EXIT();
}

/**
 * @brief Signal the completion of an async query for a ring buffer map.
 *
 * @param[in] map Pointer to the ring buffer map.
 * @param[in] index Unused for ring buffer.
 */
static void
_ebpf_ring_buffer_map_signal_async_query_complete(
    _In_ _Requires_lock_held_((EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, map))->async.lock)
        const ebpf_core_map_t* map,
    uint64_t index)
{
    UNREFERENCED_PARAMETER(index);
    ebpf_core_ring_buffer_map_t* ring_buffer_map = EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, map);
    _map_async_query_complete(map, &ring_buffer_map->async);
}

/**
 * @brief Cancel an async query for a perf event array map.
 *
 * @param[in] cancel_context Pointer to the cancel context.
 */
static void
_ebpf_perf_event_array_map_cancel_async_query(_In_ _Frees_ptr_ ebpf_core_map_async_query_context_t* context)
{
    EBPF_LOG_ENTRY();
    uint32_t cpu_id = (uint32_t)context->index;
    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, context->map);
    if (cpu_id >= perf_event_array_map->ring_count) {
        EBPF_LOG_MESSAGE_UINT64(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Invalid CPU ID", cpu_id);
        ebpf_free(context);
    } else {
        ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];
        _map_async_query_cancel(&ring->async, context);
    }

    EBPF_LOG_EXIT();
}

/**
 * @brief Signal the completion of an async query for a perf ring.
 *
 * @param[in] map Pointer to the perf event array map.
 * @param[in] index cpu_id for ring to signal.
 */
static void
_ebpf_perf_event_array_map_signal_async_query_complete(
    _In_ _Requires_lock_held_(
        (EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map))->rings[(uint32_t)index].async.lock)
        const ebpf_core_map_t* map,
    uint64_t index)
{
    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    uint32_t cpu_id = (uint32_t)index;
    if (cpu_id >= perf_event_array_map->ring_count) {
        EBPF_LOG_MESSAGE_UINT64(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Invalid CPU ID", cpu_id);
    } else {
        ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];
        _map_async_query_complete(&perf_event_array_map->core_map, &ring->async);
    }
}

static ebpf_result_t
_map_user_ring_buffer_map(
    _In_ const ebpf_core_map_t* map,
    _Outptr_ void** consumer,
    _Outptr_ void** producer,
    _Outptr_result_buffer_(*data_size) uint8_t** data,
    _Out_ size_t* data_size)
{
    ebpf_ring_buffer_t* ring_buffer = (ebpf_ring_buffer_t*)map->data;
    return ebpf_ring_buffer_map_user(ring_buffer, consumer, producer, data, data_size);
}

static ebpf_result_t
_unmap_user_ring_buffer_map(
    _In_ const ebpf_core_map_t* map, _In_ const void* consumer, _In_ const void* producer, _In_ const void* data)
{
    ebpf_ring_buffer_t* ring_buffer = (ebpf_ring_buffer_t*)map->data;
    return ebpf_ring_buffer_unmap_user(ring_buffer, consumer, producer, data);
}

static ebpf_result_t
_query_buffer_ring_buffer_map(
    _In_ const ebpf_core_map_t* map, uint64_t index, _Outptr_ uint8_t** buffer, _Out_ size_t* consumer_offset)
{
    UNREFERENCED_PARAMETER(index);
    size_t producer_offset;
    ebpf_ring_buffer_query((ebpf_ring_buffer_t*)map->data, consumer_offset, &producer_offset);
    void* consumer = NULL;
    void* producer = NULL;
    uint8_t* data = NULL;
    size_t data_size = 0;
    ebpf_result_t result =
        ebpf_ring_buffer_map_user((ebpf_ring_buffer_t*)map->data, &consumer, &producer, &data, &data_size);
    if (result == EBPF_SUCCESS) {
        *buffer = data;
    }
    return result;
}

static ebpf_result_t
_async_query_ring_buffer_map(
    _In_ const ebpf_core_map_t* map,
    uint64_t index,
    _Inout_ ebpf_map_async_query_result_t* async_query_result,
    _Inout_ void* async_context)
{
    UNREFERENCED_PARAMETER(index);

    ebpf_core_ring_buffer_map_t* ring_buffer_map = EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, map);
    ebpf_core_map_async_contexts_t* async_contexts = &ring_buffer_map->async;
    return _map_async_query(
        map,
        index,
        async_contexts,
        async_query_result,
        async_context,
        _ebpf_ring_buffer_map_signal_async_query_complete,
        _ebpf_ring_buffer_map_cancel_async_query);
}

static ebpf_result_t
_return_buffer_ring_buffer_map(_In_ const ebpf_core_map_t* map, uint64_t index, size_t consumer_offset)
{
    UNREFERENCED_PARAMETER(index);
    return ebpf_ring_buffer_return_buffer((ebpf_ring_buffer_t*)map->data, consumer_offset);
}

static ebpf_result_t
_write_data_ring_buffer_map(_Inout_ ebpf_core_map_t* map, uint64_t flags, _In_ uint8_t* data, size_t length)
{
    UNREFERENCED_PARAMETER(flags);
    return ebpf_ring_buffer_map_output(map, data, length);
}

static ebpf_result_t
_query_buffer_perf_event_array_map(
    _In_ const ebpf_core_map_t* map, uint64_t index, _Outptr_ uint8_t** buffer, _Out_ size_t* consumer_offset)
{
    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    uint32_t cpu_id = (uint32_t)index;
    ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];
    void* consumer = NULL;
    void* producer = NULL;
    uint8_t* data = NULL;
    size_t data_size = 0;
    ebpf_result_t result = ebpf_ring_buffer_map_user(&ring->ring, &consumer, &producer, &data, &data_size);
    if (result == EBPF_SUCCESS) {
        *buffer = data;
        size_t producer_offset;
        ebpf_ring_buffer_query(&ring->ring, consumer_offset, &producer_offset);
    }
    return result;
}

static ebpf_result_t
_async_query_perf_event_array_map(
    _In_ const ebpf_core_map_t* map,
    uint64_t index,
    _Inout_ ebpf_map_async_query_result_t* async_query_result,
    _Inout_ void* async_context)
{
    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    uint32_t cpu_id = (uint32_t)index;
    ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];
    ebpf_core_map_async_contexts_t* async_contexts = &ring->async;
    return _map_async_query(
        map,
        index,
        async_contexts,
        async_query_result,
        async_context,
        _ebpf_perf_event_array_map_signal_async_query_complete,
        _ebpf_perf_event_array_map_cancel_async_query);
}

static ebpf_result_t
_return_buffer_perf_event_array_map(_In_ const ebpf_core_map_t* map, uint64_t index, size_t consumer_offset)
{
    EBPF_LOG_ENTRY();
    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    uint32_t cpu_id = (uint32_t)index;
    ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];

    ebpf_result_t result = ebpf_ring_buffer_return_buffer(&ring->ring, consumer_offset);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_write_data_perf_event_array_map(_Inout_ ebpf_core_map_t* map, uint64_t flags, _In_ uint8_t* data, size_t length)
{
    UNREFERENCED_PARAMETER(flags);
    return ebpf_perf_event_array_map_output(map, data, length);
}

static void
_delete_ring_buffer_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    EBPF_LOG_ENTRY();
    // Free the ring buffer.
    ebpf_ring_buffer_destroy((ebpf_ring_buffer_t*)map->data);

    ebpf_core_ring_buffer_map_t* ring_buffer_map = EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, map);
    // Snap the async context list.
    ebpf_list_entry_t temp_list;
    ebpf_list_initialize(&temp_list);
    ebpf_lock_state_t state = ebpf_lock_lock(&ring_buffer_map->async.lock);
    ebpf_list_entry_t* first_entry = ring_buffer_map->async.contexts.Flink;
    if (!ebpf_list_is_empty(&ring_buffer_map->async.contexts)) {
        ebpf_list_remove_entry(&ring_buffer_map->async.contexts);
        ebpf_list_append_tail_list(&temp_list, first_entry);
    }
    ebpf_lock_unlock(&ring_buffer_map->async.lock, state);
    // Cancel all pending async query operations.
    for (ebpf_list_entry_t* temp_entry = temp_list.Flink; temp_entry != &temp_list; temp_entry = temp_entry->Flink) {
        ebpf_core_map_async_query_context_t* context =
            EBPF_FROM_FIELD(ebpf_core_map_async_query_context_t, entry, temp_entry);
        ebpf_async_complete(context->async_context, 0, EBPF_CANCELED);
    }
    ebpf_epoch_free(ring_buffer_map);
    EBPF_LOG_EXIT();
}

static ebpf_result_t
_create_ring_buffer_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t result;
    ebpf_core_ring_buffer_map_t* ring_buffer_map = NULL;
    ebpf_ring_buffer_t* ring_buffer = NULL;

    EBPF_LOG_ENTRY();

    *map = NULL;

    if (inner_map_handle != ebpf_handle_invalid || map_definition->key_size != 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    ring_buffer_map = ebpf_epoch_allocate_with_tag(sizeof(ebpf_core_ring_buffer_map_t), EBPF_POOL_TAG_MAP);
    if (ring_buffer_map == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(ring_buffer_map, 0, sizeof(ebpf_core_ring_buffer_map_t));

    ring_buffer_map->core_map.ebpf_map_definition = *map_definition;
    result =
        ebpf_ring_buffer_create((ebpf_ring_buffer_t**)&ring_buffer_map->core_map.data, map_definition->max_entries);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    ring_buffer = (ebpf_ring_buffer_t*)ring_buffer_map->core_map.data;

    ebpf_list_initialize(&ring_buffer_map->async.contexts);

    *map = &ring_buffer_map->core_map;
    ring_buffer = NULL;
    ring_buffer_map = NULL;

Exit:
    ebpf_ring_buffer_destroy(ring_buffer);
    ebpf_epoch_free(ring_buffer_map);

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_map_output(_Inout_ ebpf_core_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_LOG_ENTRY();

    result = ebpf_ring_buffer_output((ebpf_ring_buffer_t*)map->data, data, length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    ebpf_core_ring_buffer_map_t* ring_buffer_map = EBPF_FROM_FIELD(ebpf_core_ring_buffer_map_t, core_map, map);

    ebpf_lock_state_t state = ebpf_lock_lock(&ring_buffer_map->async.lock);
    _ebpf_ring_buffer_map_signal_async_query_complete(map, 0);
    ebpf_lock_unlock(&ring_buffer_map->async.lock, state);

Exit:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_query_buffer(
    _In_ const ebpf_map_t* map, uint64_t index, _Outptr_ uint8_t** buffer, _Out_ size_t* consumer_offset)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->query_buffer == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_query_buffer not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->query_buffer(map, index, buffer, consumer_offset);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_map_map_user(
    _In_ const ebpf_map_t* map,
    _Outptr_ void** consumer,
    _Outptr_ void** producer,
    _Outptr_result_buffer_(*data_size) const uint8_t** data,
    _Out_ size_t* data_size)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->map_ring_buffer == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_ring_buffer_map_map_user not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->map_ring_buffer(map, consumer, producer, data, data_size);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_map_unmap_user(
    _In_ const ebpf_map_t* map, _In_ const void* consumer, _In_ const void* producer, _In_ const void* data)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    if (!table->unmap_ring_buffer)
        return EBPF_INVALID_ARGUMENT;
    return table->unmap_ring_buffer((const ebpf_core_map_t*)map, consumer, producer, data);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_set_wait_handle_internal(_In_ const ebpf_map_t* map, uint64_t index, ebpf_handle_t wait_handle, uint64_t flags)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->set_wait_handle == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_set_wait_handle_internal not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->set_wait_handle(map, index, wait_handle, flags);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_async_query(
    _Inout_ ebpf_map_t* map,
    uint64_t index,
    _Inout_ ebpf_map_async_query_result_t* async_query_result,
    _Inout_ void* async_context)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    if (table->async_query == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_async_query not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->async_query(map, index, async_query_result, async_context);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_return_buffer(_In_ const ebpf_map_t* map, uint64_t flags, size_t length)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->return_buffer == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_return_buffer not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->return_buffer(map, flags, length);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_write_data(_Inout_ ebpf_map_t* map, uint64_t flags, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    if (table->write_data == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_write_data not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->write_data(map, flags, data, length);
}

static void
_delete_perf_event_array_map(_In_ _Post_invalid_ ebpf_core_map_t* map)
{
    EBPF_LOG_ENTRY();

    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);

    uint32_t ring_count = perf_event_array_map->ring_count;

    // Cancel any outstanting contexts and free each ring.
    for (uint32_t cpu_id = 0; cpu_id < ring_count; cpu_id++) {
        ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];
        // Snap the async context list.
        ebpf_list_entry_t temp_list;
        ebpf_list_initialize(&temp_list);

        ebpf_lock_state_t state = ebpf_lock_lock(&ring->async.lock);
        ebpf_list_entry_t* first_entry = ring->async.contexts.Flink;
        if (!ebpf_list_is_empty(&ring->async.contexts)) {
            ebpf_list_remove_entry(&ring->async.contexts);
            ebpf_list_append_tail_list(&temp_list, first_entry);
        }
        ebpf_lock_unlock(&ring->async.lock, state);

        // Cancel all pending async query operations.
        for (ebpf_list_entry_t* temp_entry = temp_list.Flink; temp_entry != &temp_list;
             temp_entry = temp_entry->Flink) {
            ebpf_core_map_async_query_context_t* context =
                EBPF_FROM_FIELD(ebpf_core_map_async_query_context_t, entry, temp_entry);
            ebpf_async_complete(context->async_context, 0, EBPF_CANCELED);
        }
        ebpf_ring_buffer_free_ring_memory(&ring->ring);
    }

    ebpf_epoch_free(perf_event_array_map);
}

static ebpf_result_t
_create_perf_event_array_map(
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_core_map_t** map)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_core_perf_event_array_map_t* perf_event_array_map = NULL;
    uint32_t cpu_count = ebpf_get_cpu_count();

    EBPF_LOG_ENTRY();

    *map = NULL;

    if (inner_map_handle != ebpf_handle_invalid) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    size_t perf_event_array_map_size =
        EBPF_OFFSET_OF(ebpf_core_perf_event_array_map_t, rings) + cpu_count * sizeof(ebpf_core_perf_ring_t);

    perf_event_array_map = ebpf_epoch_allocate_with_tag(perf_event_array_map_size, EBPF_POOL_TAG_MAP);
    if (perf_event_array_map == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memset(perf_event_array_map, 0, perf_event_array_map_size);

    perf_event_array_map->core_map.ebpf_map_definition = *map_definition;
    perf_event_array_map->ring_count = cpu_count;

    uint32_t cpu_i;
    for (cpu_i = 0; cpu_i < perf_event_array_map->ring_count; cpu_i++) {
        ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_i];
        result = ebpf_ring_buffer_allocate_ring(&ring->ring, map_definition->max_entries);
        if (result != EBPF_SUCCESS) {
            // Failed to allocate ring, only free the rings we created.
            perf_event_array_map->ring_count = cpu_i;
            goto Exit;
        }
        ebpf_list_initialize(&ring->async.contexts);
        ebpf_lock_create(&ring->async.lock);
    }

    result = EBPF_SUCCESS;

    *map = &perf_event_array_map->core_map;
    perf_event_array_map = NULL;

Exit:
    if (perf_event_array_map != NULL) {
        for (cpu_i = 0; cpu_i < perf_event_array_map->ring_count; cpu_i++) {
            ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_i];
            ebpf_ring_buffer_free_ring_memory(&ring->ring);
        }
        ebpf_epoch_free(perf_event_array_map);
    }

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_output(_Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    EBPF_LOG_ENTRY();

    KIRQL irql_at_enter = ebpf_raise_irql_to_dispatch_if_needed();
    uint32_t cpu_id = ebpf_get_current_cpu();

    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];

    uint8_t* record_data;
    ebpf_result_t result = ebpf_ring_buffer_reserve_exclusive(&ring->ring, &record_data, length);
    if (result != EBPF_SUCCESS) {
        ring->lost_records++;
        goto Exit;
    }
    memcpy(record_data, data, length);
    result = ebpf_ring_buffer_submit(record_data, 0);

    ebpf_lock_state_t state = ebpf_lock_lock(&ring->async.lock);
    _ebpf_perf_event_array_map_signal_async_query_complete(&perf_event_array_map->core_map, cpu_id);
    ebpf_lock_unlock(&ring->async.lock, state);

Exit:
    ebpf_lower_irql_from_dispatch_if_needed(irql_at_enter);
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_output_with_capture(
    _In_ void* ctx, _Inout_ ebpf_map_t* map, uint64_t flags, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    if (flags == EBPF_MAP_FLAG_CURRENT_CPU) {
        // Automatic CPU selection and no data capture.
        return ebpf_perf_event_array_map_output(map, data, length);
    }

    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_LOG_ENTRY();

    ebpf_assert(ctx != NULL);

    uint32_t target_cpu = (uint32_t)((EBPF_MAP_FLAG_INDEX_MASK & flags) >> EBPF_MAP_FLAG_INDEX_SHIFT);
    uint32_t capture_length = (uint32_t)((flags & EBPF_MAP_FLAG_CTX_LENGTH_MASK) >> EBPF_MAP_FLAG_CTX_LENGTH_SHIFT);

    const void* extra_data = NULL;
    size_t extra_length = 0;
    if (capture_length != 0) {
        // Caller requested data capture.
        ebpf_assert(ctx != NULL);

        uint8_t *ctx_data_start, *ctx_data_end;
        ebpf_program_get_context_data(ctx, &ctx_data_start, &ctx_data_end);

        if (ctx_data_start == NULL || ctx_data_end == NULL) {
            // no context data pointer.
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto exit_pre_dispatch;
        } else if ((uint64_t)(ctx_data_end - ctx_data_start) < (uint64_t)capture_length) {
            // Requested capture length larger than data.
            result = EBPF_INVALID_ARGUMENT;
            goto exit_pre_dispatch;
        }

        extra_data = ctx_data_start;
        extra_length = capture_length;
    }

    KIRQL irql_at_enter = KeGetCurrentIrql();
    if (irql_at_enter < DISPATCH_LEVEL) {
        if (target_cpu != (uint32_t)EBPF_MAP_FLAG_CURRENT_CPU) {
            // Passive producers must specify current cpu flag.
            result = EBPF_INVALID_ARGUMENT;
            goto exit_pre_dispatch;
        }
        irql_at_enter = ebpf_raise_irql(DISPATCH_LEVEL);
    }

    uint32_t current_cpu = ebpf_get_current_cpu();

    uint32_t cpu_id = target_cpu;
    if (target_cpu == (uint32_t)EBPF_MAP_FLAG_CURRENT_CPU) {
        cpu_id = current_cpu;
    } else if (cpu_id != current_cpu) {
        // We only support writes to the current CPU.
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    ebpf_core_perf_event_array_map_t* perf_event_array_map =
        EBPF_FROM_FIELD(ebpf_core_perf_event_array_map_t, core_map, map);
    ebpf_core_perf_ring_t* ring = &perf_event_array_map->rings[cpu_id];

    uint8_t* record_data;
    result = ebpf_ring_buffer_reserve_exclusive(&ring->ring, &record_data, length + extra_length);
    if (result != EBPF_SUCCESS) {
        ring->lost_records++;
        goto Exit;
    }
    memcpy(record_data, data, length);
    if (extra_data != NULL) {
        memcpy(record_data + length, extra_data, extra_length);
    }
    result = ebpf_ring_buffer_submit(record_data, 0);

    ebpf_lock_state_t state = ebpf_lock_lock(&ring->async.lock);
    _ebpf_perf_event_array_map_signal_async_query_complete(&perf_event_array_map->core_map, cpu_id);
    ebpf_lock_unlock(&ring->async.lock, state);

Exit:
    if (irql_at_enter < DISPATCH_LEVEL) {
        ebpf_lower_irql(irql_at_enter);
    }
exit_pre_dispatch:
    EBPF_RETURN_RESULT(result);
}

const ebpf_map_metadata_table_t ebpf_map_metadata_tables[] = {
    {
        BPF_MAP_TYPE_UNSPEC,
        NULL,
    },
    {
        .map_type = BPF_MAP_TYPE_HASH,
        .create_map = _create_hash_map,
        .delete_map = _delete_hash_map,
        .find_entry = _find_hash_map_entry,
        .update_entry = _update_hash_map_entry,
        .delete_entry = _delete_hash_map_entry,
        .next_key_and_value = _next_hash_map_key_and_value,
    },
    {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .create_map = _create_array_map,
        .delete_map = _delete_array_map,
        .find_entry = _find_array_map_entry,
        .update_entry = _update_array_map_entry,
        .delete_entry = _delete_array_map_entry,
        .next_key_and_value = _next_array_map_key_and_value,
    },
    {
        .map_type = BPF_MAP_TYPE_PROG_ARRAY,
        .create_map = _create_object_array_map,
        .delete_map = _delete_program_array_map,
        .associate_program = _associate_program_with_prog_array_map,
        .find_entry = _find_array_map_entry_with_reference,
        .get_object_from_entry = _get_object_from_array_map_entry,
        .update_entry_with_handle = _update_prog_array_map_entry_with_handle,
        .delete_entry = _delete_program_array_map_entry,
        .next_key_and_value = _next_array_map_key_and_value,
    },
    {
        .map_type = BPF_MAP_TYPE_PERCPU_HASH,
        .create_map = _create_hash_map,
        .delete_map = _delete_hash_map,
        .find_entry = _find_hash_map_entry,
        .update_entry = _update_hash_map_entry,
        .update_entry_per_cpu = _update_entry_per_cpu,
        .delete_entry = _delete_hash_map_entry,
        .next_key_and_value = _next_hash_map_key_and_value,
        .per_cpu = true,
    },
    {
        .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .create_map = _create_array_map,
        .delete_map = _delete_array_map,
        .find_entry = _find_array_map_entry,
        .update_entry = _update_array_map_entry,
        .update_entry_per_cpu = _update_entry_per_cpu,
        .delete_entry = _delete_array_map_entry,
        .next_key_and_value = _next_array_map_key_and_value,
        .per_cpu = true,
    },
    {
        .map_type = BPF_MAP_TYPE_HASH_OF_MAPS,
        .create_map = _create_object_hash_map,
        .delete_map = _delete_object_hash_map,
        .find_entry = _find_hash_map_entry,
        .get_object_from_entry = _get_object_from_hash_map_entry,
        .update_entry_with_handle = _update_map_hash_map_entry_with_handle,
        .delete_entry = _delete_map_hash_map_entry,
        .next_key_and_value = _next_hash_map_key_and_value,
    },
    {
        .map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
        .create_map = _create_object_array_map,
        .delete_map = _delete_map_array_map,
        .find_entry = _find_array_map_entry_with_reference,
        .get_object_from_entry = _get_object_from_array_map_entry,
        .update_entry_with_handle = _update_map_array_map_entry_with_handle,
        .delete_entry = _delete_map_array_map_entry,
        .next_key_and_value = _next_array_map_key_and_value,
    },
    {
        .map_type = BPF_MAP_TYPE_LRU_HASH,
        .create_map = _create_lru_hash_map,
        .delete_map = _delete_hash_map,
        .find_entry = _find_hash_map_entry,
        .update_entry = _update_hash_map_entry,
        .delete_entry = _delete_hash_map_entry,
        .next_key_and_value = _next_hash_map_key_and_value,
        .key_history = true,
    },
    // LPM_TRIE is currently a hash-map with special behavior for find.
    {
        .map_type = BPF_MAP_TYPE_LPM_TRIE,
        .create_map = _create_lpm_map,
        .delete_map = _delete_hash_map,
        .find_entry = _find_lpm_map_entry,
        .update_entry = _update_lpm_map_entry,
        .delete_entry = _delete_lpm_map_entry,
        .next_key_and_value = _next_lpm_map_key_and_value,
    },
    {
        .map_type = BPF_MAP_TYPE_QUEUE,
        .create_map = _create_queue_map,
        .delete_map = _delete_circular_map,
        .find_entry = _find_circular_map_entry,
        .update_entry = _update_circular_map_entry,
        .zero_length_key = true,
    },
    {
        .map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
        .create_map = _create_lru_hash_map,
        .delete_map = _delete_hash_map,
        .find_entry = _find_hash_map_entry,
        .update_entry = _update_hash_map_entry,
        .update_entry_per_cpu = _update_entry_per_cpu,
        .delete_entry = _delete_hash_map_entry,
        .next_key_and_value = _next_hash_map_key_and_value,
        .per_cpu = true,
        .key_history = true,
    },
    {
        .map_type = BPF_MAP_TYPE_STACK,
        .create_map = _create_stack_map,
        .delete_map = _delete_circular_map,
        .find_entry = _find_circular_map_entry,
        .update_entry = _update_circular_map_entry,
        .zero_length_key = true,
    },
    {
        BPF_MAP_TYPE_RINGBUF,
        .create_map = _create_ring_buffer_map,
        .delete_map = _delete_ring_buffer_map,
        .query_buffer = _query_buffer_ring_buffer_map,
        .map_ring_buffer = _map_user_ring_buffer_map,
        .unmap_ring_buffer = _unmap_user_ring_buffer_map,
        .async_query = _async_query_ring_buffer_map,
        .query_ring_buffer = _query_ring_buffer_map,
        .set_wait_handle = _set_wait_handle_ring_buffer_map,
        .return_buffer = _return_buffer_ring_buffer_map,
        .write_data = _write_data_ring_buffer_map,
        .zero_length_key = true,
        .zero_length_value = true,
    },
    {
        BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .create_map = _create_perf_event_array_map,
        .delete_map = _delete_perf_event_array_map,
        .query_buffer = _query_buffer_perf_event_array_map,
        .async_query = _async_query_perf_event_array_map,
        .query_ring_buffer = _query_perf_event_array_map,
        .return_buffer = _return_buffer_perf_event_array_map,
        .write_data = _write_data_perf_event_array_map,
        .zero_length_key = true,
        .zero_length_value = true,
        .per_cpu = true,
    },
};

// ebpf_map_get_table(type) - get the metadata table for the given map type.
//
// type is checked on map creation and not user writeable, so in release mode we don't need to check it.
// In debug mode, we assert that the type is within the table bounds.
static inline _Ret_notnull_ const ebpf_map_metadata_table_t*
ebpf_map_get_table(_In_range_(0, EBPF_COUNT_OF(ebpf_map_metadata_tables) - 1) const ebpf_map_type_t type)
{
    ebpf_assert(type < EBPF_COUNT_OF(ebpf_map_metadata_tables));
    return &ebpf_map_metadata_tables[type];
}

static void
_ebpf_map_delete(_In_ _Post_invalid_ ebpf_core_object_t* object)
{
    EBPF_LOG_ENTRY();
    ebpf_map_t* map = (ebpf_map_t*)object;

    ebpf_free(map->name.value);
    ebpf_map_get_table(map->ebpf_map_definition.type)->delete_map(map);
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_create(
    _In_ const cxplat_utf8_string_t* map_name,
    _In_ const ebpf_map_definition_in_memory_t* ebpf_map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_map_t** ebpf_map)
{
    EBPF_LOG_ENTRY();
    ebpf_map_t* local_map = NULL;
    ebpf_map_type_t type = ebpf_map_definition->type;
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t cpu_count;
    cpu_count = ebpf_get_cpu_count();
    ebpf_map_definition_in_memory_t local_map_definition = *ebpf_map_definition;

    if (type < 0 || type >= EBPF_COUNT_OF(ebpf_map_metadata_tables)) {
        EBPF_LOG_MESSAGE_UINT64(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Unsupported map type", type);
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(type);

    ebpf_assert(type == table->map_type);
    ebpf_assert(BPF_MAP_TYPE_PER_CPU(type) == !!(table->per_cpu));

    if (ebpf_map_definition->key_size == 0 && !(table->zero_length_key)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    if (ebpf_map_definition->value_size == 0 && !(table->zero_length_value)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    if (ebpf_map_definition->max_entries == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (table->per_cpu) {
        local_map_definition.value_size = cpu_count * EBPF_PAD_8(local_map_definition.value_size);
    }

    if (map_name->length >= BPF_OBJ_NAME_LEN) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Map name too long", map_name->length);
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (table->create_map == NULL) {
        EBPF_LOG_MESSAGE_UINT64(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Unsupported map type", type);
        result = EBPF_OPERATION_NOT_SUPPORTED;
        goto Exit;
    }

    result = table->create_map(&local_map_definition, inner_map_handle, &local_map);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    ebpf_assert(type == local_map->ebpf_map_definition.type);

    local_map->original_value_size = ebpf_map_definition->value_size;

    result = ebpf_duplicate_utf8_string(&local_map->name, map_name);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    ebpf_object_get_program_type_t get_program_type = (table->get_object_from_entry) ? _get_map_program_type : NULL;
    result = EBPF_OBJECT_INITIALIZE(&local_map->object, EBPF_OBJECT_MAP, _ebpf_map_delete, NULL, get_program_type);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    *ebpf_map = local_map;

Exit:
    if (result != EBPF_SUCCESS) {
        if (local_map) {
            _ebpf_map_delete(&local_map->object);
        }
    }
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_find_entry(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _Out_writes_(value_size) uint8_t* value,
    int flags)
{
    // High volume call - Skip entry/exit logging.
    uint8_t* return_value = NULL;

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map key size",
            key_size,
            map->ebpf_map_definition.key_size);
        return EBPF_INVALID_ARGUMENT;
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map value size",
            value_size,
            map->ebpf_map_definition.value_size);
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_map_type_t type = map->ebpf_map_definition.type;
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(type);

    if (table->find_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "ebpf_map_find_entry not supported on map", type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    EBPF_LOG_MAP_OPERATION(flags, "find", map, key);

    if ((flags & EBPF_MAP_FLAG_HELPER) && (table->get_object_from_entry != NULL)) {

        // Disallow reads to prog array maps from this helper call for now.
        if (type == BPF_MAP_TYPE_PROG_ARRAY) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Find not supported on BPF_MAP_TYPE_PROG_ARRAY");
            return EBPF_INVALID_ARGUMENT;
        }

        ebpf_core_object_t* object = table->get_object_from_entry(map, key);
        if (object) {
            return_value = (uint8_t*)object;
        }
    } else {
        ebpf_result_t result =
            table->find_entry(map, key, flags & EBPF_MAP_FIND_FLAG_DELETE ? true : false, &return_value);
        if (result != EBPF_SUCCESS) {
            return result;
        }
    }
    if (return_value == NULL) {
        return EBPF_OBJECT_NOT_FOUND;
    }

    if (flags & EBPF_MAP_FLAG_HELPER) {
        if (_ebpf_adjust_value_pointer(map, &return_value) != EBPF_SUCCESS) {
            return EBPF_INVALID_ARGUMENT;
        }

        *(uint8_t**)value = return_value;
    } else {
        memcpy(value, return_value, map->ebpf_map_definition.value_size);
    }
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_associate_program(_Inout_ ebpf_map_t* map, _In_ const ebpf_program_t* program)
{
    EBPF_LOG_ENTRY();
    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    if (table->associate_program != NULL) {
        return table->associate_program(map, program);
    } else {
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }
}

_Ret_maybenull_ ebpf_program_t*
ebpf_map_get_program_from_entry(_Inout_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key)
{
    // High volume call - Skip entry/exit logging.
    if (key_size != map->ebpf_map_definition.key_size) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map key size",
            key_size,
            map->ebpf_map_definition.key_size);
        return NULL;
    }
    ebpf_map_type_t type = map->ebpf_map_definition.type;
    // This function should be invoked only for BPF_MAP_TYPE_PROG_ARRAY.
    // We can bypass the metadata table lookup and directly call the function.
    if (type != BPF_MAP_TYPE_PROG_ARRAY) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_get_program_from_entry not supported on map",
            type);
        return NULL;
    }

    return (ebpf_program_t*)_get_object_from_array_map_entry(map, key);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_update_entry(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    ebpf_map_option_t option,
    int flags)
{
    // High volume call - Skip entry/exit logging.
    ebpf_result_t result;

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->zero_length_key) {
        if (key_size != 0) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Map doesn't support keys",
                map->ebpf_map_definition.type);
            return EBPF_INVALID_ARGUMENT;
        }
    } else {
        if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Incorrect map key size",
                key_size,
                map->ebpf_map_definition.key_size);
            return EBPF_INVALID_ARGUMENT;
        }
    }

    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map value size",
            value_size,
            map->ebpf_map_definition.value_size);
        return EBPF_INVALID_ARGUMENT;
    }

    if (table->update_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_update_entry not supported on map",
            map->ebpf_map_definition.type);

        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    EBPF_LOG_MAP_OPERATION(flags, "update", map, key);

    if ((flags & EBPF_MAP_FLAG_HELPER) && (table->update_entry_per_cpu != NULL)) {
        result = table->update_entry_per_cpu(map, key, value, option);
    } else {
        result = table->update_entry(map, key, value, option);
    }
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_update_entry_with_handle(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    uintptr_t value_handle,
    ebpf_map_option_t option)
{
    // High volume call - Skip entry/exit logging.
    if (key_size != map->ebpf_map_definition.key_size) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map key size",
            key_size,
            map->ebpf_map_definition.key_size);
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->update_entry_with_handle == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_update_entry_with_handle not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->update_entry_with_handle(map, key, value_handle, option);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_delete_entry(_In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags)
{
    // High volume call - Skip entry/exit logging.
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (key_size != map->ebpf_map_definition.key_size)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map key size",
            key_size,
            map->ebpf_map_definition.key_size);
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->delete_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_delete_entry not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    EBPF_LOG_MAP_OPERATION(flags, "delete", map, key);

    ebpf_result_t result = table->delete_entry(map, key);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_next_key(
    _Inout_ ebpf_map_t* map,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key)
{
    // High volume call - Skip entry/exit logging.
    if (key_size != map->ebpf_map_definition.key_size) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map key size",
            key_size,
            map->ebpf_map_definition.key_size);
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);
    if (table->next_key_and_value == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_next_key not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return table->next_key_and_value(map, previous_key, next_key, NULL);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_get_info(
    _In_ const ebpf_map_t* map, _Out_writes_to_(*info_size, *info_size) uint8_t* buffer, _Inout_ uint16_t* info_size)
{
    // High volume call - Skip entry/exit logging.
    struct bpf_map_info local_map = {0};
    struct bpf_map_info* info = &local_map;

    if (*info_size == 0) {
        *info_size = sizeof(*info);
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "ebpf_map_get_info buffer length is 0.");
        EBPF_RETURN_RESULT(EBPF_INSUFFICIENT_BUFFER);
    }

    if (*info_size < sizeof(*info)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_get_info output buffer too small",
            *info_size,
            sizeof(*info));
    }

    info->id = map->object.id;
    info->type = map->ebpf_map_definition.type;
    info->key_size = map->ebpf_map_definition.key_size;
    info->value_size = map->original_value_size;
    info->max_entries = map->ebpf_map_definition.max_entries;
    info->map_flags = 0;
    if (info->type == BPF_MAP_TYPE_ARRAY_OF_MAPS || info->type == BPF_MAP_TYPE_HASH_OF_MAPS) {
        ebpf_core_object_map_t* object_map = EBPF_FROM_FIELD(ebpf_core_object_map_t, core_map, map);
        info->inner_map_id = object_map->core_map.ebpf_map_definition.inner_map_id
                                 ? object_map->core_map.ebpf_map_definition.inner_map_id
                                 : EBPF_ID_NONE;
    } else {
        info->inner_map_id = EBPF_ID_NONE;
    }
    info->pinned_path_count = map->object.pinned_path_count;
    ebpf_assert(sizeof(info->name) >= map->name.length);
    strncpy_s(info->name, sizeof(info->name), (char*)map->name.value, map->name.length);
    if (map->name.length < sizeof(info->name)) {
        memset(info->name + map->name.length, 0, sizeof(info->name) - map->name.length);
    }

    // Copy the local map info to the user supplied buffer, as much as will fit.
    uint16_t out_size = min(sizeof(*info), *info_size);
    memcpy(buffer, info, out_size);
    *info_size = out_size;

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_push_entry(_Inout_ ebpf_map_t* map, size_t value_size, _In_reads_(value_size) const uint8_t* value, int flags)
{
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->update_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_push_entry not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    return table->update_entry(map, NULL, value, flags);
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_pop_entry(_Inout_ ebpf_map_t* map, size_t value_size, _Out_writes_(value_size) uint8_t* value, int flags)
{
    uint8_t* return_value;
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->find_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_pop_entry not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    ebpf_result_t result = table->find_entry(map, NULL, true, &return_value);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    memcpy(value, return_value, map->ebpf_map_definition.value_size);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_peek_entry(_Inout_ ebpf_map_t* map, size_t value_size, _Out_writes_(value_size) uint8_t* value, int flags)
{
    uint8_t* return_value;
    if (!(flags & EBPF_MAP_FLAG_HELPER) && (value_size != map->ebpf_map_definition.value_size)) {
        return EBPF_INVALID_ARGUMENT;
    }

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->find_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_peek_entry not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    ebpf_result_t result = table->find_entry(map, NULL, false, &return_value);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    memcpy(value, return_value, map->ebpf_map_definition.value_size);
    return EBPF_SUCCESS;
}

ebpf_id_t
ebpf_map_get_id(_In_ const ebpf_map_t* map)
{
    return map->object.id;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_get_next_key_and_value_batch(
    _Inout_ ebpf_map_t* map,
    size_t previous_key_length,
    _In_reads_bytes_opt_(previous_key_length) const uint8_t* previous_key,
    _Inout_ size_t* key_and_value_length,
    _Out_writes_bytes_to_(*key_and_value_length, *key_and_value_length) uint8_t* key_and_value,
    int flags)
{
    ebpf_result_t result = EBPF_SUCCESS;
    size_t key_size = map->ebpf_map_definition.key_size;
    size_t value_size = map->ebpf_map_definition.value_size;
    size_t output_length = 0;
    size_t maximum_output_length = *key_and_value_length;

    const ebpf_map_metadata_table_t* table = ebpf_map_get_table(map->ebpf_map_definition.type);

    if (table->next_key_and_value == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_get_next_key_and_value_batch not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    if (table->delete_entry == NULL) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_map_get_next_key_and_value_batch not supported on map",
            map->ebpf_map_definition.type);
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    if (previous_key && previous_key_length != key_size) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Incorrect map key size",
            previous_key_length,
            key_size);
        return EBPF_INVALID_ARGUMENT;
    }

    // Copy as many key/value pairs as we can fit in the output buffer.
    for (;;) {
        // Check if we have enough space to write the next key and value.
        if ((output_length + key_size + value_size) > maximum_output_length) {
            // Output buffer is full.
            break;
        }

        uint8_t* next_value = NULL;

        // Get the next key and value.
        result = table->next_key_and_value(map, previous_key, key_and_value + output_length, &next_value);

        if (result != EBPF_SUCCESS) {
            break;
        }

        memcpy(key_and_value + output_length + key_size, next_value, value_size);

        if ((flags & EBPF_MAP_FIND_FLAG_DELETE) && (previous_key != NULL)) {
            // If the caller requested deletion, delete the previous entry.
            result = table->delete_entry(map, previous_key);
            if (result != EBPF_SUCCESS) {
                EBPF_LOG_MESSAGE_UINT64(
                    EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Failed to delete entry", result);
                break;
            }
        }

        previous_key = key_and_value + output_length;

        // Advance the output buffer pointer.
        output_length += key_size + value_size;
    }

    if (result == EBPF_NO_MORE_KEYS && output_length != 0) {
        // Returned at least one key/value pair.
        result = EBPF_SUCCESS;
    }

    *key_and_value_length = output_length;

    if ((flags & EBPF_MAP_FIND_FLAG_DELETE) && (previous_key != NULL) && (output_length != 0)) {
        // If the caller requested deletion, delete the last entry.
        ebpf_result_t delete_result = table->delete_entry(map, previous_key);
        if (delete_result != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_MAP, "Failed to delete last entry", delete_result);
            result = delete_result;
        }
    }

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_map_get_value_address(_In_ const ebpf_map_t* map, _Out_ uintptr_t* value_address)
{
    if (map->ebpf_map_definition.type != BPF_MAP_TYPE_ARRAY) {
        return EBPF_INVALID_ARGUMENT;
    } else {
        ebpf_core_map_t* core_map = (ebpf_core_map_t*)map;
        *value_address = (uintptr_t)core_map->data;
    }
    return EBPF_SUCCESS;
}
