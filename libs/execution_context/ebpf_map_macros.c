
#define FIND_ENTRY(type, map, key, flags, return_value, result) \
{ \
    switch (type) { \
    case BPF_MAP_TYPE_HASH : \
    case BPF_MAP_TYPE_PERCPU_HASH : \
    case BPF_MAP_TYPE_HASH_OF_MAPS : \
    case BPF_MAP_TYPE_LRU_HASH : \
    case BPF_MAP_TYPE_LRU_PERCPU_HASH : \
        result = _find_hash_map_entry( \
            (ebpf_map_t*)map, key, flags, return_value); \
        break; \
    case BPF_MAP_TYPE_ARRAY : \
    case BPF_MAP_TYPE_PROG_ARRAY : \
    case BPF_MAP_TYPE_PERCPU_ARRAY : \
    case BPF_MAP_TYPE_ARRAY_OF_MAPS : \
        result = _find_array_map_entry( \
            (ebpf_map_t*)map, key, flags, return_value); \
        break; \
    case BPF_MAP_TYPE_LPM_TRIE : \
        result = _find_lpm_map_entry( \
            (ebpf_map_t*)map, key, flags, return_value); \
        break; \
    case BPF_MAP_TYPE_QUEUE : \
    case BPF_MAP_TYPE_STACK : \
        result = _find_circular_map_entry( \
            (ebpf_map_t*)map, key, flags, return_value); \
        break; \
    default: \
        ebpf_assert(false); \
        result = EBPF_INVALID_ARGUMENT; \
        break; \
    } \
}

#define FIND_ENTRY_SUPPORTED(type) \
{ \
    switch (type) { \
    case BPF_MAP_TYPE_RINGBUF : \
        return false; \
    } \
    return true; \
}

#define GET_OBJECT_FROM_ENTRY(type, map, key, object) \
{ \
    switch (type) { \
    case BPF_MAP_TYPE_PROG_ARRAY : \
    case BPF_MAP_TYPE_ARRAY_OF_MAPS : \
        object = _get_object_from_array_map_entry( \
            (ebpf_map_t*)map, key); \
        break; \
    case BPF_MAP_TYPE_HASH_OF_MAPS : \
        object = _get_object_from_hash_map_entry( \
            (ebpf_map_t*)map, key); \
        break; \
    default: \
        ebpf_assert(false); \
        break; \
    } \
}

#define UPDATE_ENTRY(type, map, key, value, option, result) \
{ \
    switch (type) { \
    case BPF_MAP_TYPE_HASH : \
    case BPF_MAP_TYPE_PERCPU_HASH : \
    case BPF_MAP_TYPE_LRU_HASH : \
    case BPF_MAP_TYPE_LRU_PERCPU_HASH : \
        result = _update_hash_map_entry( \
            map, key, value, option); \
        break; \
    case BPF_MAP_TYPE_ARRAY : \
    case BPF_MAP_TYPE_PERCPU_ARRAY : \
        result = _update_array_map_entry( \
            map, key, value, option); \
        break; \
    case BPF_MAP_TYPE_LPM_TRIE : \
        result = _update_lpm_map_entry( \
            map, key, value, option); \
        break; \
    case BPF_MAP_TYPE_QUEUE : \
    case BPF_MAP_TYPE_STACK : \
        result = _update_circular_map_entry( \
            map, key, value, option); \
        break; \
    default: \
        ebpf_assert(false); \
        result = EBPF_INVALID_ARGUMENT; \
        break; \
    } \
}

#define UPDATE_ENTRY_PER_CPU(type, map, key, value, option, result) \
{ \
    switch (type) { \
    case BPF_MAP_TYPE_PERCPU_HASH : \
    case BPF_MAP_TYPE_PERCPU_ARRAY : \
    case BPF_MAP_TYPE_LRU_PERCPU_HASH : \
        result = _update_entry_per_cpu( \
            map, key, value, option); \
        break; \
    default: \
        ebpf_assert(false); \
        result = EBPF_INVALID_ARGUMENT; \
        break; \
    } \
}

