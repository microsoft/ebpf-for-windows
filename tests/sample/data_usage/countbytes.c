#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

#pragma clang section data = "maps"
ebpf_map_definition_t byte_map = {
    .size = sizeof(ebpf_map_definition_t),
    .type = EBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(five_tuple_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 500};


#pragma clang section text = "mac"
int
CountBytes(mac_md_t* ctx)
{
    uint64_t* byte_count = ebpf_map_lookup_element(&byte_map, &ctx->five_tuple);
    if (!byte_count) {
        ebpf_map_update_element(&byte_map, &ctx->five_tuple, ctx->packet_length, 0);
    }
    else {
        ebpf_map_update_element(&byte_map, &ctx->five_tuple, *byte_count + ctx->packet_length, 0);
    }
    return;
}