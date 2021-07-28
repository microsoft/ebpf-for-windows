#include <stdbool.h>
#include <stdint.h>
#include "ebpf_helpers.h"
#include "ebpf_nethooks.h"

#pragma clang section data = "maps"
ebpf_map_definition_t app_map = {
    .size = sizeof(ebpf_map_definition_t),
    .type = EBPF_MAP_TYPE_HASH,
    .key_size = sizeof(five_tuple_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 500};


#pragma clang section text = "flow"
int
AssociateFlowToContext(flow_md_t* ctx)
{
    if (ctx->flow_established_flag) {
        ebpf_map_update_element(&app_map, &ctx->five_tuple, &ctx->app_id, 0);
    }
    else { //flow deletion
        ebpf_map_delete_element(&app_map, &ctx->five_tuple);
    }
Done:
    return;
}