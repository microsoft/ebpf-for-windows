// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Defines prototype structures for program information for general helper functions (aka global functions)
 * implemented by the eBPF core Execution Context.
 */

#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"

ebpf_helper_function_prototype_t ebpf_core_helper_function_prototype_array[] = {
    {BPF_FUNC_map_lookup_elem,
     "bpf_map_lookup_elem",
     EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    {BPF_FUNC_map_update_elem,
     "bpf_map_update_elem",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
    {BPF_FUNC_map_delete_elem,
     "bpf_map_delete_elem",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    {BPF_FUNC_map_lookup_and_delete_elem,
     "bpf_map_lookup_and_delete_elem",
     EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    {BPF_FUNC_tail_call,
     "bpf_tail_call",
     EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS, EBPF_ARGUMENT_TYPE_ANYTHING}},
    {BPF_FUNC_get_prandom_u32, "bpf_get_prandom_u32", EBPF_RETURN_TYPE_INTEGER, {0}},
    {BPF_FUNC_ktime_get_boot_ns, "bpf_ktime_get_boot_ns", EBPF_RETURN_TYPE_INTEGER, {0}},
    {BPF_FUNC_get_smp_processor_id, "bpf_get_smp_processor_id", EBPF_RETURN_TYPE_INTEGER, {0}},
    {BPF_FUNC_ktime_get_ns, "bpf_ktime_get_ns", EBPF_RETURN_TYPE_INTEGER, {0}},
    {BPF_FUNC_csum_diff,
     "bpf_csum_diff",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
      EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
      EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
      EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
      EBPF_ARGUMENT_TYPE_ANYTHING}},
    {BPF_FUNC_ringbuf_output,
     "bpf_ringbuf_output",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
      EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
      EBPF_ARGUMENT_TYPE_CONST_SIZE,
      EBPF_ARGUMENT_TYPE_ANYTHING}}};

#ifdef __cplusplus
extern "C"
{
#endif

    ebpf_helper_function_prototype_t* ebpf_core_helper_function_prototype =
        &ebpf_core_helper_function_prototype_array[0];
    uint32_t ebpf_core_helper_functions_count = EBPF_COUNT_OF(ebpf_core_helper_function_prototype_array);

#ifdef __cplusplus
}
#endif