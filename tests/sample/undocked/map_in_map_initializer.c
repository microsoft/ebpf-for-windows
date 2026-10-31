// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

/**
 * @brief Inner map referenced by the static outer-map initializer.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
} inner_map SEC(".maps");

/**
 * @brief Outer map with a generated static initializer that references inner_map.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __array(values, inner_map);
} outer_map SEC(".maps") = {
    .values = {&inner_map},
};

/**
 * @brief No-op program used to produce a helper-free native module for static map initializer tests.
 *
 * @param[in] context Sample program context.
 * @return Zero.
 */
SEC("sample_ext") int map_in_map_initializer(sample_program_context_t* context)
{
    (void)context;
    return 0;
}
