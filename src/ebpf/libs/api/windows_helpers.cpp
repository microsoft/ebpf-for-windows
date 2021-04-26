// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "platform.hpp"

// Array of eBPF helpers exposed by Windows, where the index is an integer
// that appears in a Call instruction in eBPF bytecode.
const struct EbpfHelperPrototype windows_helper_prototypes[] = {
    {
        // Not used.  Clang can't deal with a "call 0"
    },
    {// void *ebpf_map_lookup_elem(struct ebpf_map *map, const void *key);
     .name = "ebpf_map_lookup_elem",
     .return_type = EbpfHelperReturnType::PTR_TO_MAP_VALUE_OR_NULL,
     .argument_type =
         {
             EbpfHelperArgumentType::PTR_TO_MAP,
             EbpfHelperArgumentType::PTR_TO_MAP_KEY,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
         }},
    {// long ebpf_map_update_elem(struct ebpf_map *map, const void *key,  const
     // void *value, uint64_t flags);
     .name = "ebpf_map_update_elem",
     .return_type = EbpfHelperReturnType::INTEGER,
     .argument_type =
         {
             EbpfHelperArgumentType::PTR_TO_MAP,
             EbpfHelperArgumentType::PTR_TO_MAP_KEY,
             EbpfHelperArgumentType::PTR_TO_MAP_VALUE,
             EbpfHelperArgumentType::ANYTHING,
             EbpfHelperArgumentType::DONTCARE,
         }},
    {// long ebpf_map_delete_elem(struct bpf_map *map, const void *key);
     .name = "ebpf_map_delete_elem",
     .return_type = EbpfHelperReturnType::INTEGER,
     .argument_type =
         {
             EbpfHelperArgumentType::PTR_TO_MAP,
             EbpfHelperArgumentType::PTR_TO_MAP_KEY,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
         }},
    {// Just for a tutorial, can probably be removed.
     // int ebpf_get_tick_count(void* ctx);
     .name = "ebpf_get_tick_count",
     .return_type = EbpfHelperReturnType::INTEGER,
     .argument_type =
         {
             EbpfHelperArgumentType::PTR_TO_CTX,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
             EbpfHelperArgumentType::DONTCARE,
         }},
};

// Check whether a given integer is a valid helper ID.
bool
is_helper_usable_windows(unsigned int n)
{
    return (n > 0) && (n < (sizeof(windows_helper_prototypes) / sizeof(*windows_helper_prototypes)));
}

// Get the prototype for the helper with a given ID.
EbpfHelperPrototype
get_helper_prototype_windows(unsigned int n)
{
    if (!is_helper_usable_windows(n)) {
        throw std::exception();
    }
    return windows_helper_prototypes[n];
}
