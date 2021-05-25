/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

// #include "ebpf_api.h"
// #include "ebpf_execution_context.h"
// #undef VOID
// #include "ebpf_helpers.h"
#include "platform.hpp"
/*
extern "C"
{
#include "ubpf.h"
}
*/

EbpfMapDescriptor&
get_map_descriptor(int map_fd);

void
cache_map_file_descriptors(const EbpfMapDescriptor* map_descriptors, uint32_t map_descriptors_count);

void
cache_map_file_descriptor(uint32_t type, uint32_t key_size, uint32_t value_size, int fd);

void
clear_map_descriptors(void);

EbpfMapDescriptor&
get_map_descriptor_at_index(int index);

uintptr_t
get_map_handle_at_index(int index);
