// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief This file contains eBPF definitions common to eBPF core libraries as well as
 * the eBPF API library.
 */

#include "ebpf_structs.h"

#include <sal.h>

#define EBPF_MAX_PIN_PATH_LENGTH 256

/**
 * @brief eBPF Map Information
 */
typedef struct _ebpf_map_info
{
    ebpf_map_definition_in_memory_t definition;
    _Field_z_ char* pin_path;
} ebpf_map_info_t;

typedef intptr_t ebpf_handle_t;
extern __declspec(selectany) const ebpf_handle_t ebpf_handle_invalid = (ebpf_handle_t)-1;

typedef struct _ebpf_ring_buffer_map_async_query_result
{
    size_t producer;
    size_t consumer;
} ebpf_ring_buffer_map_async_query_result_t;

typedef enum _ebpf_object_type
{
    EBPF_OBJECT_UNKNOWN,
    EBPF_OBJECT_MAP,
    EBPF_OBJECT_LINK,
    EBPF_OBJECT_PROGRAM,
} ebpf_object_type_t;
