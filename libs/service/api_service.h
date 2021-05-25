/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include <map>
#include <stdexcept>
#include "ebpf_api.h"
#include "ebpf_execution_context.h"
extern "C"
{
#include "ubpf.h"
}

ebpf_result_t
ebpf_verify_program(
    const GUID* program_type,
    ebpf_execution_context_t execution_context,
    uint32_t map_descriptors_count,
    EbpfMapDescriptor* map_descriptors,
    uint32_t byte_code_size,
    uint8_t* byte_code,
    const char** logs,
    uint32_t* logs_size);
