// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "config.hpp"
#undef VOID
#include "platform.hpp"

ebpf_result_t
verify_byte_code(
    const GUID* program_type,
    const uint8_t* byte_code,
    size_t byte_code_size,
    const char** error_message,
    uint32_t* error_message_size);
