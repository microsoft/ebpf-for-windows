// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "config.hpp"
#include "platform.hpp"

_Must_inspect_result_ ebpf_result_t
verify_byte_code(
    _In_ const GUID* program_type,
    _In_reads_(instruction_count) const ebpf_inst* instructions,
    uint32_t instruction_count,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_ uint32_t* error_message_size);
