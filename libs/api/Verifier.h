// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "api_internal.h"
#include "config.hpp"
#include "ebpf_program_types.h"
#include "ebpf_result.h"
#include "platform.hpp"

#include <variant>

typedef int (*map_create_fp)(
    uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

_Must_inspect_result_ ebpf_result_t
load_byte_code(
    std::variant<std::string, std::vector<uint8_t>>& file_or_buffer,
    _In_opt_z_ const char* section_name,
    _In_ const ebpf_verifier_options_t* verifier_options,
    _In_z_ const char* pin_root_path,
    _Inout_ std::vector<ebpf_program_t*>& programs,
    _Inout_ std::vector<ebpf_map_t*>& maps,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept;
