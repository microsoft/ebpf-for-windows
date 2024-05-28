// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_api.h"

#include <iostream>

std::string
down_cast_from_wstring(const std::wstring& wide_string);

/**
 * @brief Parse input string (depicting either interface name, alias, or index) and convert to interface index.
 *
 * @param[in] arg Input string.
 * @param[out] if_index Interface index.
 *
 * @retval EBPF_SUCCESS Operation succeeded.
 * @retval EBPF_INVALID_ARGUMENT Input string could not be converted to interface index.
 */
_Must_inspect_result_ ebpf_result_t
parse_if_index(_In_z_ const wchar_t* arg, _Out_ uint32_t* if_index);
