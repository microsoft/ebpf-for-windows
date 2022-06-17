// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <windows.h>
#include "ebpf_api.h"
#include "platform.h"

ebpf_result_t
read_registry_value_string(HKEY key, _In_ const wchar_t* value_name, _Out_ wchar_t** value);

ebpf_result_t
read_registry_value_dword(_In_ HKEY key, _In_ const wchar_t* value_name, _Out_ uint32_t* value);

ebpf_result_t
read_registry_value_binary(
    _In_ HKEY key, _In_ const wchar_t* value_name, _Out_writes_(value_size) uint8_t* value, _In_ size_t value_size);
