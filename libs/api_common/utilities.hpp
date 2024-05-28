// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_windows.h"

#include <iostream>

std::wstring
guid_to_wide_string(_In_ const GUID* guid);

std::string
guid_to_string(_In_ const GUID* guid);

std::string
ebpf_down_cast_from_wstring(const std::wstring& wide_string);
