// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <iostream>
#include <ebpf_windows.h>

std::wstring
guid_to_wide_string(_In_ const GUID* guid);

std::string
guid_to_string(_In_ const GUID* guid);