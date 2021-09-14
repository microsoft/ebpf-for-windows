// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "windows_platform_common.hpp"

EbpfProgramType
get_program_type_windows(const GUID& program_type);

extern const ebpf_platform_t g_ebpf_platform_windows_service;
