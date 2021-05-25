// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

EbpfHelperPrototype
get_helper_prototype_windows(unsigned int n);
bool
is_helper_usable_windows(unsigned int n);

EbpfProgramType
get_program_type_windows(const GUID& program_type);

extern const ebpf_platform_t g_ebpf_platform_windows_service;
