// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

EbpfHelperPrototype get_helper_prototype_windows(unsigned int n);
bool is_helper_usable_windows(unsigned int n);

extern const ebpf_platform_t g_ebpf_platform_windows;
