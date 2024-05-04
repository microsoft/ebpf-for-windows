// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

// TODO(#2677): Update this prototype.
BOOLEAN
usersim_fault_injection_is_enabled(void)
{
    // Kernel mode replacement (for call from usersim).
    // As of now, fault injection is not supported in kernel mode.
    return FALSE;
}
