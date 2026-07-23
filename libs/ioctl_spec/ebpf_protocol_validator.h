// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This header declares the EverParse-generated IOCTL message validator.
// It avoids including EverParse headers directly, so it can be used from
// both user-mode and kernel-mode translation units without header conflicts.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#include <sal.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    // Validate an IOCTL message using the EverParse-generated parser.
    // Returns true if the message passes structural validation.
    _Must_inspect_result_ bool
    ebpf_protocol_validate_ioctl_message(_In_reads_bytes_(length) const uint8_t* buffer, uint32_t length);

#ifdef __cplusplus
}
#endif
