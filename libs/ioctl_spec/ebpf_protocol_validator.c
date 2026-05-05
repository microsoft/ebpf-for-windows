// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This file wraps the EverParse-generated IOCTL validator for use in both
// user-mode and kernel-mode builds. It is compiled as a separate translation
// unit so that EverParse's CRT includes (windef.h, stdlib.h, etc.) do not
// conflict with kernel headers (ntdef.h, ntddk.h) used in ebpf_core.c.

// Suppress EverParse's use of printf/exit (not available in kernel mode).
// These must be defined before any EverParse header is included.
#define KRML_HOST_PRINTF(...)
#define KRML_HOST_EXIT(x)

// Suppress warnings in EverParse-generated code:
// C4100: unreferenced parameter (EverParse.h DefaultErrorHandler)
// C4456: variable shadowing (EbpfProtocol.c generated validators)
#pragma warning(push)
#pragma warning(disable : 4100 4456)

#include "EbpfProtocol.c"
#include "EbpfProtocolWrapper.c"

#pragma warning(pop)

#include "ebpf_protocol_layout_check.h"
#include "ebpf_protocol_validator.h"

// EverParse error callback (required by generated wrapper code).
void
EbpfProtocolEverParseError(const char* struct_name, const char* field_name, const char* reason)
{
    (void)struct_name;
    (void)field_name;
    (void)reason;
}

_Must_inspect_result_ bool
ebpf_protocol_validate_ioctl_message(_In_reads_bytes_(length) const uint8_t* buffer, uint32_t length)
{
    // EverParse takes a mutable buffer pointer here, but validation is read-only in practice.
    return (bool)EbpfProtocolCheckEbpfIoctlMessage(length, (uint8_t*)buffer, length);
}
