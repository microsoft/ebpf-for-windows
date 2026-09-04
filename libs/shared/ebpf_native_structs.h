// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "bpf2c.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _ebpf_native_map_entry_legacy
    {
        uint64_t zero_marker[2];
        ebpf_native_module_header_t header;
        ebpf_native_map_definition_t definition;
        const char* name;
    } ebpf_native_map_entry_legacy_t;

#define EBPF_NATIVE_MAP_ENTRY_LEGACY_SIZE EBPF_SIZE_INCLUDING_FIELD(ebpf_native_map_entry_legacy_t, name)
#define EBPF_NATIVE_MAP_ENTRY_LEGACY_TOTAL_SIZE sizeof(ebpf_native_map_entry_legacy_t)

    bool
    ebpf_native_map_entry_to_current(_Out_ map_entry_t* destination, _In_ const void* source);

#ifdef __cplusplus
}
#endif
