// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_VERSION_MAJOR 0
#define EBPF_VERSION_MINOR 9
#define EBPF_VERSION_REVISION 0

#define QUOTE(str) #str
#define EXPAND_AND_QUOTE(str) QUOTE(str)

#define EBPF_VERSION                     \
    EXPAND_AND_QUOTE(EBPF_VERSION_MAJOR) \
    "." EXPAND_AND_QUOTE(EBPF_VERSION_MINOR) "." EXPAND_AND_QUOTE(EBPF_VERSION_REVISION)
