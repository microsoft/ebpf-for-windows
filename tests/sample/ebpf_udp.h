// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file is included by sample eBPF programs that need
// definitions for UDP headers.

#include "ebpf_nethooks.h"

typedef struct UDP_HEADER_
{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
} UDP_HEADER;