// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

typedef struct UDP_HEADER_
{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
} UDP_HEADER;
