// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <netiodef.h>
#include <winsock2.h>
#include <ws2tcpip.h>

struct _udp_header
{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
};
