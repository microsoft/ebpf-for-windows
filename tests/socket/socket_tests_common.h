// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SOCKET_TEST_PORT 8989

typedef struct _ip_address
{
    union
    {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };
} ip_address_t;

typedef struct _connection_tuple
{
    ip_address_t src_ip;
    uint16_t src_port;
    ip_address_t dst_ip;
    uint16_t dst_port;
    uint32_t protocol;
    uint64_t interface_luid;
} connection_tuple_t;

typedef struct _audit_entry
{
    connection_tuple_t tuple;
    bool outbound : 1;
    bool connected : 1;
} audit_entry_t;
