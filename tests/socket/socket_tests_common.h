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

typedef struct _destination_entry
{
    ip_address_t destination_ip;
    uint16_t destination_port;
    uint32_t protocol;
} destination_entry_t;

typedef struct _sock_addr_audit_entry
{
    uint64_t logon_id;
    uint64_t process_id;
    int32_t is_admin;
    uint16_t local_port;
} sock_addr_audit_entry_t;