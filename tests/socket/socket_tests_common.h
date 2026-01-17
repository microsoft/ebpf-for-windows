// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SOCKET_TEST_PORT 8989
#define REDIRECT_CONTEXT_MESSAGE "RedirectContextTestMessage"

typedef struct _ip_address
{
    union
    {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };
} ip_address_t;

typedef enum _connection_type
{
    INVALID,
    TCP,
    UNCONNECTED_UDP,
    CONNECTED_UDP
} connection_type_t;

typedef struct _connection_tuple
{
    ip_address_t local_ip;
    uint16_t local_port;
    ip_address_t remote_ip;
    uint16_t remote_port;
    uint32_t protocol;
    uint64_t interface_luid;
} connection_tuple_t;

typedef struct _audit_entry
{
    connection_tuple_t tuple;
    uint64_t process_id;
    bool outbound : 1;
    bool connected : 1;
} audit_entry_t;

typedef struct _destination_entry_key
{
    ip_address_t destination_ip;
    uint16_t destination_port;
    uint32_t protocol;
} destination_entry_key_t;

typedef struct _destination_entry_value
{
    ip_address_t destination_ip;
    uint16_t destination_port;
    uint32_t connection_type;
    uint32_t verdict;
} destination_entry_value_t;

typedef struct _sock_addr_audit_entry
{
    uint64_t logon_id;
    uint64_t process_id;
    int32_t is_admin;
    uint16_t local_port;
    uint64_t socket_cookie;
} sock_addr_audit_entry_t;

/**
 * @brief Policy lookup key for bind operations.
 *
 * Maps to the bind_policy_key_t structure used in bind_policy.c sample program.
 */
typedef struct _bind_policy_key
{
    uint64_t process_id; ///< Target process ID (0 = wildcard).
    uint16_t port;       ///< Target port number (0 = wildcard).
    uint8_t protocol;    ///< IP protocol (0 = wildcard).
} bind_policy_key_t;

/**
 * @brief Policy action configuration for bind operations.
 *
 * Maps to the bind_policy_value_t structure used in bind_policy.c sample program.
 */
typedef struct _bind_policy_value
{
    uint32_t action;        ///< Action to take (bind_action_t values: BIND_PERMIT_SOFT, BIND_PERMIT_HARD, BIND_DENY,
                            ///< BIND_REDIRECT).
    uint16_t redirect_port; ///< Port to redirect to if action is BIND_REDIRECT.
    uint32_t flags;         ///< Reserved for future use.
} bind_policy_value_t;

/**
 * @brief Audit log entry for bind operations.
 *
 * Maps to the bind_audit_entry_t structure used in bind_policy.c sample program.
 */
typedef struct _bind_audit_entry
{
    uint64_t process_id;   ///< Process ID that attempted the bind.
    uint16_t port;         ///< Port that was being bound.
    uint8_t protocol;      ///< IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.).
    uint32_t operation;    ///< Operation type (bind_operation_t values).
    uint32_t action_taken; ///< Action taken (bind_action_t values).
    uint64_t timestamp;    ///< Timestamp from bpf_ktime_get_ns().
} bind_audit_entry_t;
