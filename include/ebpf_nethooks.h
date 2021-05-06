// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by netebpfext.sys for use by eBPF programs.

// XDP hook.  We use "struct xdp_md" for cross-platform compatibility.
typedef struct xdp_md
{
    void* data;         /*     0     8 */
    void* data_end;     /*     8     8 */
    uint64_t data_meta; /*     16    8 */

    /* size: 12, cachelines: 1, members: 3 */
    /* last cacheline: 12 bytes */
} xdp_md_t;

typedef enum _xdp_action
{
    XDP_PASS = 1,
    XDP_DROP = 2
} xdp_action_t;

// BIND hook
typedef struct _bind_md
{
    uint8_t* app_id_start;         // 0,8
    uint8_t* app_id_end;           // 8,8
    uint64_t process_id;           // 16,8
    uint8_t socket_address[16];    // 24,16
    uint8_t socket_address_length; // 40,1
    uint8_t operation;             // 41,1
    uint8_t protocol;              // 42,1
} bind_md_t;

typedef enum _bind_operation
{
    BIND_OPERATION_BIND,      // Entry to bind
    BIND_OPERATION_POST_BIND, // After port allocation
    BIND_OPERATION_UNBIND,    // Release port
} bind_operation_t;

typedef enum _bind_action
{
    BIND_PERMIT,
    BIND_DENY,
    BIND_REDIRECT,
} bind_action_t;
