// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by netebpfext.sys for use by eBPF programs.

// XDP hook.  We use "struct xdp_md" for cross-platform compatibility.
typedef struct xdp_md
{
    void* data;               ///< Pointer to start of packet data.
    void* data_end;           ///< Pointer to end of packet data.
    uint64_t data_meta;       ///< Packet metadata.
    uint32_t ingress_ifindex; ///< Ingress interface index.

    /* size: 26, cachelines: 1, members: 4 */
    /* last cacheline: 26 bytes */
} xdp_md_t;

typedef enum _xdp_action
{
    XDP_PASS = 1, ///< Allow the packet to pass.
    XDP_DROP,     ///< Drop the packet.
    XDP_TX        ///< Bounce the received packet back out the same NIC it arrived on.
} xdp_action_t;

/**
 * @brief Handle an incoming packet as early as possible.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_XDP
 *
 * @param[in] context Packet metadata.
 * @retval XDP_PASS Allow the packet to pass.
 * @retval XDP_DROP Drop the packet.
 * @retval XDP_TX Bounce the received packet back out the same NIC it arrived on.
 */
typedef xdp_action_t
xdp_hook_t(xdp_md_t* context);

// XDP helper functions.
#define XDP_EXT_HELPER_FN_BASE 0xFFFF

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_xdp_adjust_head = XDP_EXT_HELPER_FN_BASE + 1,
} ebpf_nethook_helper_id_t;

/**
 * @brief Adjust XDP context data pointer.
 *
 * @param[in] ctx XDP context.
 * @param[in] delta Number of bytes to move the data pointer by.
 *
 * @retval 0 The operation was successful.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_xdp_adjust_head, (xdp_md_t * ctx, int delta));
#ifndef __doxygen
#define bpf_xdp_adjust_head ((bpf_xdp_adjust_head_t)BPF_FUNC_xdp_adjust_head)
#endif

// BIND hook

typedef enum _bind_operation
{
    BIND_OPERATION_BIND,      ///< Entry to bind.
    BIND_OPERATION_POST_BIND, ///< After port allocation.
    BIND_OPERATION_UNBIND,    ///< Release port.
} bind_operation_t;

typedef struct _bind_md
{
    uint8_t* app_id_start;         ///< Pointer to start of App ID.
    uint8_t* app_id_end;           ///< Pointer to end of App ID.
    uint64_t process_id;           ///< Process ID.
    uint8_t socket_address[16];    ///< Socket address to bind to.
    uint8_t socket_address_length; ///< Length in bytes of the socket address.
    bind_operation_t operation;    ///< Operation to do.
    uint8_t protocol;              ///< Protocol number (e.g., IPPROTO_TCP).
} bind_md_t;

typedef enum _bind_action
{
    BIND_PERMIT,   ///< Permit the bind operation.
    BIND_DENY,     ///< Deny the bind operation.
    BIND_REDIRECT, ///< Change the bind endpoint.
} bind_action_t;

/**
 * @brief Handle a socket bind() request.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_BIND
 *
 * @param[in] context Socket metadata.
 * @retval BIND_PERMIT Permit the bind operation.
 * @retval BIND_DENY Deny the bind operation.
 * @retval BIND_REDIRECT Change the bind endpoint.
 */
typedef bind_action_t
bind_hook_t(bind_md_t* context);
