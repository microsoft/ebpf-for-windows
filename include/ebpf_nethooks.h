// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by netebpfext.sys for use by eBPF programs.

#ifndef __doxygen
#define EBPF_HELPER(return_type, name, args) typedef return_type(*const name##_t) args
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

/**
 * @brief Actions that can be returned by a bind hook program.
 */
typedef enum _bind_action
{
    /**
     * @brief Permit the bind operation (soft permit).
     *
     * Use this when you want to allow the operation but still permit other
     * security policies or filters to make the final decision.
     */
    BIND_PERMIT_SOFT,

    /**
     * @brief Deny the bind operation.
     *
     * The bind operation will be blocked.
     */
    BIND_DENY,

    /**
     * @brief Change the bind endpoint.
     *
     * The bind operation is allowed but the target address/port may be modified
     * by the eBPF program. The program should update the socket_address field
     * in the bind_md_t context to specify the new target.
     */
    BIND_REDIRECT,

    /**
     * @brief Permit the bind operation (hard permit).
     *
     * The bind operation is allowed and lower-priority filters or security policies
     * cannot override this decision.
     */
    BIND_PERMIT_HARD,

    /**
     * @brief Backward compatibility alias for BIND_PERMIT_SOFT.
     * @deprecated Use BIND_PERMIT_SOFT instead for clarity about the permit behavior.
     */
    BIND_PERMIT = BIND_PERMIT_SOFT,
} bind_action_t;

/**
 * @brief Handle IPv4 and IPv6 socket bind() requests.
 *
 * This function type defines the signature for eBPF programs that handle socket bind operations.
 * The program is called before the bind operation completes and can inspect the socket metadata
 * to make policy decisions about whether to allow, deny, or redirect the bind request.
 *
 * The program can examine details such as the process ID, socket address, protocol, and
 * interface information to implement custom bind policies. For redirect operations, the
 * program can modify the socket_address field in the context to change the bind target.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_BIND
 *
 * @note The function must return one of the defined bind_action_t values.
 *
 * @param[in] context Socket metadata.
 * @retval BIND_PERMIT_SOFT Permit the bind operation (soft permit - allows lower-priority filters to override).
 * @retval BIND_PERMIT_HARD Permit the bind operation (hard permit - blocks lower-priority filters).
 * @retval BIND_DENY Deny the bind operation.
 * @retval BIND_REDIRECT Change the bind endpoint.
 */
typedef bind_action_t
bind_hook_t(bind_md_t* context);

//
// CGROUP_SOCK_ADDR.
//

typedef enum _ebpf_sock_addr_verdict
{
    BPF_SOCK_ADDR_VERDICT_REJECT,
    BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
    BPF_SOCK_ADDR_VERDICT_PROCEED_HARD
} ebpf_sock_addr_verdict_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
/**
 *  @brief Data structure used as context for BPF_PROG_TYPE_CGROUP_SOCK_ADDR program type.
 */
typedef struct bpf_sock_addr
{
    uint32_t family; ///< IP address family.
    struct
    {
        /**
         * @brief Source IP address in network byte order.
         * Local for ingress, remote for egress.
         */
        union
        {
            uint32_t msg_src_ip4;
            uint32_t msg_src_ip6[4];
        };
        uint16_t msg_src_port; ///< Source port in network byte order.
    };
    struct
    {
        /* @brief Destination IP address in network byte order.
         * Local for egress, remote for ingress.
         */
        union
        {
            uint32_t user_ip4;
            uint32_t user_ip6[4];
        };
        uint16_t user_port; ///< Destination port in network byte order.
    };
    uint32_t protocol;       ///< IP protocol.
    uint32_t compartment_id; ///< Network compartment Id.
    uint64_t interface_luid; ///< Interface LUID.
} bpf_sock_addr_t;

#define SOCK_ADDR_EXT_HELPER_FN_BASE 0xFFFF

typedef enum
{
    BPF_FUNC_sock_addr_get_current_pid_tgid = SOCK_ADDR_EXT_HELPER_FN_BASE + 1,
    BPF_FUNC_sock_addr_set_redirect_context = SOCK_ADDR_EXT_HELPER_FN_BASE + 2,
} ebpf_sock_addr_helper_id_t;

/**
 * @brief Set a context for consumption by a user-mode application (sock_addr specific only).
 * This function is not supported for the recv_accept hooks.
 *
 * @param[in] ctx Pointer to bpf_sock_addr_t context.
 * @param[in] data Pointer to data to store.
 * @param[in] data_size The size of the data to store.
 *
 * @retval 0 The operation was successful.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_sock_addr_set_redirect_context, (bpf_sock_addr_t * ctx, void* data, uint32_t data_size));
#ifndef __doxygen
#define bpf_sock_addr_set_redirect_context \
    ((bpf_sock_addr_set_redirect_context_t)BPF_FUNC_sock_addr_set_redirect_context)
#endif

/**
 * @brief Handle socket operation. Currently supports ingress/egress connection initialization.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR
 *
 * Attach type(s):
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT
 *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT
 *
 * @param[in] context \ref bpf_sock_addr_t
 * @retval BPF_SOCK_ADDR_VERDICT_REJECT Block the socket operation. Maps to a hard block in WFP.
 * @retval BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT Allow the socket operation. Maps to a soft permit in WFP.
 * @retval BPF_SOCK_ADDR_VERDICT_PROCEED_HARD Allow the socket operation. Maps to a hard permit in WFP.
 *
 * Any return value other than the ones mentioned above is treated as BPF_SOCK_ADDR_VERDICT_REJECT.
 */
typedef ebpf_sock_addr_verdict_t
sock_addr_hook_t(bpf_sock_addr_t* context);

typedef enum _bpf_sock_op_type
{
    /** @brief Indicates when an active (outbound) connection is established. **/
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
    /** @brief Indicates when a passive (inbound) connection is established. **/
    BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    /** @brief Indicates when a connection is deleted. **/
    BPF_SOCK_OPS_CONNECTION_DELETED_CB
} bpf_sock_op_type_t;

typedef struct _bpf_sock_ops
{
    bpf_sock_op_type_t op;
    uint32_t family; ///< IP address family.
    struct
    {
        union
        {
            uint32_t local_ip4;
            uint32_t local_ip6[4];
        }; ///< Local IP address.
        uint32_t local_port;
    }; ///< Local IP address and port stored in network byte order.
    struct
    {
        union
        {
            uint32_t remote_ip4;
            uint32_t remote_ip6[4];
        }; ///< Remote IP address.
        uint32_t remote_port;
    }; ///< Remote IP address and port stored in network byte order.
    uint8_t protocol;        ///< IP protocol.
    uint32_t compartment_id; ///< Network compartment Id.
    uint64_t interface_luid; ///< Interface LUID.
} bpf_sock_ops_t;

/**
 * @brief Handle socket event notification. Currently notifies ingress/egress connection establishment and tear down.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_SOCK_OPS
 *
 * Attach type(s):
 *  \ref EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS
 *
 * @param[in] context \ref bpf_sock_ops_t
 * @return 0 on success, or error value in case of failure.
 *
 */
typedef int
sock_ops_hook_t(bpf_sock_ops_t* context);

#ifdef _MSC_VER
#pragma warning(pop)
#endif
