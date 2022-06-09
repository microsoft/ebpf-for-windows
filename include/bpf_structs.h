// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file contains eBPF definitions common to eBPF programs, core execution engine
// as well as eBPF API library.

#pragma once

#if !defined(NO_CRT)
#include <stdbool.h>
#include <stdint.h>
#endif
// #include "ebpf_windows.h"

// Cross-platform BPF program types.
enum bpf_prog_type
{
    BPF_PROG_TYPE_UNSPEC, ///< Unspecified program type.

    /** @brief Program type for handling incoming packets as early as possible.
     *
     * **eBPF program prototype:** \ref xdp_hook_t
     *
     * **Attach type(s):** \ref BPF_XDP
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_XDP,

    /** @brief Program type for handling socket bind() requests.
     *
     * **eBPF program prototype:** \ref bind_hook_t
     *
     * **Attach type(s):** \ref BPF_ATTACH_TYPE_BIND
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_BIND, // TODO(#333): replace with cross-platform program type

    /** @brief Program type for handling various socket operations such as connect(), accept() etc.
     *
     * **eBPF program prototype:** \ref sock_addr_hook_t
     *
     * **Attach type(s):**
     *  \ref BPF_CGROUP_INET4_CONNECT
     *  \ref BPF_CGROUP_INET6_CONNECT
     *  \ref BPF_CGROUP_INET4_RECV_ACCEPT
     *  \ref BPF_CGROUP_INET6_RECV_ACCEPT
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,

    /** @brief Program type for handling various socket event notifications such as connection established etc.
     *
     * **eBPF program prototype:** \ref sock_ops_hook_t
     *
     * **Attach type(s):**
     *  \ref BPF_CGROUP_SOCK_OPS
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_SOCK_OPS,

    /** @brief Program type for handling calls from the eBPF sample extension. Used for
     * testing.
     *
     * **eBPF program prototype:** see the eBPF sample extension.
     *
     * **Attach type(s):** \ref BPF_ATTACH_TYPE_SAMPLE
     */
    BPF_PROG_TYPE_SAMPLE = 999
};

typedef enum bpf_prog_type bpf_prog_type_t;

// The link type is used to tell which union member is present
// in the bpf_link_info struct.  There is exactly one non-zero value
// per union member.
enum bpf_link_type
{
    BPF_LINK_TYPE_UNSPEC, ///< Unspecified link type.
    BPF_LINK_TYPE_PLAIN,  ///< Normal link type.
};

enum bpf_attach_type
{
    BPF_ATTACH_TYPE_UNSPEC, ///< Unspecified attach type.

    /** @brief Attach type for handling incoming packets as early as possible.
     *
     * **Program type:** \ref BPF_PROG_TYPE_XDP
     */
    BPF_XDP,

    /** @brief Attach type for handling socket bind() requests.
     *
     * **Program type:** \ref BPF_PROG_TYPE_BIND
     */
    BPF_ATTACH_TYPE_BIND,

    /** @brief Attach type for handling IPv4 TCP connect() or UDP send
     * to a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET4_CONNECT,

    /** @brief Attach type for handling IPv6 TCP connect() or UDP send
     * to a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET6_CONNECT,

    /** @brief Attach type for handling IPv4 TCP accept() or on receiving
     * the first unicast UDP packet from a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET4_RECV_ACCEPT,

    /** @brief Attach type for handling IPv6 TCP accept() or on receiving
     * the first unicast UDP packet from a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET6_RECV_ACCEPT,

    /** @brief Attach type for handling various socket event notifications.
     *
     * **Program type:** \ref BPF_PROG_TYPE_SOCK_OPS
     */
    BPF_CGROUP_SOCK_OPS,

    /** @brief Attach type implemented by eBPF Sample Extension driver, used for testing.
     *
     * **Program type:** \ref BPF_PROG_TYPE_SAMPLE
     */
    BPF_ATTACH_TYPE_SAMPLE,

    __MAX_BPF_ATTACH_TYPE,
};

typedef enum bpf_attach_type bpf_attach_type_t;