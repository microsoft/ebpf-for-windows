// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_windows.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
    //
    // Attach Types.
    //

    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_UNSPECIFIED = {0};

    /** @brief Attach type for handling incoming packets as early as possible.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_XDP
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_XDP = {
        0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};

    /** @brief Attach type for handling socket bind() requests.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_BIND
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_BIND = {
        0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};

    /** @brief The programs attached to the INET4_CONNECT hook will be invoked for
     * connect() calls on TCP or UDP sockets or when a UDP socket sends a packet to
     * a unique remote address/port tuple.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT = {
        0xa82e37b1, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};

    /** @brief The programs attached to the INET6_CONNECT hook will be invoked for
     * connect() calls on TCP or UDP sockets or when a UDP socket sends a packet to
     * a unique remote address/port tuple.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT = {
        0xa82e37b2, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};

    /** @brief The programs attached to the INET4_RECV_ACCEPT hook will get invoked for
     *  TCP accept() calls or for the first unicast UDP packet from a unique remote
     *  address/port tuple.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT = {
        0xa82e37b3, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};

    /** @brief The programs attached to the INET6_RECV_ACCEPT hook will get invoked for
     *  TCP accept() calls or for the first unicast UDP packet from a unique remote
     *  address/port tuple.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT = {
        0xa82e37b4, 0xaee7, 0x11ec, {0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee}};

    /** @brief Attach type for handling socket event notifications.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_SOCK_OPS
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS = {
        0x837d02cd, 0x3251, 0x4632, {0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2}};

    /** @brief Attach type implemented by eBPF Sample Extension driver, used for testing.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_SAMPLE
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_SAMPLE = {
        0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};

    //
    // Program Types.
    //

    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_UNSPECIFIED = {0};

#define EBPF_PROGRAM_TYPE_XDP_GUID                                                     \
    {                                                                                  \
        0xf1832a85, 0x85d5, 0x45b0, { 0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0 } \
    }

    /** @brief Program type for handling incoming packets as early as possible.
     *
     * eBPF program prototype: \ref xdp_hook_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_XDP
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_XDP = EBPF_PROGRAM_TYPE_XDP_GUID;

#define EBPF_PROGRAM_TYPE_BIND_GUID                                                    \
    {                                                                                  \
        0x608c517c, 0x6c52, 0x4a26, { 0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf } \
    }

    /** @brief Program type for handling socket bind() requests.
     *
     * eBPF program prototype: \ref bind_hook_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_BIND
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_BIND = EBPF_PROGRAM_TYPE_BIND_GUID;

#define EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR_GUID                                        \
    {                                                                                  \
        0x92ec8e39, 0xaeec, 0x11ec, { 0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee } \
    }

    /** @brief Program type for handling various socket operations such as connect(), accept() etc.
     *
     * eBPF program prototype: \ref sock_addr_hook_t
     *
     * Attach type(s):
     *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT
     *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT
     *  \ref EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT
     *  \ref EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT
     */
    __declspec(selectany)
        ebpf_program_type_t EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR = EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR_GUID;

#define EBPF_PROGRAM_TYPE_SOCK_OPS_GUID                                                \
    {                                                                                  \
        0x43fb224d, 0x68f8, 0x46d6, { 0xaa, 0x3f, 0xc8, 0x56, 0x51, 0x8c, 0xbb, 0x32 } \
    }

    /** @brief Program type for handling socket event notifications.
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_SOCK_OPS = EBPF_PROGRAM_TYPE_SOCK_OPS_GUID;

#define EBPF_PROGRAM_TYPE_SAMPLE_GUID                                                  \
    {                                                                                  \
        0xf788ef4a, 0x207d, 0x4dc3, { 0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c } \
    }

    /** @brief Program type for handling calls from the eBPF sample extension. Used for
     * testing.
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_SAMPLE
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_SAMPLE = EBPF_PROGRAM_TYPE_SAMPLE_GUID;

#ifdef __cplusplus
}
#endif
