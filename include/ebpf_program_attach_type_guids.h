// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif
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

    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_SAMPLE = {
        0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};

    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_UNSPECIFIED = {0};

    /** @brief Program type for handling incoming packets as early as possible.
     *
     * eBPF program prototype: \ref xdp_hook_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_XDP
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_XDP = {
        0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};

    /** @brief Program type for handling socket bind() requests.
     *
     * eBPF program prototype: \ref bind_hook_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_BIND
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_BIND = {
        0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};

    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_SAMPLE = {
        0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};

#ifdef __cplusplus
}
#endif
