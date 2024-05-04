// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif
    /** @brief NPI ID for eBPF program information extension.
     */
    /* 2934ad50-2154-44b6-9622-6c528c068411 */
    __declspec(selectany) GUID EBPF_PROGRAM_INFO_EXTENSION_IID = {
        0x2934ad50, 0x2154, 0x44b6, {0x96, 0x22, 0x6c, 0x52, 0x8c, 0x06, 0x84, 0x11}};

    /** @brief NPI ID for eBPF hook extension.
     */
    /* 5d564054-2736-406d-8b22-12bcffaf0a9f */
    __declspec(selectany) GUID EBPF_HOOK_EXTENSION_IID = {
        0x5d564054, 0x2736, 0x406d, {0x8b, 0x22, 0x12, 0xbc, 0xff, 0xaf, 0x0a, 0x9f}};

#ifdef __cplusplus
}
#endif
