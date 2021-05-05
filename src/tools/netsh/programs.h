// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    FN_HANDLE_CMD handle_ebpf_add_program;
    FN_HANDLE_CMD handle_ebpf_delete_program;
    FN_HANDLE_CMD handle_ebpf_set_program;
    FN_HANDLE_CMD handle_ebpf_show_programs;

#ifdef __cplusplus
}
#endif
