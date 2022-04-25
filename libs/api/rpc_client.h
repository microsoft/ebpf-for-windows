// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <rpc.h>
#include "rpc_interface_h.h"

RPC_STATUS
initialize_rpc_binding(void);

RPC_STATUS
clean_up_rpc_binding(void);

ebpf_result_t
ebpf_rpc_load_program(
    _In_ ebpf_program_load_info* info,
    _Outptr_result_maybenull_z_ const char** logs,
    _Inout_ uint32_t* logs_size) noexcept;
