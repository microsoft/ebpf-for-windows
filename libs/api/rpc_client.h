// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "rpc_interface_h.h"

#include <rpc.h>

RPC_STATUS
clean_up_rpc_binding(void);

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
_Must_inspect_result_ ebpf_result_t
ebpf_rpc_load_program(
    _In_ const ebpf_program_load_info* info,
    _Outptr_result_maybenull_z_ const char** logs,
    _Inout_ uint32_t* logs_size) noexcept;
#endif // !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)

_Must_inspect_result_ ebpf_result_t
ebpf_rpc_authorize_native_module(_In_z_ const char* image_path) noexcept;