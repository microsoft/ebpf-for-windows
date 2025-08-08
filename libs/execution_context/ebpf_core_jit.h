// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_structs.h"

#ifdef __cplusplus
extern "C"
{
#endif

    // Shared variable between ebpf_core.c and ebpf_core_jit.c, defined in ebpf_core.c.
    extern bool _ebpf_platform_hypervisor_code_integrity_enabled;

#define PROTOCOL_NATIVE_MODE 1
#if !defined(CONFIG_BPF_JIT_DISABLED)
#define PROTOCOL_JIT_MODE 2
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define PROTOCOL_INTERPRET_MODE 4
#endif
#define PROTOCOL_PRIVILEGED_OPERATION 8
#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define PROTOCOL_JIT_OR_INTERPRET_MODE (PROTOCOL_JIT_MODE | PROTOCOL_INTERPRET_MODE)
#define PROTOCOL_ALL_MODES (PROTOCOL_NATIVE_MODE | PROTOCOL_JIT_MODE | PROTOCOL_INTERPRET_MODE)
#elif !defined(CONFIG_BPF_JIT_DISABLED)
#define PROTOCOL_JIT_OR_INTERPRET_MODE PROTOCOL_JIT_MODE
#define PROTOCOL_ALL_MODES (PROTOCOL_NATIVE_MODE | PROTOCOL_JIT_MODE)
#else
#define PROTOCOL_ALL_MODES PROTOCOL_NATIVE_MODE
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_protocol_load_code(_In_ const ebpf_operation_load_code_request_t* request);

    _Must_inspect_result_ ebpf_result_t
    ebpf_core_protocol_create_program(
        _In_ const ebpf_operation_create_program_request_t* request,
        _Inout_ ebpf_operation_create_program_reply_t* reply);
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_protocol_resolve_helper(
        _In_ const ebpf_operation_resolve_helper_request_t* request,
        _Inout_ ebpf_operation_resolve_helper_reply_t* reply,
        uint16_t reply_length);

    _Must_inspect_result_ ebpf_result_t
    ebpf_core_protocol_resolve_map(
        _In_ const struct _ebpf_operation_resolve_map_request* request,
        _Inout_ struct _ebpf_operation_resolve_map_reply* reply,
        uint16_t reply_length);

    _Must_inspect_result_ uint64_t
    ebpf_core_protocol_get_ec_function(
        _In_ const ebpf_operation_get_ec_function_request_t* request,
        _Inout_ ebpf_operation_get_ec_function_reply_t* reply);
#endif

#ifdef __cplusplus
}
#endif
