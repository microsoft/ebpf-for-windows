// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "api_internal.h"
#include "api_test.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_structs.h"
#include "service_helper.h"

#define SAMPLE_PROGRAM_COUNT 1
#define BIND_MONITOR_PROGRAM_COUNT 1

#define SAMPLE_MAP_COUNT 1
#define BIND_MONITOR_MAP_COUNT 3

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

inline service_install_helper
    ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);
#endif

typedef struct _audit_entry
{
    uint64_t logon_id;
    int32_t is_admin;
} audit_entry_t;

#if defined(CONFIG_BPF_JIT_DISABLED)
#define JIT_LOAD_RESULT -ENOTSUP
#else
#define JIT_LOAD_RESULT 0
#endif

int32_t
get_expected_jit_result(int32_t expected_result);

int32_t
get_expected_jit_result(int32_t expected_result);

void
perform_socket_bind(const uint16_t test_port, bool expect_success);
