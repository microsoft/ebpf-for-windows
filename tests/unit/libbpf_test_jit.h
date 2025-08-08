// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

const int nonexistent_fd = 12345678;

#define TEST_IFINDEX 17

#define CONCAT(s1, s2) s1 s2
#define DECLARE_TEST_CASE(_name, _group, _function, _suffix, _execution_type) \
    TEST_CASE(CONCAT(_name, _suffix), _group) { _function(_execution_type); }
#define DECLARE_NATIVE_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-native", EBPF_EXECUTION_NATIVE)
#if !defined(CONFIG_BPF_JIT_DISABLED)
#define DECLARE_JIT_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-jit", EBPF_EXECUTION_JIT)
#else
#define DECLARE_JIT_TEST(_name, _group, _function)
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define DECLARE_INTERPRET_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-interpret", EBPF_EXECUTION_INTERPRET)
#else
#define DECLARE_INTERPRET_TEST(_name, _group, _function)
#endif

#define DECLARE_ALL_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)        \
    DECLARE_INTERPRET_TEST(_name, _group, _function)

#define DECLARE_JIT_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)

void
ebpf_test_tail_call(_In_z_ const char* filename, uint32_t expected_result);

void
test_invalid_bpf_action(char log_buffer[]);

#ifdef __cplusplus
}
#endif