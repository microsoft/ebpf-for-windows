// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>

#include "ebpf_protocol.h"

static_assert(sizeof(ebpf_operation_header_t) == 8, "ebpf_operation_header_t must remain 8 bytes");
static_assert(sizeof(ebpf_operation_id_t) == sizeof(uint32_t), "ebpf_operation_id_t must remain 4 bytes");
static_assert(sizeof(ebpf_code_type_t) == sizeof(uint32_t), "ebpf_code_type_t must remain 4 bytes");
static_assert(sizeof(ebpf_map_option_t) == sizeof(uint32_t), "ebpf_map_option_t must remain 4 bytes");
static_assert(sizeof(ebpf_object_type_t) == sizeof(uint32_t), "ebpf_object_type_t must remain 4 bytes");

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
static_assert(
    offsetof(ebpf_operation_create_program_request_t, data) == 28,
    "ebpf_operation_create_program_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_load_code_request_t, code) == 20,
    "ebpf_operation_load_code_request_t.code offset mismatch");
#endif

static_assert(
    offsetof(ebpf_operation_create_map_request_t, data) == 40, "ebpf_operation_create_map_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_find_element_request_t, key) == 17,
    "ebpf_operation_map_find_element_request_t.key offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_update_element_request_t, data) == 20,
    "ebpf_operation_map_update_element_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_update_element_with_handle_request_t, key) == 28,
    "ebpf_operation_map_update_element_with_handle_request_t.key offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_delete_element_request_t, key) == 16,
    "ebpf_operation_map_delete_element_request_t.key offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_get_next_key_request_t, previous_key) == 16,
    "ebpf_operation_map_get_next_key_request_t.previous_key offset mismatch");
static_assert(
    offsetof(ebpf_operation_update_pinning_request_t, path) == 16,
    "ebpf_operation_update_pinning_request_t.path offset mismatch");
static_assert(
    offsetof(ebpf_operation_get_pinned_object_request_t, path) == 8,
    "ebpf_operation_get_pinned_object_request_t.path offset mismatch");
static_assert(
    offsetof(ebpf_operation_link_program_request_t, data) == 32, "ebpf_operation_link_program_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_unlink_program_request_t, data) == 41,
    "ebpf_operation_unlink_program_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_write_data_request_t, data) == 24,
    "ebpf_operation_map_write_data_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_load_native_module_request_t, data) == 24,
    "ebpf_operation_load_native_module_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_program_test_run_request_t, data) == 42,
    "ebpf_operation_program_test_run_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_update_element_batch_request_t, data) == 20,
    "ebpf_operation_map_update_element_batch_request_t.data offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_delete_element_batch_request_t, keys) == 16,
    "ebpf_operation_map_delete_element_batch_request_t.keys offset mismatch");
static_assert(
    offsetof(ebpf_operation_map_get_next_key_value_batch_request_t, previous_key) == 17,
    "ebpf_operation_map_get_next_key_value_batch_request_t.previous_key offset mismatch");
static_assert(
    offsetof(ebpf_operation_get_next_pinned_object_path_request_t, start_path) == 12,
    "ebpf_operation_get_next_pinned_object_path_request_t.start_path offset mismatch");
