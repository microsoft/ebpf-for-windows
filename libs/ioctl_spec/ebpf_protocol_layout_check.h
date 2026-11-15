// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_protocol.h"

#include <stddef.h>

static_assert(sizeof(ebpf_operation_header_t) == 8, "ebpf_operation_header_t must remain 8 bytes");
static_assert(EBPF_OPERATION_SET_NAMESPACE == 46, "Namespace operations must preserve existing operation IDs");
static_assert(EBPF_OPERATION_GET_NAMESPACE == 47, "GET_NAMESPACE operation ID mismatch");
static_assert(EBPF_OPERATION_DELETE_PINNING_IF_MATCHES == 48, "Conditional unpin operation ID mismatch");
static_assert(EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX == 49, "Extended native load operation ID mismatch");
static_assert(EBPF_OPERATION_UPDATE_PINNING_EX == 50, "Pin receipt operation ID mismatch");
static_assert(sizeof(ebpf_operation_set_namespace_request_t) == 24, "SET_NAMESPACE request layout mismatch");
static_assert(sizeof(ebpf_operation_get_namespace_request_t) == 8, "GET_NAMESPACE request layout mismatch");
static_assert(sizeof(ebpf_operation_get_namespace_reply_t) == 24, "GET_NAMESPACE reply layout mismatch");
static_assert(
    offsetof(ebpf_operation_load_native_programs_ex_request_t, pin_root_path) == 24,
    "Extended native request layout mismatch");
static_assert(
    offsetof(ebpf_operation_delete_pinning_if_matches_request_t, path) == 24, "Conditional unpin path offset mismatch");
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
    offsetof(ebpf_operation_create_map_request_t, data) == 48,
    "ebpf_operation_create_map_request_t.data offset mismatch");
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
    offsetof(ebpf_operation_link_program_request_t, data) == 32,
    "ebpf_operation_link_program_request_t.data offset mismatch");
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
    offsetof(ebpf_operation_load_native_programs_request_t, pin_root_path) == 24,
    "ebpf_operation_load_native_programs_request_t.pin_root_path offset mismatch");
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
