// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

uint32_t
test_ioctl_load_native_module(
    _In_ const std::wstring& service_path,
    _In_ const GUID* module_id,
    _Out_ ebpf_handle_t* module_handle,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs);

uint32_t
test_ioctl_load_native_programs(
    _In_ const GUID* module_id,
    size_t count_of_maps,
    _Out_writes_(count_of_maps) ebpf_handle_t* map_handles,
    size_t count_of_programs,
    _Out_writes_(count_of_programs) ebpf_handle_t* program_handles);

uint32_t
test_ioctl_map_write(ebpf_handle_t map_handle, _In_reads_bytes_(data_length) const void* data, size_t data_length);

uint32_t
test_ioctl_map_update_element_with_handle(
    ebpf_handle_t map_handle,
    uint32_t key_size,
    _In_reads_bytes_(key_size) const uint8_t* key,
    ebpf_handle_t value_handle);