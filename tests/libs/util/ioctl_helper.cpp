// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "catch_wrapper.hpp"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "ioctl_helper.h"

#include <future>
#include <map>
using namespace std::chrono_literals;

#ifndef GUID_NULL
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

uint32_t
test_ioctl_load_native_module(
    _In_ const std::wstring& service_path,
    _In_ const GUID* module_id,
    _Out_ ebpf_handle_t* module_handle,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs)
{
    uint32_t error = ERROR_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_load_native_module_request_t* request;
    ebpf_operation_load_native_module_reply_t reply;
    size_t service_path_size = service_path.size() * 2;

    *count_of_maps = 0;
    *count_of_programs = 0;
    *module_handle = ebpf_handle_invalid;

    size_t buffer_size = offsetof(ebpf_operation_load_native_module_request_t, data) + service_path_size;
    request_buffer.resize(buffer_size);

    request = reinterpret_cast<ebpf_operation_load_native_module_request_t*>(request_buffer.data());
    request->header.id = EBPF_OPERATION_LOAD_NATIVE_MODULE;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->module_id = *module_id;
    memcpy(
        request_buffer.data() + offsetof(ebpf_operation_load_native_module_request_t, data),
        (char*)service_path.c_str(),
        service_path_size);

    error = invoke_ioctl(request_buffer, reply);
    if (error != ERROR_SUCCESS) {
        goto Done;
    }

    *count_of_maps = reply.count_of_maps;
    *count_of_programs = reply.count_of_programs;
    *module_handle = reply.native_module_handle;

Done:
    return error;
}

uint32_t
test_ioctl_map_write(ebpf_handle_t map_handle, _In_reads_bytes_(data_length) const void* data, size_t data_length)
{
    uint32_t error = ERROR_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_map_write_data_request_t* request;

    if (map_handle == ebpf_handle_invalid || data == nullptr || data_length == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    try {
        size_t buffer_size = offsetof(ebpf_operation_map_write_data_request_t, data) + data_length;
        request_buffer.resize(buffer_size);

        request = reinterpret_cast<ebpf_operation_map_write_data_request_t*>(request_buffer.data());
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = EBPF_OPERATION_MAP_WRITE_DATA;
        request->map_handle = (uint64_t)map_handle;
        memcpy(request->data, data, data_length);

        error = invoke_ioctl(request_buffer);
    } catch (const std::bad_alloc&) {
        error = ERROR_NOT_ENOUGH_MEMORY;
    }

    return error;
}

uint32_t
test_ioctl_load_native_programs(
    _In_ const GUID* module_id,
    size_t count_of_maps,
    _Out_writes_(count_of_maps) ebpf_handle_t* map_handles,
    size_t count_of_programs,
    _Out_writes_(count_of_programs) ebpf_handle_t* program_handles)
{
    uint32_t error = ERROR_SUCCESS;
    ebpf_protocol_buffer_t reply_buffer;
    ebpf_operation_load_native_programs_request_t request;
    ebpf_operation_load_native_programs_reply_t* reply;
    size_t map_handles_size = count_of_maps * sizeof(ebpf_handle_t);
    size_t program_handles_size = count_of_programs * sizeof(ebpf_handle_t);
    size_t handles_size = map_handles_size + program_handles_size;

    size_t buffer_size = offsetof(ebpf_operation_load_native_programs_reply_t, data) + handles_size;
    reply_buffer.resize(buffer_size);

    reply = reinterpret_cast<ebpf_operation_load_native_programs_reply_t*>(reply_buffer.data());
    request.header.id = EBPF_OPERATION_LOAD_NATIVE_PROGRAMS;
    request.header.length = sizeof(ebpf_operation_load_native_programs_request_t);
    request.module_id = *module_id;

    error = invoke_ioctl(request, reply_buffer);
    if (error != ERROR_SUCCESS) {
        goto Done;
    }

    REQUIRE(reply->map_handle_count == count_of_maps);
    REQUIRE(reply->program_handle_count == count_of_programs);

    memcpy(map_handles, reply->data, map_handles_size);
    memcpy(program_handles, reply->data + map_handles_size, program_handles_size);

Done:
    return error;
}

uint32_t
test_ioctl_map_update_element_with_handle(
    ebpf_handle_t map_handle,
    uint32_t key_size,
    _In_reads_bytes_(key_size) const uint8_t* key,
    ebpf_handle_t value_handle)
{
    uint32_t error = ERROR_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_map_update_element_with_handle_request_t* request;

    if (map_handle == ebpf_handle_invalid || key == nullptr || key_size == 0 || value_handle == ebpf_handle_invalid) {
        return ERROR_INVALID_PARAMETER;
    }

    try {
        size_t buffer_size = offsetof(ebpf_operation_map_update_element_with_handle_request_t, key) + key_size;
        request_buffer.resize(buffer_size);

        request = reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request_buffer.data());
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE;
        request->map_handle = (uint64_t)map_handle;
        request->value_handle = (uint64_t)value_handle;
        memcpy(request->key, key, key_size);

        error = invoke_ioctl(request_buffer);
    } catch (const std::bad_alloc&) {
        error = ERROR_NOT_ENOUGH_MEMORY;
    }

    return error;
}