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

// uint32_t
// test_ioctl_map_async_query(
//     ebpf_handle_t map_handle,
//     uint32_t index,
//     size_t consumer_offset,
//     _Out_ size_t* producer,
//     _Out_ size_t* consumer,
//     _Out_ size_t* lost_count)
// {
//     uint32_t error = ERROR_SUCCESS;
//     ebpf_operation_map_async_query_request_t request;
//     ebpf_operation_map_async_query_reply_t reply;

//     if (map_handle == ebpf_handle_invalid || producer == nullptr || consumer == nullptr || lost_count == nullptr) {
//         return ERROR_INVALID_PARAMETER;
//     }

//     // Initialize the request
//     request.header.id = EBPF_OPERATION_MAP_ASYNC_QUERY;
//     request.header.length = sizeof(ebpf_operation_map_async_query_request_t);
//     request.map_handle = map_handle;
//     request.index = index;
//     request.consumer_offset = consumer_offset;

//     // Initialize the reply
//     memset(&reply, 0, sizeof(ebpf_operation_map_async_query_reply_t));

//     error = invoke_ioctl(request, reply);
//     if (error == ERROR_SUCCESS) {
//         *producer = reply.async_query_result.producer;
//         *consumer = reply.async_query_result.consumer;
//         *lost_count = reply.async_query_result.lost_count;
//     }

//     return error;
// }

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
