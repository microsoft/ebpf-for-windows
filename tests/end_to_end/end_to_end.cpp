// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <mutex>
#include <thread>
#include <WinSock2.h>

#include "bpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_core.h"
#include "ebpf_xdp_program_data.h"
#include "ebpf_flow_program_data.h"
#include "ebpf_mac_program_data.h"
#include "helpers.h"
#include "libbpf.h"
#include "mock.h"
#include "test_helper.hpp"
#include "tlv.h"
namespace ebpf {
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#include "../sample/ebpf.h"
#pragma warning(pop)
}; // namespace ebpf

ebpf_handle_t
GlueCreateFileW(
    PCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    PSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    ebpf_handle_t hTemplateFile)
{
    UNREFERENCED_PARAMETER(lpFileName);
    UNREFERENCED_PARAMETER(dwDesiredAccess);
    UNREFERENCED_PARAMETER(dwShareMode);
    UNREFERENCED_PARAMETER(lpSecurityAttributes);
    UNREFERENCED_PARAMETER(dwCreationDisposition);
    UNREFERENCED_PARAMETER(dwFlagsAndAttributes);
    UNREFERENCED_PARAMETER(hTemplateFile);

    return (ebpf_handle_t)0x12345678;
}

BOOL
GlueCloseHandle(ebpf_handle_t hObject)
{
    UNREFERENCED_PARAMETER(hObject);
    return TRUE;
}

BOOL
GlueDeviceIoControl(
    ebpf_handle_t hDevice,
    DWORD dwIoControlCode,
    PVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    PDWORD lpBytesReturned,
    OVERLAPPED* lpOverlapped)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(nInBufferSize);
    UNREFERENCED_PARAMETER(dwIoControlCode);
    UNREFERENCED_PARAMETER(lpOverlapped);

    ebpf_result_t result;
    const ebpf_operation_header_t* user_request = reinterpret_cast<decltype(user_request)>(lpInBuffer);
    ebpf_operation_header_t* user_reply = nullptr;
    *lpBytesReturned = 0;
    auto request_id = user_request->id;
    size_t minimum_request_size = 0;
    size_t minimum_reply_size = 0;

    result = ebpf_core_get_protocol_handler_properties(request_id, &minimum_request_size, &minimum_reply_size);
    if (result != EBPF_SUCCESS)
        goto Fail;

    if (user_request->length < minimum_request_size) {
        result = EBPF_INVALID_ARGUMENT;
        goto Fail;
    }

    if (minimum_reply_size > 0) {
        user_reply = reinterpret_cast<decltype(user_reply)>(lpOutBuffer);
        if (!user_reply) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        if (nOutBufferSize < minimum_reply_size) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        user_reply->length = static_cast<uint16_t>(nOutBufferSize);
        user_reply->id = user_request->id;
        *lpBytesReturned = user_reply->length;
    }

    result =
        ebpf_core_invoke_protocol_handler(request_id, user_request, user_reply, static_cast<uint16_t>(nOutBufferSize));

    if (result != EBPF_SUCCESS)
        goto Fail;

    return TRUE;

Fail:
    if (result != EBPF_SUCCESS) {
        switch (result) {
        case EBPF_NO_MEMORY:
            SetLastError(ERROR_OUTOFMEMORY);
            break;
        case EBPF_KEY_NOT_FOUND:
            SetLastError(ERROR_NOT_FOUND);
            break;
        case EBPF_INVALID_ARGUMENT:
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        case EBPF_NO_MORE_KEYS:
            SetLastError(ERROR_NO_MORE_ITEMS);
            break;
        case EBPF_INSUFFICIENT_BUFFER:
            SetLastError(ERROR_MORE_DATA);
            break;
        case EBPF_OBJECT_ALREADY_EXISTS:
            SetLastError(ERROR_OBJECT_ALREADY_EXISTS);
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        }
    }

    return FALSE;
}

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length)
{
    std::vector<uint8_t> packet(sizeof(ebpf::IPV4_HEADER) + sizeof(ebpf::UDP_HEADER));
    auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(packet.data());
    auto udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv4 + 1);

    ipv4->Protocol = 17;

    udp->length = udp_length;

    return packet;
}

#define SAMPLE_PATH ""

void
droppacket_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    const char* error_message = nullptr;
    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);
    fd_t port_map_fd = bpf_object__find_map_fd_by_name(object, "port_map");

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0);

    uint32_t key = 0;
    uint64_t value = 1000;
    REQUIRE(bpf_map_update_elem(port_map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 2);

    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 1001);

    REQUIRE(bpf_map_delete_elem(port_map_fd, &key) == EBPF_SUCCESS);

    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

    packet = prepare_udp_packet(10);
    xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

    REQUIRE(hook.fire(&ctx2, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 1);

    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

void
divide_by_zero_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    const char* error_message = nullptr;
    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "divide_by_zero.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    // uBPF returns -1 when the program hits a divide by zero error.
    REQUIRE(hook_result == -1);

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

uint32_t
get_bind_count_for_pid(fd_t map_fd, uint64_t pid)
{
    process_entry_t entry{};
    bpf_map_lookup_elem(map_fd, &pid, &entry);

    return entry.count;
}

bind_action_t
emulate_bind(single_instance_hook_t& hook, uint64_t pid, const char* appid)
{
    int result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.app_id_start = (uint8_t*)app_id.c_str();
    ctx.app_id_end = (uint8_t*)(app_id.c_str()) + app_id.size();
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_BIND;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    return static_cast<bind_action_t>(result);
}

void
emulate_unbind(single_instance_hook_t& hook, uint64_t pid, const char* appid)
{
    int result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_UNBIND;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
}

void
set_bind_limit(fd_t map_fd, uint32_t limit)
{
    uint32_t limit_key = 0;
    REQUIRE(bpf_map_update_elem(map_fd, &limit_key, &limit, EBPF_ANY) == EBPF_SUCCESS);
}

void
bindmonitor_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    uint64_t fake_pid = 12345;
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);
    fd_t limit_map_fd = bpf_object__find_map_fd_by_name(object, "limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    // Bind first port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Bind second port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Bind third port - blocked
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Unbind second port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Unbind first port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 0);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    fake_pid = 54321;
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    uint64_t pid;
    REQUIRE(bpf_map_get_next_key(process_map_fd, NULL, &pid) == EBPF_SUCCESS);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) == EBPF_SUCCESS);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) == -EBPF_NO_MORE_KEYS);

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

// //Associate to Flow

// int
// emulate_flow(single_instance_hook_t& hook, uint8_t protocol, const char* appid)
// {
//     uint32_t result;
//     std::string app_id = appid;
//     flow_md_t context{0};
//     context.app_name_start = (uint8_t*)app_id.c_str();
//     context.app_name_end = (uint8_t*)(app_id.c_str()) + app_id.size();
//     context.five_tuple = {};
//     context.five_tuple.protocol = protocol;
//     context.flow_established_flag = true;
//     REQUIRE(hook.fire(&context, &result) == EBPF_SUCCESS);
//     return static_cast<int>(result);
// }

// int
// emulate_flow_delete(single_instance_hook_t& hook, five_tuple_t five_tuple)
// {
//     uint32_t result;
//     flow_md_t context{0};
//     context.five_tuple = five_tuple;
//     context.flow_established_flag = false;
//     REQUIRE(hook.fire(&context, &result) == EBPF_SUCCESS);
//     return static_cast<int>(result);
// }

// uint8_t
// get_app_name(ebpf_handle_t handle, five_tuple_t key)
// {
//     app_name_t value{};
//     uint32_t result = ebpf_api_map_find_element(handle, sizeof(five_tuple_t), (uint8_t*)&key, sizeof(value), (uint8_t*)&value);
//     if (result != ERROR_SUCCESS) {
//         return 0;
//     }
//     return value.name[0];
// }


// void
// associatetoflow_test(ebpf_execution_type_t execution_type)
// {
//     _test_helper_end_to_end test_helper;

//     ebpf_handle_t program_handle;
//     const char* error_message = nullptr;
//     ebpf_handle_t map_handles[1];
//     uint32_t count_of_map_handles = 1;
//     uint32_t result;

//     uint8_t fake_protocol_1 = 0x11;
//     uint8_t fake_protocol_2 = 0x06;
//     // uint8_t fake_protocol_3 = 0xff;

//     five_tuple_t five_tuple_1 = {};
//     five_tuple_1.protocol = fake_protocol_1;
//     five_tuple_t five_tuple_2 = {};
//     five_tuple_2.protocol = fake_protocol_2;

//     program_info_provider_t flow_program_info(EBPF_PROGRAM_TYPE_FLOW);

//     REQUIRE(
//         (result = ebpf_api_load_program(
//              SAMPLE_PATH "associatetoflow.o",
//              "flow",
//              execution_type,
//              &program_handle,
//              &count_of_map_handles,
//              map_handles,
//              &error_message),
//          error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
//          ebpf_free_string(error_message),
//          error_message = nullptr,
//          result == EBPF_SUCCESS));

//     single_instance_hook_t hook(EBPF_PROGRAM_TYPE_FLOW, EBPF_ATTACH_TYPE_FLOW);

//     REQUIRE(hook.attach(program_handle) == EBPF_SUCCESS);

//     // Establish first flow - success
//     REQUIRE(emulate_flow(hook, fake_protocol_1, "1_fake_app") == 0);
//     REQUIRE(get_app_name(map_handles[0], five_tuple_1) == '1');

//     // Duplicate it
//     REQUIRE(emulate_flow(hook, fake_protocol_1, "1_fake_app") == 0);
//     REQUIRE(get_app_name(map_handles[0], five_tuple_1) == '1');

//     // Establish second flow - success
//     REQUIRE(emulate_flow(hook, fake_protocol_2, "2_fake_app") == 0);
//     REQUIRE(get_app_name(map_handles[0], five_tuple_2) == '2');

//     five_tuple_t key;
//     app_name_t app_name = {};

//     REQUIRE(
//         ebpf_api_get_next_map_key(map_handles[0], sizeof(five_tuple_t), NULL, reinterpret_cast<uint8_t*>(&key)) ==
//         EBPF_SUCCESS);
//     REQUIRE(key.protocol == 0x06);
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         EBPF_SUCCESS);
//     REQUIRE(key.protocol == 0x11);
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         ERROR_NO_MORE_ITEMS);

//     // Establish third flow - fail
//     // TODO

//     // Delete second flow
//     emulate_flow_delete(hook, five_tuple_2);
//     REQUIRE(get_app_name(map_handles[0], five_tuple_2) == 0);

//     // Delete first flow
//     emulate_flow_delete(hook, five_tuple_1);
//     REQUIRE(get_app_name(map_handles[0], five_tuple_1) == 0);

//     // All elements deleted from map
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         ERROR_NO_MORE_ITEMS);

//     hook.detach();
// }

// //Count Bytes
// std::vector<uint8_t>
// prepare_packet(uint8_t protocol, bool v4, uint16_t length)
// {
//     if (protocol == 0x11 && v4){
//         std::vector<uint8_t> packet(sizeof(ebpf::IPV4_HEADER) + sizeof(ebpf::UDP_HEADER));
//         auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(packet.data());
//         auto udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv4 + 1);
//         ipv4->Protocol = 17;
//         udp->length = length;
//         udp->destPort = 0;
//         udp->srcPort = 0;
//         return packet;
//     }
//     else if (protocol == 0x11 && !v4) {
//         std::vector<uint8_t> packet(sizeof(ebpf::IPV6_HEADER) + sizeof(ebpf::UDP_HEADER));
//         auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(packet.data());
//         auto udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv6 + 1);
//         ipv6->NextHeader = 17;
//         udp->length = length;
//         udp->destPort = 0;
//         udp->srcPort = 0;
//         return packet;
//     }
//     else if (protocol == 0x06 && v4) {
//         std::vector<uint8_t> packet(sizeof(ebpf::IPV4_HEADER) + sizeof(ebpf::TCP_HEADER));
//         auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(packet.data());
//         auto tcp = reinterpret_cast<ebpf::TCP_HEADER*>(ipv4 + 1);
//         ipv4->Protocol = 6;
//         tcp->destPort = 0;
//         tcp->srcPort = 0;
//         return packet;
//     }
//     else if (protocol == 0x06 && !v4) {
//         std::vector<uint8_t> packet(sizeof(ebpf::IPV6_HEADER) + sizeof(ebpf::TCP_HEADER));
//         auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(packet.data());
//         auto tcp = reinterpret_cast<ebpf::TCP_HEADER*>(ipv6 + 1);
//         ipv6->NextHeader = 6;
//         tcp->destPort = 0;
//         tcp->srcPort = 0;
//         return packet;
//     }
//     return std::vector<uint8_t>();
// }

// int
// emulate_mac(single_instance_hook_t& hook, uint16_t length, uint64_t packet_length, uint8_t protocol, bool v4)
// {
//     uint32_t result;
//     auto packet = prepare_packet(protocol, v4, length);
//     mac_md_t context = {packet.data(), packet.data() + packet.size(), packet_length, v4};
//     REQUIRE(hook.fire(&context, &result) == EBPF_SUCCESS);
//     return static_cast<int>(result);
// }

// void
// countbytes_test(ebpf_execution_type_t execution_type)
// {
//     _test_helper_end_to_end test_helper;

//     ebpf_handle_t program_handle;
//     const char* error_message = nullptr;
//     ebpf_handle_t map_handles[1];
//     uint32_t count_of_map_handles = 1;
//     uint32_t result;

//     program_info_provider_t mac_program_info(EBPF_PROGRAM_TYPE_MAC);

//     REQUIRE(
//         (result = ebpf_api_load_program(
//              SAMPLE_PATH "countbytes.o",
//              "mac",
//              execution_type,
//              &program_handle,
//              &count_of_map_handles,
//              map_handles,
//              &error_message),
//          error_message ? printf("ebpf_api_load_program failed with %s\n", error_message) : 0,
//          ebpf_free_string(error_message),
//          error_message = nullptr,
//          result == EBPF_SUCCESS));

//     single_instance_hook_t hook(EBPF_PROGRAM_TYPE_MAC, EBPF_ATTACH_TYPE_MAC);

//     REQUIRE(hook.attach(program_handle) == EBPF_SUCCESS);

//     // Send IPV4 UDP packet
//     uint64_t fake_length_1 = 100;
//     REQUIRE(emulate_mac(hook, 10, fake_length_1, 0x11, 1) == 0);
//     REQUIRE(result == 0);

//     // Send IPV4 TCP packet
//     uint64_t fake_length_2 = 200;
//     REQUIRE(emulate_mac(hook, 20, fake_length_2, 0x06, 1) == 0);
//     REQUIRE(result == 0);

//     // Send IPV6 UDP packet
//     uint64_t fake_length_3 = 300;
//     REQUIRE(emulate_mac(hook, 30, fake_length_3, 0x11, 0) == 0);
//     REQUIRE(result == 0);

//     // Send IPV6TCDP packet
//     uint64_t fake_length_4 = 400;
//     REQUIRE(emulate_mac(hook, 40, fake_length_4, 0x06, 0) == 0);
//     REQUIRE(result == 0);

//     five_tuple_t key;
//     uint64_t value;

//     REQUIRE(
//         ebpf_api_get_next_map_key(map_handles[0], sizeof(five_tuple_t), NULL, reinterpret_cast<uint8_t*>(&key)) ==
//         EBPF_SUCCESS);
//     REQUIRE(key.protocol == 0x06);
//     REQUIRE(key.dest_port == 0);
//     REQUIRE(key.source_port == 0);
//     REQUIRE(
//         ebpf_api_map_find_element(map_handles[0], sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
//         EBPF_SUCCESS);
//     REQUIRE(value == fake_length_4);
//     REQUIRE(key.dest_port == 0);
//     REQUIRE(key.source_port == 0);
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         EBPF_SUCCESS);
//     REQUIRE(key.protocol == 0x11);
//     REQUIRE(key.dest_port == 0);
//     REQUIRE(key.source_port == 0);
//     REQUIRE(
//         ebpf_api_map_find_element(map_handles[0], sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
//         EBPF_SUCCESS);
//     REQUIRE(value == fake_length_3);
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         EBPF_SUCCESS);
//     REQUIRE(key.protocol == 0x06);
//     REQUIRE(key.dest_port == 0);
//     REQUIRE(key.source_port == 0);
//     REQUIRE(
//         ebpf_api_map_find_element(map_handles[0], sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
//         EBPF_SUCCESS);
//     REQUIRE(value == fake_length_2);
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         EBPF_SUCCESS);
//     REQUIRE(key.protocol == 0x11);
//     REQUIRE(key.dest_port == 0);
//     REQUIRE(key.source_port == 0);
//     REQUIRE(
//         ebpf_api_map_find_element(map_handles[0], sizeof(key), (uint8_t*)&key, sizeof(value), (uint8_t*)&value) ==
//         EBPF_SUCCESS);
//     REQUIRE(value == fake_length_1);
//     REQUIRE(
//         ebpf_api_get_next_map_key(
//             map_handles[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key)) ==
//         ERROR_NO_MORE_ITEMS);

//     hook.detach();
// }

TEST_CASE("droppacket-jit", "[end_to_end]") { droppacket_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[end_to_end]") { divide_by_zero_test(EBPF_EXECUTION_JIT); }
TEST_CASE("bindmonitor-jit", "[end_to_end]") { bindmonitor_test(EBPF_EXECUTION_JIT); }
TEST_CASE("droppacket-interpret", "[end_to_end]") { droppacket_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("divide_by_zero_interpret", "[end_to_end]") { divide_by_zero_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("bindmonitor-interpret", "[end_to_end]") { bindmonitor_test(EBPF_EXECUTION_INTERPRET); }

// TEST_CASE("associatetoflow-jit", "[end_to_end]") { associatetoflow_test(EBPF_EXECUTION_JIT); }
// TEST_CASE("countbytes-jit", "[end_to_end]") { countbytes_test(EBPF_EXECUTION_JIT); }
// TEST_CASE("associatetoflow-interpret", "[end_to_end]") { associatetoflow_test(EBPF_EXECUTION_INTERPRET); }
// TEST_CASE("countbytes-interpret", "[end_to_end]") { countbytes_test(EBPF_EXECUTION_INTERPRET); }

TEST_CASE("enum section", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    const tlv_type_length_value_t* section_data = nullptr;
    uint32_t result;

    REQUIRE(
        (result =
             ebpf_api_elf_enumerate_sections(SAMPLE_PATH "droppacket.o", nullptr, true, &section_data, &error_message),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    for (auto current_section = tlv_child(section_data); current_section != tlv_next(section_data);
         current_section = tlv_next(current_section)) {
        auto section_name = tlv_child(current_section);
        auto type = tlv_next(section_name);
        auto map_count = tlv_next(type);
        auto program_bytes = tlv_next(map_count);
        auto stats_secton = tlv_next(program_bytes);

        REQUIRE(static_cast<tlv_type_t>(section_name->type) == tlv_type_t::STRING);
        REQUIRE(static_cast<tlv_type_t>(type->type) == tlv_type_t::STRING);
        REQUIRE(static_cast<tlv_type_t>(map_count->type) == tlv_type_t::UINT);
        REQUIRE(static_cast<tlv_type_t>(program_bytes->type) == tlv_type_t::BLOB);
        REQUIRE(static_cast<tlv_type_t>(stats_secton->type) == tlv_type_t::SEQUENCE);

        for (auto current_stat = tlv_child(stats_secton); current_stat != tlv_next(stats_secton);
             current_stat = tlv_next(current_stat)) {
            auto name = tlv_child(current_stat);
            auto value = tlv_next(name);
            REQUIRE(static_cast<tlv_type_t>(name->type) == tlv_type_t::STRING);
            REQUIRE(static_cast<tlv_type_t>(value->type) == tlv_type_t::UINT);
        }
    }
}

TEST_CASE("verify section", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;
    REQUIRE((
        result = ebpf_api_elf_verify_section(SAMPLE_PATH "droppacket.o", "xdp", false, &report, &error_message, &stats),
        ebpf_free_string(error_message),
        error_message = nullptr,
        result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
}

TEST_CASE("map_pinning_test", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    ebpf_result_t result;
    bpf_object* object = nullptr;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    std::string process_maps_name = "bindmonitor::process_map";
    std::string limit_maps_name = "bindmonitor::limits_map";

    REQUIRE(bpf_object__find_map_by_name(object, "process_map") != nullptr);
    REQUIRE(bpf_object__find_map_by_name(object, "limits_map") != nullptr);
    REQUIRE(
        bpf_map__pin(bpf_object__find_map_by_name(object, "process_map"), process_maps_name.c_str()) == EBPF_SUCCESS);
    REQUIRE(bpf_map__pin(bpf_object__find_map_by_name(object, "limits_map"), limit_maps_name.c_str()) == EBPF_SUCCESS);

    REQUIRE(ebpf_object_get(process_maps_name.c_str()) != ebpf_fd_invalid);

    REQUIRE(ebpf_object_get(limit_maps_name.c_str()) != ebpf_fd_invalid);

    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(object, "process_map"), process_maps_name.c_str()) == EBPF_SUCCESS);
    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(object, "limits_map"), limit_maps_name.c_str()) == EBPF_SUCCESS);

    REQUIRE(ebpf_object_get(limit_maps_name.c_str()) == ebpf_fd_invalid);

    REQUIRE(ebpf_object_get(process_maps_name.c_str()) == ebpf_fd_invalid);

    bpf_object__close(object);
}

TEST_CASE("enumerate_and_query_maps", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    fd_t map_fds[4] = {0};
    bpf_object* object;
    fd_t program_fd;
    uint32_t result;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    std::string process_maps_name = "process_map";
    std::string limit_maps_name = "limits_map";

    map_fds[0] = bpf_object__find_map_fd_by_name(object, process_maps_name.c_str());
    REQUIRE(map_fds[0] > 0);
    map_fds[1] = bpf_object__find_map_fd_by_name(object, limit_maps_name.c_str());
    REQUIRE(map_fds[1] > 0);

    fd_t fd_iterator = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_map(fd_iterator, &fd_iterator) == EBPF_SUCCESS);
    map_fds[2] = fd_iterator;
    REQUIRE(ebpf_get_next_map(fd_iterator, &fd_iterator) == EBPF_SUCCESS);
    map_fds[3] = fd_iterator;
    REQUIRE(ebpf_get_next_map(fd_iterator, &fd_iterator) == EBPF_SUCCESS);
    REQUIRE(fd_iterator == ebpf_fd_invalid);

    ebpf_map_definition_t map_definitions[_countof(map_fds)];
    ebpf_map_definition_t process_map = {
        sizeof(ebpf_map_definition_t), BPF_MAP_TYPE_HASH, sizeof(uint64_t), sizeof(process_entry_t), 1024};

    ebpf_map_definition_t limits_map = {
        sizeof(ebpf_map_definition_t), BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

    for (size_t index = 0; index < _countof(map_fds); index++) {
        REQUIRE(
            ebpf_map_query_definition(
                map_fds[index],
                &map_definitions[index].size,
                reinterpret_cast<uint32_t*>(&map_definitions[index].type),
                &map_definitions[index].key_size,
                &map_definitions[index].value_size,
                &map_definitions[index].max_entries,
                &map_definitions[index].inner_map_idx) == EBPF_SUCCESS);
        if (index % 2 == 0) {
            REQUIRE(memcmp(&process_map, &map_definitions[index], sizeof(process_map)) == 0);
        } else {
            REQUIRE(memcmp(&limits_map, &map_definitions[index], sizeof(process_map)) == 0);
        }
    }

    bpf_object__close(object);
}

TEST_CASE("enumerate_and_query_programs", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    fd_t program_fd;
    fd_t next_program_fd;
    const char* error_message = nullptr;
    ebpf_result_t result;
    const char* file_name = nullptr;
    const char* section_name = nullptr;
    bpf_object* object[2] = {0};
    fd_t program_fds[2] = {0};

    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object[0], &program_fds[0], &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        nullptr,
        nullptr,
        EBPF_EXECUTION_INTERPRET,
        &object[1],
        &program_fds[1],
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    ebpf_execution_type_t type;
    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &next_program_fd) == EBPF_SUCCESS);
    REQUIRE(next_program_fd != ebpf_fd_invalid);
    program_fd = next_program_fd;
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    REQUIRE(type == EBPF_EXECUTION_JIT);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    ebpf_free_string(file_name);
    file_name = nullptr;
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_free_string(section_name);
    section_name = nullptr;

    REQUIRE(ebpf_get_next_program(program_fd, &next_program_fd) == EBPF_SUCCESS);
    REQUIRE(next_program_fd != ebpf_fd_invalid);
    ebpf_close_fd(program_fd);
    program_fd = next_program_fd;
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    REQUIRE(type == EBPF_EXECUTION_INTERPRET);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_free_string(file_name);
    ebpf_free_string(section_name);
    file_name = nullptr;
    section_name = nullptr;

    REQUIRE(ebpf_get_next_program(program_fd, &next_program_fd) == EBPF_SUCCESS);
    REQUIRE(next_program_fd == ebpf_fd_invalid);
    ebpf_close_fd(program_fd);

    for (int i = 0; i < _countof(object); i++) {
        bpf_object__close(object[i]);
    }
}

TEST_CASE("pinned_map_enum", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    ebpf_test_pinned_map_enum();
}

TEST_CASE("implicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close program handle. An implicit detach should happen and program
    //    object should be deleted.
    // 2. Close link handle. The link object should be deleted.

    _test_helper_end_to_end test_helper;

    uint32_t result = 0;
    bpf_object* object = nullptr;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(object);

    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);

    // Close link handle (without detaching). This should delete the link
    // object. ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.close_link(link);
}

TEST_CASE("explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Call detach API and then close the link handle. The link onject
    //    should be deleted.
    // 2. Close program handle. The program object should be deleted.

    _test_helper_end_to_end test_helper;

    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link = nullptr;
    ebpf_result_t result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_link(link);
    hook.close_link(link);

    // Close program handle.
    bpf_object__close(object);
    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);
}

TEST_CASE("implicit_explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close the program handle so that an implicit detach happens.
    // 2. Explicitly call detach and then close the link handle. Explicit
    //    detach in this step should be a no-op.

    _test_helper_end_to_end test_helper;

    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link = nullptr;
    ebpf_result_t result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    // Close program handle. That should detach the program from the hook
    // and unload the program.
    bpf_object__close(object);
    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_link(link);
    hook.close_link(link);
}

TEST_CASE("create_map", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;

    result = ebpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t), 5, 0, &map_fd);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(map_fd > 0);

    for (int i = 0; i < element_count; i++) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);
        key++;
        value++;
    }

    key = 0;
    value = 10;
    for (int i = 0; i < element_count; i++) {
        uint64_t read_value;
        REQUIRE(bpf_map_lookup_elem(map_fd, &key, &read_value) == EBPF_SUCCESS);
        REQUIRE(read_value == value);
        key++;
        value++;
    }
}

TEST_CASE("create_map_name", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;
    const char* map_name = "array_map";

    result = ebpf_create_map_name(BPF_MAP_TYPE_ARRAY, map_name, sizeof(uint32_t), sizeof(uint64_t), 5, 0, &map_fd);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(map_fd > 0);

    for (int i = 0; i < element_count; i++) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);
        key++;
        value++;
    }

    key = 0;
    value = 10;
    for (int i = 0; i < element_count; i++) {
        uint64_t read_value;
        REQUIRE(bpf_map_lookup_elem(map_fd, &key, &read_value) == EBPF_SUCCESS);
        REQUIRE(read_value == value);
        key++;
        value++;
    }
}
