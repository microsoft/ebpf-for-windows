// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This module facilitates testing various socket related eBPF program types and hooks.
 */

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_nethooks.h"
#include "ebpf_structs.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "socket_helper.h"
#include "socket_tests_common.h"
#include "watchdog.h"

#include <chrono>
#include <future>
#include <iostream>
using namespace std::chrono_literals;
#include <mstcpip.h>

CATCH_REGISTER_LISTENER(_watchdog)

#define MULTIPLE_ATTACH_PROGRAM_COUNT 3

thread_local bool _is_main_thread = false;

void
connection_test(
    ADDRESS_FAMILY address_family,
    _Inout_ client_socket_t& sender_socket,
    _Inout_ receiver_socket_t& receiver_socket,
    uint32_t protocol)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr");

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);
    const char* connect_program_name = (address_family == AF_INET) ? "authorize_connect4" : "authorize_connect6";
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);

    const char* recv_accept_program_name =
        (address_family == AF_INET) ? "authorize_recv_accept4" : "authorize_recv_accept6";
    bpf_program* recv_accept_program = bpf_object__find_program_by_name(object, recv_accept_program_name);
    SAFE_REQUIRE(recv_accept_program != nullptr);

    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;
    sender_socket.get_local_address(local_address, local_address_length);

    connection_tuple_t tuple = {0};
    if (address_family == AF_INET) {
        tuple.remote_ip.ipv4 = htonl(INADDR_LOOPBACK);
        printf("tuple.remote_ip.ipv4 = %x\n", tuple.remote_ip.ipv4);
    } else {
        memcpy(tuple.remote_ip.ipv6, &in6addr_loopback, sizeof(tuple.remote_ip.ipv6));
    }
    tuple.remote_port = htons(SOCKET_TEST_PORT);
    printf("tuple.remote_port = %x\n", tuple.remote_port);
    tuple.protocol = protocol;

    bpf_map* ingress_connection_policy_map = bpf_object__find_map_by_name(object, "ingress_connection_policy_map");
    SAFE_REQUIRE(ingress_connection_policy_map != nullptr);
    bpf_map* egress_connection_policy_map = bpf_object__find_map_by_name(object, "egress_connection_policy_map");
    SAFE_REQUIRE(egress_connection_policy_map != nullptr);

    // Update ingress and egress policy to block loopback packet on test port.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT.
    bpf_attach_type connect_attach_type =
        (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;
    int result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program)), 0, connect_attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);

    // The packet should be blocked by the connect program.
    receiver_socket.complete_async_receive(true);
    // Cancel send operation.
    sender_socket.cancel_send_message();

    // Update egress policy to allow packet.
    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Attach the receive/accept program at BPF_CGROUP_INET4_RECV_ACCEPT.
    bpf_attach_type recv_accept_attach_type =
        (address_family == AF_INET) ? BPF_CGROUP_INET4_RECV_ACCEPT : BPF_CGROUP_INET6_RECV_ACCEPT;
    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept_program)), 0, recv_accept_attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Resend the packet. This time, it should be dropped by the receive/accept program.
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    receiver_socket.complete_async_receive(true);
    // Cancel send operation.
    sender_socket.cancel_send_message();

    // Update ingress policy to allow packet.
    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Resend the packet. This time, it should be allowed by both the programs and the packet should reach loopback the
    // destination.
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    receiver_socket.complete_async_receive();
}

TEST_CASE("connection_test_udp_v4", "[sock_addr_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP);
}
TEST_CASE("connection_test_udp_v6", "[sock_addr_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP);
}

TEST_CASE("connection_test_tcp_v4", "[sock_addr_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP);
}
TEST_CASE("connection_test_tcp_v6", "[sock_addr_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP);
}

TEST_CASE("attach_sock_addr_programs", "[sock_addr_tests]")
{
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);

    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr");

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* connect4_program = bpf_object__find_program_by_name(object, "authorize_connect4");
    SAFE_REQUIRE(connect4_program != nullptr);

    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_CONNECT,
        0);
    SAFE_REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    SAFE_REQUIRE(program_info.link_count == 1);
    SAFE_REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach(UNSPECIFIED_COMPARTMENT_ID, BPF_CGROUP_INET4_CONNECT);
    SAFE_REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    SAFE_REQUIRE(program_info.link_count == 0);

    bpf_program* recv_accept4_program = bpf_object__find_program_by_name(object, "authorize_recv_accept4");
    SAFE_REQUIRE(recv_accept4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT,
        0);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    SAFE_REQUIRE(program_info.link_count == 1);
    SAFE_REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach2(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    SAFE_REQUIRE(program_info.link_count == 0);

    bpf_program* connect6_program = bpf_object__find_program_by_name(object, "authorize_connect6");
    SAFE_REQUIRE(connect6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_CONNECT,
        0);
    SAFE_REQUIRE(result == 0);

    bpf_program* recv_accept6_program = bpf_object__find_program_by_name(object, "authorize_recv_accept6");
    SAFE_REQUIRE(recv_accept6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_RECV_ACCEPT,
        0);
    SAFE_REQUIRE(result == 0);
}

void
connection_monitor_test(
    ADDRESS_FAMILY address_family,
    _Inout_ client_socket_t& sender_socket,
    _Inout_ receiver_socket_t& receiver_socket,
    uint32_t protocol,
    bool disconnect)
{
    native_module_helper_t helper;
    helper.initialize("sockops");
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Ring buffer event callback context.
    std::unique_ptr<ring_buffer_test_event_context_t> context = std::make_unique<ring_buffer_test_event_context_t>();
    context->test_event_count = disconnect ? 4 : 2;

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    SAFE_REQUIRE(_program != nullptr);

    uint64_t process_id = get_current_pid_tgid();
    // Ignore the thread Id.
    process_id >>= 32;

    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;
    sender_socket.get_local_address(local_address, local_address_length);

    connection_tuple_t tuple{}, reverse_tuple{};
    if (address_family == AF_INET) {
        tuple.local_ip.ipv4 = htonl(INADDR_LOOPBACK);
        tuple.remote_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(tuple.local_ip.ipv6, &in6addr_loopback, sizeof(tuple.local_ip.ipv6));
        memcpy(tuple.remote_ip.ipv6, &in6addr_loopback, sizeof(tuple.local_ip.ipv6));
    }
    tuple.local_port = INETADDR_PORT(local_address);
    tuple.remote_port = htons(SOCKET_TEST_PORT);
    tuple.protocol = protocol;
    NET_LUID net_luid = {};
    net_luid.Info.IfType = IF_TYPE_SOFTWARE_LOOPBACK;
    tuple.interface_luid = net_luid.Value;

    reverse_tuple.local_ip = tuple.remote_ip;
    reverse_tuple.remote_ip = tuple.local_ip;
    reverse_tuple.local_port = tuple.remote_port;
    reverse_tuple.remote_port = tuple.local_port;
    reverse_tuple.protocol = tuple.protocol;
    reverse_tuple.interface_luid = tuple.interface_luid;

    std::vector<std::vector<char>> audit_entry_list;
    audit_entry_t audit_entries[4] = {0};

    // Connect outbound.
    audit_entries[0].tuple = tuple;
    audit_entries[0].process_id = process_id;
    audit_entries[0].connected = true;
    audit_entries[0].outbound = true;
    char* p = reinterpret_cast<char*>(&audit_entries[0]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Connect inbound.
    audit_entries[1].tuple = reverse_tuple;
    audit_entries[1].process_id = process_id;
    audit_entries[1].connected = true;
    audit_entries[1].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[1]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create an audit entry for the disconnect case.
    // The direction bit is set to false.
    audit_entries[2].tuple = tuple;
    audit_entries[2].process_id = process_id;
    audit_entries[2].connected = false;
    audit_entries[2].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[2]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create another audit entry for the disconnect event with the reverse packet tuple.
    audit_entries[3].tuple = reverse_tuple;
    audit_entries[3].process_id = process_id;
    audit_entries[3].connected = false;
    audit_entries[3].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[3]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    context->records = &audit_entry_list;

    // Get the std::future from the promise field in ring buffer event context, which should be in ready state
    // once notifications for all events are received.
    auto ring_buffer_event_callback = context->ring_buffer_event_promise.get_future();

    // Create a new ring buffer manager and subscribe to ring buffer events.
    bpf_map* ring_buffer_map = bpf_object__find_map_by_name(object, "audit_map");
    SAFE_REQUIRE(ring_buffer_map != nullptr);
    context->ring_buffer = ring_buffer__new(
        bpf_map__fd(ring_buffer_map), (ring_buffer_sample_fn)ring_buffer_test_event_handler, context.get(), nullptr);
    SAFE_REQUIRE(context->ring_buffer != nullptr);

    bpf_map* connection_map = bpf_object__find_map_by_name(object, "connection_map");
    SAFE_REQUIRE(connection_map != nullptr);

    // Update connection map with loopback packet tuples.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &tuple, &verdict, EBPF_ANY) == 0);
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &reverse_tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the sockops program.
    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    SAFE_REQUIRE(result == 0);

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    // Receive the packet on test port.
    receiver_socket.complete_async_receive();

    if (disconnect) {
        sender_socket.close();
        receiver_socket.close();
    }

    // Wait for event handler getting notifications for all connection audit events.
    SAFE_REQUIRE(ring_buffer_event_callback.wait_for(1s) == std::future_status::ready);

    // Mark the event context as canceled, such that the event callback stops processing events.
    context->canceled = true;

    // Release the raw pointer such that the final callback frees the callback context.
    ring_buffer_test_event_context_t* raw_context = context.release();

    // Unsubscribe.
    raw_context->unsubscribe();
}

TEST_CASE("connection_monitor_test_udp_v4", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, false);
}
TEST_CASE("connection_monitor_test_disconnect_udp_v4", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, true);
}

TEST_CASE("connection_monitor_test_udp_v6", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, false);
}
TEST_CASE("connection_monitor_test_disconnect_udp_v6", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, true);
}

TEST_CASE("connection_monitor_test_tcp_v4", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP, false);
}
TEST_CASE("connection_monitor_test_disconnect_tcp_v4", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP, true);
}

TEST_CASE("connection_monitor_test_tcp_v6", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP, false);
}
TEST_CASE("connection_monitor_test_disconnect_tcp_v6", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP, true);
}

TEST_CASE("attach_sockops_programs", "[sock_ops_tests]")
{
    native_module_helper_t helper;
    helper.initialize("sockops");
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    SAFE_REQUIRE(_program != nullptr);

    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    SAFE_REQUIRE(result == 0);
}

// This function populates map polcies for multi-attach tests.
// It assumes that the destination and proxy are loopback addresses.
static void
_update_map_entry_multi_attach(
    fd_t map_fd,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    bool add)
{
    destination_entry_key_t key = {0};
    destination_entry_value_t value = {0};

    if (address_family == AF_INET) {
        key.destination_ip.ipv4 = htonl(INADDR_LOOPBACK);
        value.destination_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(key.destination_ip.ipv6, &in6addr_loopback, sizeof(key.destination_ip.ipv6));
        memcpy(value.destination_ip.ipv6, &in6addr_loopback, sizeof(value.destination_ip.ipv6));
    }
    key.destination_port = destination_port;
    key.protocol = protocol;
    value.destination_port = proxy_port;

    if (add) {
        SAFE_REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        bpf_map_delete_elem(map_fd, &key);
    }
}

typedef enum _connection_result
{
    RESULT_ALLOW,
    RESULT_DROP,
    RESULT_DONT_CARE
} connection_result_t;

void
get_client_socket(socket_family_t family, uint16_t protocol, _Inout_ client_socket_t** sender_socket)
{
    client_socket_t* old_socket = *sender_socket;
    client_socket_t* new_socket = nullptr;
    if (protocol == IPPROTO_TCP) {
        new_socket = (client_socket_t*)new stream_client_socket_t(SOCK_STREAM, IPPROTO_TCP, 0, family);
    } else {
        new_socket = (client_socket_t*)new datagram_client_socket_t(SOCK_DGRAM, IPPROTO_UDP, 0, family);
    }

    *sender_socket = new_socket;
    if (old_socket) {
        delete old_socket;
    }
}

void
validate_connection_multi_attach(
    socket_family_t family,
    ADDRESS_FAMILY address_family,
    uint16_t receiver_port,
    uint16_t destination_port,
    uint16_t protocol,
    connection_result_t expected_result)
{
    client_socket_t* sender_socket = nullptr;
    receiver_socket_t* receiver_socket = nullptr;

    if (protocol == IPPROTO_UDP) {
        receiver_socket = new datagram_server_socket_t(SOCK_DGRAM, IPPROTO_UDP, receiver_port);
    } else if (protocol == IPPROTO_TCP) {
        receiver_socket = new stream_server_socket_t(SOCK_STREAM, IPPROTO_TCP, receiver_port);
    } else {
        SAFE_REQUIRE(false);
    }
    get_client_socket(family, protocol, &sender_socket);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket->post_async_receive();

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        if (family == socket_family_t::Dual) {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        } else {
            IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&destination_address);
        }
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }

    sender_socket->send_message_to_remote_host(message, destination_address, destination_port);

    if (expected_result == RESULT_DROP) {
        // The packet should be blocked.
        receiver_socket->complete_async_receive(true);
        // Cancel send operation.
        sender_socket->cancel_send_message();
    } else if (expected_result == RESULT_ALLOW) {
        // The packet should be allowed by the connect program.
        receiver_socket->complete_async_receive();
    } else {
        // The result is not deterministic, so we don't care about the result.
        receiver_socket->complete_async_receive(1000, receiver_socket_t::MODE_DONT_CARE);
    }

    delete sender_socket;
    delete receiver_socket;
}

void
multi_attach_test_common(
    bpf_object* object,
    socket_family_t family,
    ADDRESS_FAMILY address_family,
    uint32_t compartment_id,
    uint16_t protocol,
    bool detach_program)
{
    // This function assumes that all the attached programs already allow the connection.
    // It then proceeds to test the following:
    // 1. For the provided program object, update policy map to block the connection
    //    and validate that the connection is blocked.
    // 2. Revert the policy to allow the connection, validate that the connection is now allowed.
    //
    // Along with the above, if "detach_program" is true, the function will also test the following:
    // 1. Update policy map to block the connection, validate that the connection is blocked.
    // 2. Detach the program, validate that the connection should now be allowed.
    // 3. Re-attach the program, and validate that the connection is again blocked.
    // 4. Update policy map to allow the connection, validate that the connection is allowed.

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Deleting the map entry will result in the program blocking the connection.
    _update_map_entry_multi_attach(
        map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, false);

    // The packet should be blocked.
    validate_connection_multi_attach(family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

    // Revert the policy to "allow" the connection.
    _update_map_entry_multi_attach(
        map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, true);

    // The packet should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

    if (detach_program) {
        // Block the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, false);

        // The packet should be blocked.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

        // Detach the program.
        int result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, attach_type);
        SAFE_REQUIRE(result == 0);

        // The packet should now be allowed.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

        // Re-attach the program.
        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);

        // The packet should be blocked.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

        // Update the policy to "allow" the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, true);

        // The packet should now be allowed.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);
    }
}

void
multi_attach_test(uint32_t compartment_id, socket_family_t family, ADDRESS_FAMILY address_family, uint16_t protocol)
{
    // This test is to verify that multiple programs can be attached to the same hook, and they work as expected.
    // Scenarios covered:
    // 1. Multiple programs attached to the same hook.
    // 2. For multiple programs attached to same hook, validate the order of execution.
    // 3. For multiple programs attached to same hook, validate the verdict based on the order of execution.
    // 4. Programs attached to different hooks -- only one should be invoked.

    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2");
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";

    // Attach all the programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);
    }

    // Configure policy maps for all programs to "allow" the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
        SAFE_REQUIRE(policy_map != nullptr);
        fd_t map_fd = bpf_map__fd(policy_map);
        SAFE_REQUIRE(map_fd != ebpf_fd_invalid);
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, true);
    }

    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

    // Test that the connection is blocked if any of the programs block the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        multi_attach_test_common(objects[i], family, address_family, compartment_id, protocol, false);
    }

    // Next section tests detach and re-attach of programs.
    // Current attach order is 0 --> 1 --> 2. Detach "first" program and check if the verdict changes.
    multi_attach_test_common(objects[0], family, address_family, compartment_id, protocol, true);

    // Now the program attach order is 1 --> 2 --> 0. Repeat detach / reattach with the "middle" program.
    multi_attach_test_common(objects[2], family, address_family, compartment_id, protocol, true);

    // Now the program attach order is 1 --> 0 --> 2. Repeat it with the "last" program.
    multi_attach_test_common(objects[2], family, address_family, compartment_id, protocol, true);

    // Now attach a 4th program to different compartment. It should not get invoked, and its verdict should not affect
    // the connection.
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2");
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);

    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT / BPF_CGROUP_INET6_CONNECT.
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id + 2, attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Not updating policy map for this program should mean that this program (if invoked) will block the connection.
    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);
}

void
multi_attach_test_redirection(
    socket_family_t family, ADDRESS_FAMILY address_family, uint32_t compartment_id, uint16_t protocol)
{
    // This test validates combination of redirection and other program verdicts.
    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    uint16_t proxy_port = SOCKET_TEST_PORT;
    uint16_t destination_port = proxy_port - 1;
    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load 3 programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2");
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    // Attach all the 3 programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);
    }

    // Lambda function to update the policy map entry, and validate the connection.
    auto validate_program_redirection = [&](uint32_t program_index) {
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            // Configure ith program to redirect the connection. Configure all other programs to "allow" the connection.
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            if (i != program_index) {
                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
            } else {
                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(destination_port), htons(proxy_port), protocol, true);
            }
        }

        // Validate that the connection is successfully redirected.
        validate_connection_multi_attach(family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

        if (program_index > 0) {
            // If this is not the first program, configure the preceding program to block the connection.
            // That should result in the connection being blocked.
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[program_index - 1], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);

            // Validate that the connection is blocked.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_DROP);

            // Now detach the preceding program, and validate that the connection is allowed.
            bpf_program* connect_program =
                bpf_object__find_program_by_name(objects[program_index - 1], connect_program_name);
            SAFE_REQUIRE(connect_program != nullptr);

            int result = bpf_prog_detach2(
                bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type);
            SAFE_REQUIRE(result == 0);

            // The connection should now be allowed.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Revert the policy to allow the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
        }

        // Reset the whole state by detaching and re-attaching all the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], connect_program_name);
            SAFE_REQUIRE(program != nullptr);
            bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, attach_type);
        }

        // Re-attach the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], connect_program_name);
            SAFE_REQUIRE(program != nullptr);
            int result = bpf_prog_attach(
                bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, attach_type, 0);
            SAFE_REQUIRE(result == 0);
        }

        // Validate that the connection is again allowed.
        validate_connection_multi_attach(family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

        if (program_index < MULTIPLE_ATTACH_PROGRAM_COUNT - 1) {
            // If this is not the last program, configure the following program to block the connection.
            // That should result in the connection still be redirected.

            bpf_map* policy_map = bpf_object__find_map_by_name(objects[program_index + 1], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);

            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            // Delete the map entry to block the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);

            // Validate that the connection is still redirected.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Next configure the last program to redirect the connection to proxy_port + 1.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port + 1), protocol, true);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(proxy_port + 1), protocol, true);

            // Validate that the connection is not redirected to proxy_port + 1. This is because the connection is
            // already redirected by the previous program.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Revert the policy to allow the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

            // Validate that the connection is allowed.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);
        }
    };

    // For each program, detach and re-attach it, and validate the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        validate_program_redirection(i);
    }
}

TEST_CASE("multi_attach_test_TCP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    multi_attach_test(compartment_id, socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_TCP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    multi_attach_test(compartment_id, socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_UDP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    multi_attach_test(compartment_id, socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_UDP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    multi_attach_test(compartment_id, socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_wildcard_TCP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_wildcard_TCP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_wildcard_UDP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_wildcard_UDP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

typedef enum _program_action
{
    ACTION_ALLOW,
    ACTION_REDIRECT,
    ACTION_BLOCK,
    ACTION_MAX,
} program_action_t;

void
multi_attach_configure_map(
    bpf_object* object,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    program_action_t action)
{
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    if (action == ACTION_ALLOW) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

        _update_map_entry_multi_attach(map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
    } else if (action == ACTION_REDIRECT) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(proxy_port), protocol, true);
    } else if (action == ACTION_BLOCK) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

        _update_map_entry_multi_attach(map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);
    } else {
        SAFE_REQUIRE(false);
    }
}

static program_action_t
_multi_attach_get_combined_verdict(program_action_t* actions, uint32_t count)
{
    SAFE_REQUIRE(count % 2 == 0);

    for (uint32_t i = 0; i < count; i++) {
        if (actions[i] == ACTION_BLOCK) {
            return ACTION_BLOCK;
        } else if (actions[i] == ACTION_REDIRECT) {
            return ACTION_REDIRECT;
        }
    }
    return ACTION_ALLOW;
}

void
test_multi_attach_combined(socket_family_t family, ADDRESS_FAMILY address_family, uint16_t protocol)
{
    // This test case loads and attaches program_count_per_hook * 2 programs:
    // program_count_per_hook programs with specific compartment id, and
    // program_count_per_hook programs with wildcard compartment id.
    // Then the test case iterates over all the possible combinations of program actions (allow, redirect, block) for
    // each program, and validates the connection based on the expected result.

    constexpr uint32_t program_count_per_hook = 2;
    native_module_helper_t helpers[program_count_per_hook * 2];
    struct bpf_object* objects[program_count_per_hook * 2] = {nullptr};
    bpf_object_ptr object_ptrs[program_count_per_hook * 2];
    program_action_t actions[program_count_per_hook * 2] = {ACTION_ALLOW};
    uint16_t proxy_port = SOCKET_TEST_PORT;
    uint16_t destination_port = proxy_port - 1;
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the programs.
    for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
        helpers[i].initialize("cgroup_sock_addr2");
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";

    // Attach all the programs.
    for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
            i < program_count_per_hook ? 1 : UNSPECIFIED_COMPARTMENT_ID,
            attach_type,
            0);
        SAFE_REQUIRE(result == 0);
    }

    // This loop will iterate over all the possible combinations of program actions for each program.
    while (true) {
        // Configure program actions.
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            multi_attach_configure_map(objects[i], address_family, destination_port, proxy_port, protocol, actions[i]);
        }

        program_action_t expected_action = _multi_attach_get_combined_verdict(actions, program_count_per_hook * 2);

        // Validate the connection based on the expected action.
        switch (expected_action) {
        case ACTION_ALLOW:
            validate_connection_multi_attach(
                family, address_family, destination_port, destination_port, protocol, RESULT_ALLOW);
            break;
        case ACTION_REDIRECT:
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);
            break;
        case ACTION_BLOCK:
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_DROP);
            break;
        default:
            SAFE_REQUIRE(false);
        }

        // Increment the program actions.
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            actions[i] = static_cast<program_action_t>(actions[i] + 1);
            if (actions[i] == ACTION_MAX) {
                actions[i] = ACTION_ALLOW;
            } else {
                break;
            }
        }

        // Print the program actions.
        printf("Program actions: ");
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            printf("%d ", actions[i]);
        }
        printf("\n");

        // Break if all the program actions are ACTION_BLOCK.
        bool should_break = true;
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            if (actions[i] != ACTION_BLOCK) {
                should_break = false;
                break;
            }
        }

        if (should_break) {
            break;
        }
    }
}

TEST_CASE("multi_attach_test_combined_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    test_multi_attach_combined(socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_combined_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    test_multi_attach_combined(socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_combined_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    test_multi_attach_combined(socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_combined_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    test_multi_attach_combined(socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, compartment_id, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, compartment_id, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, compartment_id, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, compartment_id, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, compartment_id, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, compartment_id, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, compartment_id, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, compartment_id, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_invocation_order", "[sock_addr_tests][multi_attach_tests]")
{
    // This test case validates that a program attached with specific compartment id is always invoked before a
    // program attached with wildcard compartment id, irrespective of the order of attachment.

    int result = 0;
    native_module_helper_t native_helpers_specific;
    native_module_helper_t native_helpers_wildcard;
    native_helpers_specific.initialize("cgroup_sock_addr2");
    native_helpers_wildcard.initialize("cgroup_sock_addr2");
    socket_family_t family = socket_family_t::Dual;
    ADDRESS_FAMILY address_family = AF_INET;
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    struct bpf_object* object_specific = bpf_object__open(native_helpers_specific.get_file_name().c_str());
    SAFE_REQUIRE(object_specific != nullptr);
    bpf_object_ptr object_specific_ptr(object_specific);

    struct bpf_object* object_wildcard = bpf_object__open(native_helpers_wildcard.get_file_name().c_str());
    SAFE_REQUIRE(object_wildcard != nullptr);
    bpf_object_ptr object_wildcard_ptr(object_wildcard);

    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object_specific) == 0);
    SAFE_REQUIRE(bpf_object__load(object_wildcard) == 0);

    bpf_program* connect_program_specific = bpf_object__find_program_by_name(object_specific, "connect_redirect4");
    SAFE_REQUIRE(connect_program_specific != nullptr);

    bpf_program* connect_program_wildcard = bpf_object__find_program_by_name(object_wildcard, "connect_redirect4");
    SAFE_REQUIRE(connect_program_wildcard != nullptr);

    // Attach the program with specific compartment id first.
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Attach the program with wildcard compartment id next.
    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program_wildcard)),
        UNSPECIFIED_COMPARTMENT_ID,
        attach_type,
        0);
    SAFE_REQUIRE(result == 0);

    // First configure both the programs to allow the connection.
    bpf_map* policy_map_specific = bpf_object__find_map_by_name(object_specific, "policy_map");
    SAFE_REQUIRE(policy_map_specific != nullptr);

    fd_t map_fd_specific = bpf_map__fd(policy_map_specific);
    SAFE_REQUIRE(map_fd_specific != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    bpf_map* policy_map_wildcard = bpf_object__find_map_by_name(object_wildcard, "policy_map");
    SAFE_REQUIRE(policy_map_wildcard != nullptr);

    fd_t map_fd_wildcard = bpf_map__fd(policy_map_wildcard);
    SAFE_REQUIRE(map_fd_wildcard != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the program with specific compartment id to block the connection.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // The connection should be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // The connection should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the program with wildcard compartment id to block the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // The connection should be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // The connection should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the specific program to redirect the connection.
    uint16_t destination_port = SOCKET_TEST_PORT - 1;
    // uint16_t proxy_port = destination_port + 1;

    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is redirected to the final port.
    // The order of attach and invocation should be: specific --> wildcard.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure blocking rule for wildcard program.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // Validate that the connection is still redirected to the final port.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Now detach the program with specific compartment id.
    result =
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type);

    // The connection should now be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_DROP);

    // Re-attach the program with specific compartment id.
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type, 0);

    // The connection should be allowed. This validates that the program with specific compartment id is always
    // invoked before the program with wildcard compartment id.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure allow rule for specific program and redirect rule for wildcard program.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, true);

    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(destination_port), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is redirected to the final port.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Block the connection for specific program.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, false);

    // Validate that the connection is now blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_DROP);

    // Detach the program with specific compartment id.
    result =
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type);
    SAFE_REQUIRE(result == 0);

    // Since the specific program is now detached, the connection should be correctly redirected by wildcard program.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);
}

/**
 * @brief This function sends messages to the receiver port in a loop using UDP socket.
 *
 * @param token Stop token to stop the thread.
 * @param address_family Address family to use.
 * @param receiver_port Port to send the message to.
 */
void
thread_function_invoke_connection(std::stop_token token, ADDRESS_FAMILY address_family, uint16_t receiver_port)
{
    uint32_t count = 0;

    while (!token.stop_requested()) {
        datagram_client_socket_t sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);

        // Send loopback message to test port.
        const char* message = CLIENT_MESSAGE;
        sockaddr_storage destination_address{};
        if (address_family == AF_INET) {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        } else {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        }

        sender_socket.send_message_to_remote_host(message, destination_address, receiver_port);

        count++;
    }

    std::cout << "Thread (invoke_connection)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
thread_function_attach_detach(std::stop_token token, uint32_t compartment_id, uint16_t destination_port)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2");
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);
    uint32_t count = 0;
    ADDRESS_FAMILY address_family = AF_INET;

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the program.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Configure policy map to allow the connection (TCP and UDP).
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, true);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), IPPROTO_UDP, true);

    while (!token.stop_requested()) {
        // Attach and detach the program in a loop.
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, attach_type);
        SAFE_REQUIRE(result == 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        count++;
    }

    std::cout << "Thread (attach_detach)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
thread_function_allow_block_connection(
    std::stop_token token,
    ADDRESS_FAMILY address_family,
    uint16_t protocol,
    uint16_t destination_port,
    uint32_t compartment_id)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2");
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);
    uint32_t count = 0;
    socket_family_t family = socket_family_t::Dual;

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the program.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Attach the program at BPF_CGROUP_INET4_CONNECT / BPF_CGROUP_INET6_CONNECT.
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);

    SAFE_REQUIRE(result == 0);

    // Configure policy map to allow the connection.
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    // Since the default policy is to block the connection, update the policy map to allow the connection for the
    // "other" protocol. This will ensure this program does not interfere with the connections for the second thread
    // that is also running in parallel.
    _update_map_entry_multi_attach(
        map_fd,
        address_family,
        htons(destination_port),
        htons(destination_port),
        (uint16_t)(protocol == IPPROTO_TCP ? IPPROTO_UDP : IPPROTO_TCP),
        true);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

    while (!token.stop_requested()) {
        // Block the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

        // The connection should be blocked. Due to race, it can sometimes be allowed, so we don't care about the
        // result.
        validate_connection_multi_attach(
            family, address_family, destination_port, destination_port, protocol, RESULT_DONT_CARE);

        // Allow the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

        // The connection should be allowed. Due to race, it can sometimes be blocked, so we don't care about the
        // result.
        validate_connection_multi_attach(
            family, address_family, destination_port, destination_port, protocol, RESULT_DONT_CARE);

        count++;
    }

    std::cout << "Thread (allow_block)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
multi_attach_test_thread_function1(
    std::stop_token token,
    uint32_t index,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    std::atomic<bool>& failed)
{
    // Get the mode.
    uint32_t mode = index % 7;
    uint32_t default_compartment = 1;
    uint32_t unspecified_compartment = 0;

    try {
        switch (mode) {
        case 0:
            __fallthrough;
            // break;
        case 1:
            thread_function_invoke_connection(token, address_family, destination_port);
            break;
        case 2:
            thread_function_attach_detach(token, unspecified_compartment, destination_port);
            break;
        case 3:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 4:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 5:
            thread_function_allow_block_connection(
                token, address_family, IPPROTO_TCP, destination_port, default_compartment);
            break;
        case 6:
            thread_function_allow_block_connection(
                token, address_family, IPPROTO_UDP, destination_port, default_compartment);
            break;
        }
    } catch (const test_failure& e) {
        std::cerr << "Thread " << std::this_thread::get_id() << " failed: " << e.message << std::endl;
        failed = true;
    }
}

TEST_CASE("multi_attach_concurrency_test1", "[multi_attach_tests][concurrent_tests]")
{
    // This test case validates that multiple threads can attach / detach programs concurrently, and the connection
    // verdict is as expected. The test case will have the following threads:
    //
    // Thread 0,1: Invokes connections in a loop.
    // Thread 2,3,4: Attach a program, sleep for few ms, detach the program.
    // Thread 5,6: Block and allow the connection in a loop, and invoke the connection to validate.

    uint16_t destination_port = SOCKET_TEST_PORT;
    std::vector<std::jthread> threads;
    uint32_t thread_count = 7;
    uint32_t thread_run_time = 60;
    std::atomic<bool> failed;

    for (uint32_t i = 0; i < thread_count; i++) {
        // Can only pass variables by value, not by references, hence the need for the shared_ptr<bool>.
        threads.emplace_back(
            multi_attach_test_thread_function1, i, (ADDRESS_FAMILY)AF_INET, destination_port, std::ref(failed));
    }

    std::this_thread::sleep_for(std::chrono::seconds(thread_run_time));

    for (auto& thread : threads) {
        thread.request_stop();
    }

    for (auto& thread : threads) {
        thread.join();
    }

    SAFE_REQUIRE(!failed);
}

void
multi_attach_test_thread_function2(
    std::stop_token token,
    uint32_t index,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    std::atomic<bool>& failed)
{
    // Get the mode.
    uint32_t mode = index % 7;
    uint32_t default_compartment = 1;
    uint32_t unspecified_compartment = 0;

    try {
        switch (mode) {
        case 0:
            __fallthrough;
        case 1:
            thread_function_invoke_connection(token, address_family, destination_port);
            break;
        case 2:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 3:
            thread_function_attach_detach(token, unspecified_compartment, destination_port);
            break;
        }
    } catch (const test_failure& e) {
        std::cerr << "Thread " << std::this_thread::get_id() << " failed: " << e.message << std::endl;
        failed = true;
    }
}

TEST_CASE("multi_attach_concurrency_test2", "[multi_attach_tests][concurrent_tests]")
{
    // This test case stresses the code path where 2 program -- one of type wildcard and other of specific attach
    // types are attaching and detaching in parallel, and a third thread invokes the hook by sending packets.
    //
    // Thread 0,1: Invokes connections in a loop.
    // Thread 2: Attach / detach program with wildcard.
    // Thread 3: Attach / detach program with specific compartment id.

    uint16_t destination_port = SOCKET_TEST_PORT;
    std::vector<std::jthread> threads;
    uint32_t thread_count = 4;
    uint32_t thread_run_time = 60;
    std::atomic<bool> failed = false;

    for (uint32_t i = 0; i < thread_count; i++) {
        // Can only pass variables by value, not by references, hence the need for the shared_ptr<bool>.
        threads.emplace_back(
            multi_attach_test_thread_function2, i, (ADDRESS_FAMILY)AF_INET, destination_port, std::ref(failed));
    }

    std::this_thread::sleep_for(std::chrono::seconds(thread_run_time));

    for (auto& thread : threads) {
        thread.request_stop();
    }

    for (auto& thread : threads) {
        thread.join();
    }

    SAFE_REQUIRE(!failed);
}

int
main(int argc, char* argv[])
{
    WSAData data;

    _is_main_thread = true;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    int result = Catch::Session().run(argc, argv);

    WSACleanup();

    return result;
}
