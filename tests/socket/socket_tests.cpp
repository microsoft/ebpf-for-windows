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
#include "native_helper.hpp"
#include "socket_helper.h"
#include "socket_tests_common.h"
#include "watchdog.h"

#include <chrono>
#include <future>
using namespace std::chrono_literals;
#include <mstcpip.h>

CATCH_REGISTER_LISTENER(_watchdog)

#define MULTIPLE_ATTACH_PROGRAM_COUNT 3

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

    REQUIRE(object != nullptr);
    // Load the programs.
    REQUIRE(bpf_object__load(object) == 0);
    const char* connect_program_name = (address_family == AF_INET) ? "authorize_connect4" : "authorize_connect6";
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    REQUIRE(connect_program != nullptr);

    const char* recv_accept_program_name =
        (address_family == AF_INET) ? "authorize_recv_accept4" : "authorize_recv_accept6";
    bpf_program* recv_accept_program = bpf_object__find_program_by_name(object, recv_accept_program_name);
    REQUIRE(recv_accept_program != nullptr);

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
    REQUIRE(ingress_connection_policy_map != nullptr);
    bpf_map* egress_connection_policy_map = bpf_object__find_map_by_name(object, "egress_connection_policy_map");
    REQUIRE(egress_connection_policy_map != nullptr);

    // Update ingress and egress policy to block loopback packet on test port.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);
    REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT.
    bpf_attach_type connect_attach_type =
        (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;
    int result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program)), 0, connect_attach_type, 0);
    REQUIRE(result == 0);

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
    REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Attach the receive/accept program at BPF_CGROUP_INET4_RECV_ACCEPT.
    bpf_attach_type recv_accept_attach_type =
        (address_family == AF_INET) ? BPF_CGROUP_INET4_RECV_ACCEPT : BPF_CGROUP_INET6_RECV_ACCEPT;
    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept_program)), 0, recv_accept_attach_type, 0);
    REQUIRE(result == 0);

    // Resend the packet. This time, it should be dropped by the receive/accept program.
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    receiver_socket.complete_async_receive(true);
    // Cancel send operation.
    sender_socket.cancel_send_message();

    // Update ingress policy to allow packet.
    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED;
    REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

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

    REQUIRE(object != nullptr);
    // Load the programs.
    REQUIRE(bpf_object__load(object) == 0);

    bpf_program* connect4_program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(connect4_program != nullptr);

    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_CONNECT,
        0);
    REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    REQUIRE(program_info.link_count == 1);
    REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach(UNSPECIFIED_COMPARTMENT_ID, BPF_CGROUP_INET4_CONNECT);
    REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    REQUIRE(program_info.link_count == 0);

    bpf_program* recv_accept4_program = bpf_object__find_program_by_name(object, "authorize_recv_accept4");
    REQUIRE(recv_accept4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT,
        0);
    REQUIRE(result == 0);

    REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    REQUIRE(program_info.link_count == 1);
    REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach2(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT);
    REQUIRE(result == 0);

    REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    REQUIRE(program_info.link_count == 0);

    bpf_program* connect6_program = bpf_object__find_program_by_name(object, "authorize_connect6");
    REQUIRE(connect6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_CONNECT,
        0);
    REQUIRE(result == 0);

    bpf_program* recv_accept6_program = bpf_object__find_program_by_name(object, "authorize_recv_accept6");
    REQUIRE(recv_accept6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_RECV_ACCEPT,
        0);
    REQUIRE(result == 0);
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

    REQUIRE(object != nullptr);
    // Load the programs.
    REQUIRE(bpf_object__load(object) == 0);

    // Ring buffer event callback context.
    std::unique_ptr<ring_buffer_test_event_context_t> context = std::make_unique<ring_buffer_test_event_context_t>();
    context->test_event_count = disconnect ? 4 : 2;

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    REQUIRE(_program != nullptr);

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
    audit_entries[0].connected = true;
    audit_entries[0].outbound = true;
    char* p = reinterpret_cast<char*>(&audit_entries[0]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Connect inbound.
    audit_entries[1].tuple = reverse_tuple;
    audit_entries[1].connected = true;
    audit_entries[1].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[1]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create an audit entry for the disconnect case.
    // The direction bit is set to false.
    audit_entries[2].tuple = tuple;
    audit_entries[2].connected = false;
    audit_entries[2].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[2]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create another audit entry for the disconnect event with the reverse packet tuple.
    audit_entries[3].tuple = reverse_tuple;
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
    REQUIRE(ring_buffer_map != nullptr);
    context->ring_buffer = ring_buffer__new(
        bpf_map__fd(ring_buffer_map), (ring_buffer_sample_fn)ring_buffer_test_event_handler, context.get(), nullptr);
    REQUIRE(context->ring_buffer != nullptr);

    bpf_map* connection_map = bpf_object__find_map_by_name(object, "connection_map");
    REQUIRE(connection_map != nullptr);

    // Update connection map with loopback packet tuples.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &tuple, &verdict, EBPF_ANY) == 0);
    REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &reverse_tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the sockops program.
    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    REQUIRE(result == 0);

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
    REQUIRE(ring_buffer_event_callback.wait_for(1s) == std::future_status::ready);

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

    REQUIRE(object != nullptr);
    // Load the programs.
    REQUIRE(bpf_object__load(object) == 0);

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    REQUIRE(_program != nullptr);

    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    REQUIRE(result == 0);
}

static void
_update_map_entry(
    fd_t map_fd,
    uint32_t destination,
    uint16_t destination_port,
    uint32_t proxy,
    uint16_t proxy_port,
    uint16_t protocol,
    bool add)
{
    destination_entry_key_t key = {0};
    destination_entry_value_t value = {0};

    key.destination_ip.ipv4 = destination;
    key.destination_port = destination_port;
    key.protocol = protocol;

    value.destination_ip.ipv4 = proxy;
    value.destination_port = proxy_port;

    if (add) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        REQUIRE(bpf_map_delete_elem(map_fd, &key) == 0);
    }
}

void
validate_connection_multi_attach(
    ADDRESS_FAMILY address_family,
    // _Inout_ client_socket_t& sender_socket,
    // _Inout_ receiver_socket_t& receiver_socket,
    uint16_t receiver_port,
    uint16_t destination_port,
    uint32_t protocol,
    bool expect_drop,
    bool validate_redirect_context)
{
    UNREFERENCED_PARAMETER(validate_redirect_context);
    UNREFERENCED_PARAMETER(protocol);

    client_socket_t* sender_socket = nullptr;
    receiver_socket_t* receiver_socket = nullptr;

    if (protocol == IPPROTO_UDP) {
        sender_socket = new datagram_client_socket_t(SOCK_DGRAM, IPPROTO_UDP, 0);
        receiver_socket = new datagram_server_socket_t(SOCK_DGRAM, IPPROTO_UDP, receiver_port);
    } else if (protocol == IPPROTO_TCP) {
        sender_socket = new stream_client_socket_t(SOCK_STREAM, IPPROTO_TCP, 0);
        receiver_socket = new stream_server_socket_t(SOCK_STREAM, IPPROTO_TCP, receiver_port);
    } else {
        REQUIRE(false);
    }

    // Post an asynchronous receive on the receiver socket.
    receiver_socket->post_async_receive();

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }

    sender_socket->send_message_to_remote_host(message, destination_address, destination_port);

    if (expect_drop) {
        // The packet should be blocked.
        receiver_socket->complete_async_receive(true);
        // Cancel send operation.
        sender_socket->cancel_send_message();
    } else {
        // The packet should be allowed by the connect program.
        receiver_socket->complete_async_receive();
    }

    // if (validate_redirect_context) {
    //     // Validate the redirect context.
    //     char redirect_context[] = REDIRECT_CONTEXT_MESSAGE;
    //     REQUIRE(sender_socket.validate_redirect_context(redirect_context, sizeof(redirect_context)));
    // }

    delete sender_socket;
    delete receiver_socket;
}

void
multi_attach_test_common(bpf_object* object, uint32_t compartment_id, bool detach_program)
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

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    REQUIRE(connect_program != nullptr);

    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    REQUIRE(map_fd != ebpf_fd_invalid);

    // Deleting the map entry will result in the program blocking the connection.
    _update_map_entry(
        map_fd,
        htonl(INADDR_LOOPBACK),
        htons(SOCKET_TEST_PORT),
        htonl(INADDR_LOOPBACK),
        htons(SOCKET_TEST_PORT),
        IPPROTO_TCP,
        false);

    // The packet should be blocked.
    validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, true, false);

    // Revert the policy to "allow" the connection.
    _update_map_entry(
        map_fd,
        htonl(INADDR_LOOPBACK),
        htons(SOCKET_TEST_PORT),
        htonl(INADDR_LOOPBACK),
        htons(SOCKET_TEST_PORT),
        IPPROTO_TCP,
        true);

    // The packet should be allowed.
    validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, false, false);

    if (detach_program) {
        // Block the connection.
        _update_map_entry(
            map_fd,
            htonl(INADDR_LOOPBACK),
            htons(SOCKET_TEST_PORT),
            htonl(INADDR_LOOPBACK),
            htons(SOCKET_TEST_PORT),
            IPPROTO_TCP,
            false);

        // The packet should be blocked.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, true, false);

        // Detach the program.
        int result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, BPF_CGROUP_INET4_CONNECT);
        REQUIRE(result == 0);

        // The packet should now be allowed.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, false, false);

        // Re-attach the program.
        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
            compartment_id,
            BPF_CGROUP_INET4_CONNECT,
            0);
        REQUIRE(result == 0);

        // The packet should be blocked.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, true, false);

        // Update the policy to "allow" the connection.
        _update_map_entry(
            map_fd,
            htonl(INADDR_LOOPBACK),
            htons(SOCKET_TEST_PORT),
            htonl(INADDR_LOOPBACK),
            htons(SOCKET_TEST_PORT),
            IPPROTO_TCP,
            true);

        // The packet should now be allowed.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, false, false);
    }
}

void
multi_attach_test(uint32_t compartment_id)
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

    // Load the programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2");
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    // Attach all the programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], "connect_redirect4");
        REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
            compartment_id,
            BPF_CGROUP_INET4_CONNECT,
            0);
        REQUIRE(result == 0);
    }

    // Configure policy maps for all programs to "allow" the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
        REQUIRE(policy_map != nullptr);
        fd_t map_fd = bpf_map__fd(policy_map);
        REQUIRE(map_fd != ebpf_fd_invalid);
        _update_map_entry(
            map_fd,
            htonl(INADDR_LOOPBACK),
            htons(SOCKET_TEST_PORT),
            htonl(INADDR_LOOPBACK),
            htons(SOCKET_TEST_PORT),
            IPPROTO_TCP,
            true);
    }

    // Validate that the connection is allowed.
    validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, false, false);

    // Test that the connection is blocked if any of the programs block the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        multi_attach_test_common(objects[i], compartment_id, false);
    }

    // Next section tests detach and re-attach of programs.
    // Current attach order is 0 --> 1 --> 2. Detach "first" program and check if the verdict changes.
    multi_attach_test_common(objects[0], compartment_id, true);

    // Now the program attach order is 1 --> 2 --> 0. Repeat detach / reattach with the "middle" program.
    multi_attach_test_common(objects[2], compartment_id, true);

    // Now the program attach order is 1 --> 0 --> 2. Repeat it with the "last" program.
    multi_attach_test_common(objects[2], compartment_id, true);

    // Now attach a 4th program to different compartment. It should not get invoked, and its verdict should not affect
    // the connection.
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2");
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);

    // Load the programs.
    REQUIRE(bpf_object__load(object) == 0);

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT.
    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    REQUIRE(connect_program != nullptr);
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
        compartment_id + 2,
        BPF_CGROUP_INET4_CONNECT,
        0);
    REQUIRE(result == 0);

    // Not updating policy map for this program should mean that this program (if invoked) will block the connection.
    // Validate that the connection is allowed.
    validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, false, false);
}

void
multi_attach_test_redirection(uint32_t compartment_id)
{
    // This test validates that redirection correctly happens when multiple programs are redirecting the connection.

    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    uint16_t destination_port = SOCKET_TEST_PORT - 4;
    uint16_t proxy_port1 = destination_port + 1;
    uint16_t proxy_port2 = destination_port + 2;
    uint16_t original_ports[MULTIPLE_ATTACH_PROGRAM_COUNT] = {destination_port, proxy_port1, proxy_port2};
    uint16_t redirect_ports[MULTIPLE_ATTACH_PROGRAM_COUNT] = {proxy_port1, proxy_port2, SOCKET_TEST_PORT};

    // Load 3 programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2");
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    // Attach all the 3 programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], "connect_redirect4");
        REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
            compartment_id,
            BPF_CGROUP_INET4_CONNECT,
            0);
        REQUIRE(result == 0);
    }

    // Lambda function to update the policy map entry, and validate the connection.
    auto validate_program_detach_reattach = [&](uint32_t program_index) {
        // Configure policy maps for all programs to "redirect" the connection.
        // Below is the configuration:
        // 1. Receiver will listen on SOCKET_TEST_PORT and client will send traffic to destination_port.
        // 2. Program 0: Redirect from port destination_port --> proxy_port1
        // 3. Program 1: Redirect from port proxy_port1 --> proxy_port2
        // 4. Program 2: Redirect from port proxy_port2 --> SOCKET_TEST_PORT
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
            REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            REQUIRE(map_fd != ebpf_fd_invalid);
            _update_map_entry(
                map_fd,
                htonl(INADDR_LOOPBACK),
                htons(original_ports[i]),
                htonl(INADDR_LOOPBACK),
                htons(redirect_ports[i]),
                IPPROTO_TCP,
                true);
        }

        // Validate that the connection is allowed.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, false, false);

        // Detach the program.
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[program_index], "connect_redirect4");
        REQUIRE(connect_program != nullptr);
        int result = bpf_prog_detach2(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, BPF_CGROUP_INET4_CONNECT);

        // The connection should now be blocked.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, true, false);

        // Reset the whole state by detaching and re-attaching all the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            if (i == program_index) {
                continue;
            }
            bpf_program* program = bpf_object__find_program_by_name(objects[i], "connect_redirect4");
            REQUIRE(program != nullptr);
            result = bpf_prog_detach2(
                bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, BPF_CGROUP_INET4_CONNECT);
            REQUIRE(result == 0);
        }

        // Re-attach the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], "connect_redirect4");
            REQUIRE(program != nullptr);
            result = bpf_prog_attach(
                bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, BPF_CGROUP_INET4_CONNECT, 0);
            REQUIRE(result == 0);
        }

        // Validate that the connection is again allowed.
        validate_connection_multi_attach(AF_INET, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, false, false);
    };

    // For each program, detach and re-attach it, and validate the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        validate_program_detach_reattach(i);
    }
}

TEST_CASE("multi_attach_test", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id);
}

TEST_CASE("multi_attach_test_wildcard", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID);
}

TEST_CASE("multi_attach_test_redirection", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(compartment_id);
}

TEST_CASE("multi_attach_test_redirection_wildcard", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(UNSPECIFIED_COMPARTMENT_ID);
}

// TEST_CASE("multi_attach_test_invocation_order", "[sock_addr_tests][multi_attach_tests]")
// {
//     // This test case validates that a program attached with specific compartment id is always invoked before a
//     program
//     // attached with wildcard compartment id, irrespective of the order of attachment.
//     multi_attach_test(UNSPECIFIED_COMPARTMENT_ID);
// }

// TODO: Add concurrency tests.
// thread 1: invoking connections in a loop.
// thread 2,3: attach a program, sleep for 500ms, detach the program.
// thread 4: attach a program, sleep for 500ms, update policy map to block the connection. Validate that the connection
// is blocked.

int
main(int argc, char* argv[])
{
    WSAData data;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    int result = Catch::Session().run(argc, argv);

    WSACleanup();

    return result;
}
