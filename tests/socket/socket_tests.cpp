// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This module facilitates testing various socket related eBPF program types and hooks.

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "ebpf_nethooks.h"
#include "ebpf_structs.h"
#include "socket_helper.h"
#include "socket_tests_common.h"

#include <mstcpip.h>

void
connection_test(
    ADDRESS_FAMILY address_family,
    sender_socket_t& sender_socket,
    receiver_socket_t& receiver_socket,
    uint32_t protocol)
{
    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("cgroup_sock_addr.o", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

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

    connection_tuple_t tuple{};
    if (address_family == AF_INET) {
        tuple.src_ip.ipv4 = htonl(INADDR_LOOPBACK);
        tuple.dst_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(tuple.src_ip.ipv6, &in6addr_loopback, sizeof(tuple.src_ip.ipv6));
        memcpy(tuple.dst_ip.ipv6, &in6addr_loopback, sizeof(tuple.src_ip.ipv6));
    }
    tuple.src_port = INETADDR_PORT(local_address);
    tuple.dst_port = htons(SOCKET_TEST_PORT);
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
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program)), 0, connect_attach_type, 0);
    REQUIRE(result == 0);

    // Send loopback message to test port.
    const char* message = "eBPF for Windows!";
    sockaddr_storage destination_address{};
    if (address_family == AF_INET)
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    else
        INETADDR_SETSOCKADDR(AF_INET6, (PSOCKADDR)&destination_address, &in6addr_loopback, scopeid_unspecified, 0);
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

    bpf_object__close(object);
}

TEST_CASE("connection_test_udp_v4", "[socket_tests]")
{
    datagram_sender_socket_t datagram_sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_receiver_socket_t datagram_receiver_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_test(AF_INET, datagram_sender_socket, datagram_receiver_socket, IPPROTO_UDP);
}
TEST_CASE("connection_test_udp_v6", "[socket_tests]")
{
    datagram_sender_socket_t datagram_sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_receiver_socket_t datagram_receiver_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_test(AF_INET6, datagram_sender_socket, datagram_receiver_socket, IPPROTO_UDP);
}

TEST_CASE("connection_test_tcp_v4", "[socket_tests]")
{
    stream_sender_socket_t stream_sender_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_receiver_socket_t stream_receiver_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_test(AF_INET, stream_sender_socket, stream_receiver_socket, IPPROTO_TCP);
}
TEST_CASE("connection_test_tcp_v6", "[socket_tests]")
{
    stream_sender_socket_t stream_sender_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_receiver_socket_t stream_receiver_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_test(AF_INET6, stream_sender_socket, stream_receiver_socket, IPPROTO_TCP);
}

TEST_CASE("attach_programs", "[socket_tests]")
{
    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("cgroup_sock_addr.o", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    bpf_program* connect4_program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(connect4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), 0, BPF_CGROUP_INET4_CONNECT, 0);
    REQUIRE(result == 0);

    bpf_program* recv_accept4_program = bpf_object__find_program_by_name(object, "authorize_recv_accept4");
    REQUIRE(recv_accept4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), 0, BPF_CGROUP_INET4_RECV_ACCEPT, 0);
    REQUIRE(result == 0);

    bpf_program* connect6_program = bpf_object__find_program_by_name(object, "authorize_connect6");
    REQUIRE(connect6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect6_program)), 0, BPF_CGROUP_INET6_CONNECT, 0);
    REQUIRE(result == 0);

    bpf_program* recv_accept6_program = bpf_object__find_program_by_name(object, "authorize_recv_accept6");
    REQUIRE(recv_accept6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept6_program)), 0, BPF_CGROUP_INET6_RECV_ACCEPT, 0);
    REQUIRE(result == 0);

    bpf_object__close(object);
}

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