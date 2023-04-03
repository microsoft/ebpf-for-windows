// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This module facilitates testing various XDP scenarios by sending traffic to a remote system
// running XDP eBPF hook and an attached XDP program.
// For the reflection test, reflect_packet.o needs to be loaded on the remote host.

#define CATCH_CONFIG_RUNNER

#include "catch_wrapper.hpp"
#include "ebpf_udp.h"
#include "socket_helper.h"
#include "watchdog.h"
#include "xdp_tests_common.h"

CATCH_REGISTER_LISTENER(_watchdog)

std::string _remote_ip;
const uint16_t _reflection_port = REFLECTION_TEST_PORT;

TEST_CASE("xdp_encap_reflect_test", "[xdp_tests]")
{
    // Initialize the remote address.
    struct sockaddr_storage remote_address = {};
    ADDRESS_FAMILY address_family;
    get_address_from_string(_remote_ip, remote_address, true, &address_family);
    REQUIRE((address_family == AF_INET || address_family == AF_INET6));
    int protocol = (address_family == AF_INET) ? IPPROTO_IPV4 : IPPROTO_IPV6;
    // Create a RAW receiver socket with protocol being IPv4 or IPv6 based on the address family of the remote host.
    datagram_server_socket_t datagram_server_socket(SOCK_RAW, protocol, _reflection_port);
    // Post an asynchronous receive on the receiver socket.
    datagram_server_socket.post_async_receive();
    // Send message to remote host on reflection port.
    const char* message = "Bo!ng";
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_client_socket.send_message_to_remote_host(message, remote_address, _reflection_port);
    // Complete the asynchronous receive and obtain the reflected message.
    datagram_server_socket.complete_async_receive();
    // Verify if the received message was reflected by remote host.
    PSOCKADDR sender_address = nullptr;
    int sender_length = 0;
    datagram_server_socket.get_sender_address(sender_address, sender_length);
    REQUIRE(INET_ADDR_EQUAL(
        remote_address.ss_family, INETADDR_ADDRESS((PSOCKADDR)&remote_address), INETADDR_ADDRESS(sender_address)));
    // Verify if the received message is expected.
    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    datagram_server_socket.get_received_message(bytes_received, received_message);
    if (address_family == AF_INET) {
        // Raw sockets with protocol IPPROTO_IPV4 receives the IP header in received message.
        // So skip over outer IP header to get the inner IP datagram.
        uint32_t remaining_bytes = bytes_received;
        REQUIRE(remaining_bytes > sizeof(IPV4_HEADER));
        remaining_bytes -= sizeof(IPV4_HEADER);
        IPV4_HEADER* inner_ipv4_header = reinterpret_cast<IPV4_HEADER*>(received_message + sizeof(IPV4_HEADER));
        REQUIRE(remaining_bytes > inner_ipv4_header->HeaderLength * sizeof(uint32_t));
        remaining_bytes -= inner_ipv4_header->HeaderLength * sizeof(uint32_t);
        REQUIRE(inner_ipv4_header->Protocol == IPPROTO_UDP);
        UDP_HEADER* udp_header = reinterpret_cast<UDP_HEADER*>(
            reinterpret_cast<char*>(inner_ipv4_header) + inner_ipv4_header->HeaderLength * sizeof(uint32_t));
        REQUIRE(remaining_bytes > sizeof(UDP_HEADER));
        remaining_bytes -= sizeof(UDP_HEADER);
        REQUIRE(remaining_bytes == strlen(message));
        REQUIRE(memcmp(reinterpret_cast<char*>(udp_header + 1), message, strlen(message)) == 0);
    } else {
        // Raw sockets with protocol IPPROTO_IPV6 does not receive the IP header in received message.
        // So in this case the received message is the inner IP datagram.
        REQUIRE(bytes_received == sizeof(IPV6_HEADER) + sizeof(UDP_HEADER) + strlen(message));
        REQUIRE(memcmp(received_message + sizeof(IPV6_HEADER) + sizeof(UDP_HEADER), message, strlen(message)) == 0);
    }
}

TEST_CASE("xdp_reflect_test", "[xdp_tests]")
{
    // Create a UDP receiver socket.
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, REFLECTION_TEST_PORT);
    // Post an asynchronous receive on the receiver socket.
    datagram_server_socket.post_async_receive();
    // Initialize the remote address.
    struct sockaddr_storage remote_address = {};
    get_address_from_string(_remote_ip, remote_address, true);
    // Send message to remote host on reflection port.
    const char* message = "Bo!ng";
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_client_socket.send_message_to_remote_host(message, remote_address, REFLECTION_TEST_PORT);
    // Complete the asynchronous receive and obtain the reflected message.
    datagram_server_socket.complete_async_receive();
    // Verify if the received message is expected.
    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    datagram_server_socket.get_received_message(bytes_received, received_message);
    REQUIRE(bytes_received == strlen(message));
    REQUIRE(memcmp(received_message, message, strlen(message)) == 0);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli = session.cli() |
               Opt(_remote_ip, "remote IP address")["-rip"]["--remote-ip"]("remote host's IP address in string format");

    session.cli(cli);

    int returnCode = session.applyCommandLine(argc, argv);
    if (returnCode != 0) {
        return returnCode;
    }

    WSAData data;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    session.run();
    WSACleanup();
}