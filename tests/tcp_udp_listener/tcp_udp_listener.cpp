// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This module facilitates testing various connect redirect scenarios by sending traffic to both a remote system
// running XDP eBPF hook and an attached XDP program.
// For the reflection test, reflect_packet.o needs to be loaded on the remote host.

#define CATCH_CONFIG_RUNNER

#include "catch_wrapper.hpp"
#include "socket_helper.h"

#define SERVER_PORT 4444

std::string _local_v4_ip;
std::string _local_v6_ip;
std::string _protocol;
std::string _local_port_string;

uint16_t _local_port = SERVER_PORT;

static const uint16_t _server_port = SERVER_PORT;

const char* server_v4_ip = "15.1.1.2";
const char* client_v4_ip = "15.1.1.1";

static IPPROTO
_get_protocol_from_string(std::string protocol)
{
    if (protocol.compare("tcp") == 0 || protocol.compare("TCP") == 0) {
        return IPPROTO_TCP;
    }

    return IPPROTO_UDP;
}

void
create_listener(receiver_socket_t* receiver_socket)
{
    // Post a receive. Wait for client to connect.
    printf("Posting async receive\n");
    receiver_socket->post_async_receive();
    printf("Waiting for receive to complete.\n");
    receiver_socket->complete_async_receive(WSA_INFINITE, false);
    printf("Received data from remote\n");

    PSOCKADDR local_address = nullptr;
    int local_length = 0;
    receiver_socket->get_local_address(local_address, local_length);

    std::string address_string = get_string_from_address(local_address, local_address->sa_family);
    printf("my local address is %s\n", address_string.c_str());

    // Send a response back.
    receiver_socket->send_async_response("test_message");
    receiver_socket->complete_async_send(1000);
    printf("Sent data to remote\n");
}

void
create_tcp_listener()
{
    while (true) {
        stream_receiver_socket_t receiver_socket(SOCK_STREAM, IPPROTO_TCP, _local_port);
        create_listener((receiver_socket_t*)&receiver_socket);
    }
}

void
create_udp_listener()
{
    printf("Creating UDP listener socket ...\n");
    datagram_receiver_socket_t receiver_socket(SOCK_DGRAM, IPPROTO_UDP, _local_port);
    while (true) {
        create_listener((receiver_socket_t*)&receiver_socket);
    }
}

TEST_CASE("create_listener", "[connect_redirect_tests]")
{
    IPPROTO protocol = _get_protocol_from_string(_protocol);

    /*
    int local_port = std::stoi(_local_port_string);
    if (local_port > 0 && local_port < static_cast<int>(UINT16_MAX))
    {
        _local_port = static_cast<uint16_t>(local_port);
    }
    */

    if (protocol == IPPROTO_TCP) {
        create_tcp_listener();
    } else {
        create_udp_listener();
    }
}

/*
TEST_CASE("datagram_listener", "[connect_redirect_tests]")
{
    stream_receiver_socket_t stream_receiver_socket(SOCK_STREAM, IPPROTO_TCP, SERVER_PORT);
}

TEST_CASE("stream_listener", "[connect_redirect_tests]")
{
    // Create socket.
    stream_receiver_socket_t receiver_socket(SOCK_STREAM, IPPROTO_TCP, SERVER_PORT);

    while (true) {
        // Post a receive. Wait for client to connect.
        receiver_socket.post_async_receive();
        receiver_socket.complete_async_receive(WSA_INFINITE, false);

        // Send a response back.
        receiver_socket.send_async_response("test_message");
        receiver_socket.
    }
}
*/

/*
TEST_CASE("redirect_test_remote", "[connect_redirect_tests]")
{

}
*/

/*
TEST_CASE("xdp_encap_reflect_test", "[xdp_tests]")
{
    // Initialize the remote address.
    struct sockaddr_storage remote_address = {};
    ADDRESS_FAMILY address_family;
    get_address_from_string(_remote_ip, remote_address, &address_family);
    REQUIRE((address_family == AF_INET || address_family == AF_INET6));
    int protocol = (address_family == AF_INET) ? IPPROTO_IPV4 : IPPROTO_IPV6;
    // Create a RAW receiver socket with protocol being IPV4 or IPV6 based on the address family of the remote host.
    datagram_receiver_socket_t datagram_receiver_socket(SOCK_RAW, protocol, _reflection_port);
    // Post an asynchronous receive on the receiver socket.
    datagram_receiver_socket.post_async_receive();
    // Send message to remote host on reflection port.
    const char* message = "Bo!ng";
    datagram_sender_socket_t datagram_sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_sender_socket.send_message_to_remote_host(message, remote_address, _reflection_port);
    // Complete the asynchronous receive and obtain the reflected message.
    datagram_receiver_socket.complete_async_receive();
    // Verify if the received message was reflected by remote host.
    PSOCKADDR sender_address = nullptr;
    int sender_length = 0;
    datagram_receiver_socket.get_sender_address(sender_address, sender_length);
    REQUIRE(INET_ADDR_EQUAL(
        remote_address.ss_family, INETADDR_ADDRESS((PSOCKADDR)&remote_address), INETADDR_ADDRESS(sender_address)));
    // Verify if the received message is expected.
    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    datagram_receiver_socket.get_received_message(bytes_received, received_message);
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
    datagram_receiver_socket_t datagram_receiver_socket(SOCK_DGRAM, IPPROTO_UDP, REFLECTION_TEST_PORT);
    // Post an asynchronous receive on the receiver socket.
    datagram_receiver_socket.post_async_receive();
    // Initialize the remote address.
    struct sockaddr_storage remote_address = {};
    get_address_from_string(_remote_ip, remote_address);
    // Send message to remote host on reflection port.
    const char* message = "Bo!ng";
    datagram_sender_socket_t datagram_sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_sender_socket.send_message_to_remote_host(message, remote_address, REFLECTION_TEST_PORT);
    // Complete the asynchronous receive and obtain the reflected message.
    datagram_receiver_socket.complete_async_receive();
    // Verify if the received message is expected.
    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    datagram_receiver_socket.get_received_message(bytes_received, received_message);
    REQUIRE(bytes_received == strlen(message));
    REQUIRE(memcmp(received_message, message, strlen(message)) == 0);
}
*/

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli = session.cli() | Opt(_protocol, "protocol (TCP / UDP)")["-proto"]["--protocol"]("Protocol") |
               Opt(_local_port, "protocol (TCP / UDP)")["-lport"]["--local-port"]("Local Port");

    session.cli(cli);

    int returnCode = session.applyCommandLine(argc, argv);
    if (returnCode != 0)
        return returnCode;

    WSAData data;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    session.run();
    WSACleanup();
}
