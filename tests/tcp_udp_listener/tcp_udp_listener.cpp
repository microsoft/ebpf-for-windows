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

volatile static LONG _global_counter = 0;

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
    _global_counter++;
    // Post a receive. Wait for client to connect.
    printf("=====================================\n");
    printf("Posting async receive, counter = %d\n", _global_counter);
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
    stream_receiver_socket_t receiver_socket(SOCK_STREAM, IPPROTO_TCP, _local_port);
    while (true) {
        // stream_receiver_socket_t receiver_socket(SOCK_STREAM, IPPROTO_TCP, _local_port);
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
