// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_RUNNER
#define REDIRECT_CONTEXT_BUFFER_SIZE 128

#include "catch_wrapper.hpp"
#include "socket_helper.h"

std::string _protocol;
uint16_t _local_port;
std::string _local_address;

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
create_listener(_Inout_ receiver_socket_t* receiver_socket)
{
    std::string response;
    char redirect_context_buffer[REDIRECT_CONTEXT_BUFFER_SIZE] = "\0";

    _global_counter++;
    // Post a receive. Wait for client to connect.
    printf("=====================================\n");
    printf("Posting async receive, counter = %d\n", _global_counter);
    receiver_socket->post_async_receive();
    printf("Waiting for receive to complete.\n");
    receiver_socket->complete_async_receive(WSA_INFINITE, false);
    printf("Received data from remote\n");

    // Query for the redirect context.
    // This is expected to only be valid for local redirections.
    // If not present, use the generic SERVER_MESSAGE response.
    if (receiver_socket->query_redirect_context(redirect_context_buffer, sizeof(redirect_context_buffer)) == 0) {
        response = redirect_context_buffer + std::to_string(_local_port);
    } else {
        response = SERVER_MESSAGE + std::to_string(_local_port);
    }
    printf("Sending response: %s\n", response.c_str());
    // Send a response back.
    receiver_socket->send_async_response(response.c_str());
    receiver_socket->complete_async_send(1000);
    printf("Sent data to remote\n");
}

void
create_tcp_listener(uint16_t local_port, const std::string& local_address)
{
    sockaddr_storage local_addr = {};
    if (!local_address.empty()) {
        std::string addr_str = local_address;
        get_address_from_string(addr_str, local_addr, true);
    }

    stream_server_socket_t receiver_socket(SOCK_STREAM, IPPROTO_TCP, local_port, local_addr);
    // Create a listener in a loop to accept new connections.
    // The tests / user need to kill the process to stop the listener.
    while (true) {
        create_listener((receiver_socket_t*)&receiver_socket);
    }
}

void
create_udp_listener(uint16_t local_port, const std::string& local_address)
{
    sockaddr_storage local_addr = {};
    if (!local_address.empty()) {
        std::string addr_str = local_address;
        get_address_from_string(addr_str, local_addr, true);
    }

    printf("Creating UDP listener socket with local port %d", local_port);
    if (!local_address.empty()) {
        printf(" and local address %s", local_address.c_str());
    }
    printf(" ...\n");

    datagram_server_socket_t receiver_socket(SOCK_DGRAM, IPPROTO_UDP, local_port, local_addr);
    // Create a listener in a loop to accept new connections.
    // The tests / user need to kill the process to stop the listener.
    while (true) {
        create_listener((receiver_socket_t*)&receiver_socket);
    }
}

TEST_CASE("create_listener", "[connect_redirect_tests]")
{
    IPPROTO protocol = _get_protocol_from_string(_protocol);

    if (protocol == IPPROTO_TCP) {
        create_tcp_listener(_local_port, _local_address);
    } else {
        create_udp_listener(_local_port, _local_address);
    }
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli = session.cli() | Opt(_protocol, "protocol (TCP / UDP)")["-proto"]["--protocol"]("Protocol") |
               Opt(_local_port, "Local Port")["-lport"]["--local-port"]("Local Port") |
               Opt(_local_address, "Local Address")["-laddr"]["--local-address"]("Local Address");

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
