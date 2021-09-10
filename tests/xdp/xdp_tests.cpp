// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This module facilitates testing various XDP scenarios by sending traffic to a remote system
// running XDP eBPF hook and an attached XDP program.
// For the reflection test, reflect_packet.o needs to be loaded on the remote host.

#define CATCH_CONFIG_RUNNER

#include "catch_wrapper.hpp"
#include "xdp_tests.h"
#include "xdp_tests_common.h"

#include <mstcpip.h>

std::string _remote_ip;
const uint16_t _reflection_port = REFLECTION_TEST_PORT;

TEST_CASE("xdp_reflect_test", "[xdp_tests]")
{
    int error = 0;
    uint32_t ipv6_opt = 0;

    // Create a receiver socket.
    SOCKET receiver_socket = INVALID_SOCKET;
    receiver_socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (receiver_socket == INVALID_SOCKET)
        FAIL("Failed to create receiver socket with error: " << WSAGetLastError());
    error =
        setsockopt(receiver_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_opt), sizeof(ULONG));
    if (error != 0)
        FAIL("Could not enable dual family endpoint: " << WSAGetLastError());

    // Bind it to the reflection port.
    SOCKADDR_STORAGE recv_addr;
    recv_addr.ss_family = AF_INET6;
    INETADDR_SETANY((PSOCKADDR)&recv_addr);
    ((PSOCKADDR_IN6)&recv_addr)->sin6_port = htons(_reflection_port);

    error = bind(receiver_socket, (PSOCKADDR)&recv_addr, sizeof(recv_addr));
    if (error != 0)
        FAIL("Failed to bind receiver socket with error: " << WSAGetLastError());

    WSAOVERLAPPED overlapped = {};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL)
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());

    // Post an asynchronous receive on the receiver socket.
    std::vector<char> recv_buffer(1024);
    WSABUF wsa_recv_buffer{static_cast<ULONG>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};
    uint32_t recv_flags = 0;
    SOCKADDR_STORAGE sender_addr;
    int sender_addr_size = sizeof(sender_addr);
    error = WSARecvFrom(
        receiver_socket,
        &wsa_recv_buffer,
        1,
        nullptr,
        reinterpret_cast<LPDWORD>(&recv_flags),
        (PSOCKADDR)&sender_addr,
        &sender_addr_size,
        &overlapped,
        nullptr);
    if (error != 0) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING)
            FAIL("WSARecvFrom failed with " << wsaerr);
    }

    // Create the sender socket for sending data.
    SOCKET sender_socket = INVALID_SOCKET;
    sender_socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    if (sender_socket == INVALID_SOCKET)
        FAIL("Failed to create sender socket with error: " << WSAGetLastError());
    error =
        setsockopt(sender_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_opt), sizeof(ULONG));
    if (error != 0)
        FAIL("Could not enable dual family endpoint: " << WSAGetLastError());

    // Initialize the remote address.
    ADDRINFO* address_info = nullptr;
    struct sockaddr_storage remote_address = {};
    // Try converting address string to IP address.
    error = getaddrinfo(_remote_ip.data(), nullptr, nullptr, &address_info);
    if (error != 0)
        FAIL("getaddrinfo for" << _remote_ip << " failed with " << WSAGetLastError());
    if (address_info->ai_family == AF_INET)
        IN6ADDR_SETV4MAPPED(
            (PSOCKADDR_IN6)&remote_address, (IN_ADDR*)INETADDR_ADDRESS(address_info->ai_addr), scopeid_unspecified, 0);
    else {
        REQUIRE(address_info->ai_family == AF_INET6);
        remote_address.ss_family = AF_INET6;
        INETADDR_SET_ADDRESS((PSOCKADDR)&remote_address, INETADDR_ADDRESS(address_info->ai_addr));
    }

    // Send a message to the remote host using the sender socket.
    ((PSOCKADDR_IN6)&remote_address)->sin6_port = htons(_reflection_port);
    const char* message = "Bo!ng";
    std::vector<char> send_buffer(message, message + strlen(message));
    WSABUF wsa_send_buffer{static_cast<ULONG>(send_buffer.size()), reinterpret_cast<char*>(send_buffer.data())};
    uint32_t bytes_sent = 0;
    uint32_t send_flags = 0;
    error = WSASendTo(
        sender_socket,
        &wsa_send_buffer,
        1,
        reinterpret_cast<LPDWORD>(&bytes_sent),
        send_flags,
        (PSOCKADDR)&remote_address,
        sizeof(remote_address),
        nullptr,
        nullptr);

    if (error != 0)
        FAIL("Sending message to remote host failed with " << WSAGetLastError());

    // Wait for the receiver socket to receive the reflected message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, 1000, TRUE);
    if (error != WSA_WAIT_EVENT_0)
        if (error == WSA_WAIT_TIMEOUT)
            FAIL("Receiver socket did not receive any message in 1 second.");
        else
            FAIL("Waiting on receiver socket failed with " << error);

    uint32_t bytes_received = 0;
    if (!WSAGetOverlappedResult(
            receiver_socket,
            &overlapped,
            reinterpret_cast<LPDWORD>(&bytes_received),
            FALSE,
            reinterpret_cast<LPDWORD>(&recv_flags)))
        FAIL("WSArecvFrom on the receiver socket failed with error: " << WSAGetLastError());
    else {
        REQUIRE(bytes_received == strlen(message));
        REQUIRE(memcmp(recv_buffer.data(), message, strlen(message)) == 0);
    }

    freeaddrinfo(address_info);
    closesocket(receiver_socket);
    WSACloseEvent(overlapped.hEvent);
    closesocket(sender_socket);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::clara;
    auto cli = session.cli() |
               Opt(_remote_ip, "remote IP address")["-rip"]["--remote_ip"]("remote host's IP address in string format");

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