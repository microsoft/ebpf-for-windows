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

static void
_send_message_to_remote_host(_In_z_ const char* message, sockaddr_storage& remote_address)
{
    int error = 0;
    uint32_t ipv6_opt = 0;

    // Create the sender socket for sending data.
    SOCKET sender_socket = INVALID_SOCKET;
    sender_socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    if (sender_socket == INVALID_SOCKET)
        FAIL("Failed to create sender socket with error: " << WSAGetLastError());
    error =
        setsockopt(sender_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_opt), sizeof(ULONG));
    if (error != 0)
        FAIL("Could not enable dual family endpoint: " << WSAGetLastError());

    // Send a message to the remote host using the sender socket.
    ((PSOCKADDR_IN6)&remote_address)->sin6_port = htons(_reflection_port);
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

    closesocket(sender_socket);
}

static void
_get_remote_address(sockaddr_storage& remote_address, _Out_opt_ ADDRESS_FAMILY* address_family = nullptr)
{
    int error = 0;
    // Initialize the remote address.
    ADDRINFO* address_info = nullptr;
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
    if (address_family != nullptr)
        *address_family = static_cast<ADDRESS_FAMILY>(address_info->ai_family);
    freeaddrinfo(address_info);
}

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to receive datagrams.
 */
typedef class _receiver_socket
{
  public:
    _receiver_socket(int _sock_type, int _protocol)
        : socket(INVALID_SOCKET), sock_type(_sock_type), protocol(_protocol), overlapped{},
          recv_buffer(std::vector<char>(1024)), recv_flags(0), sender_address{},
          sender_address_size(sizeof(sender_address))
    {
        int error = 0;
        if (!(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) &&
            !(protocol == IPPROTO_UDP || protocol == IPPROTO_IPV4 || protocol == IPPROTO_IPV6))
            FAIL("receiver_socket only supports these combinations (SOCK_DGRAM, IPPROTO_UDP) and (SOCK_RAW, "
                 "IPPROTO_IPV4/IPV6)");
        socket = WSASocket(AF_INET6, sock_type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (socket == INVALID_SOCKET)
            FAIL("Failed to create receiver socket with error: " << WSAGetLastError());
        uint32_t ipv6_opt = 0;
        error = setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_opt), sizeof(ULONG));
        if (error != 0)
            FAIL("Could not enable dual family endpoint: " << WSAGetLastError());
    }

    ~_receiver_socket()
    {
        closesocket(socket);
        WSACloseEvent(overlapped.hEvent);
    }

    void
    post_async_receive()
    {
        int error = 0;

        // Bind it to the reflection port.
        SOCKADDR_STORAGE recv_addr;
        recv_addr.ss_family = AF_INET6;
        INETADDR_SETANY((PSOCKADDR)&recv_addr);
        ((PSOCKADDR_IN6)&recv_addr)->sin6_port = htons(_reflection_port);

        error = bind(socket, (PSOCKADDR)&recv_addr, sizeof(recv_addr));
        if (error != 0)
            FAIL("Failed to bind receiver socket with error: " << WSAGetLastError());

        // Create an event handle and set up the overlapped structure.
        overlapped.hEvent = WSACreateEvent();
        if (overlapped.hEvent == NULL)
            FAIL("WSACreateEvent failed with error: " << WSAGetLastError());

        WSABUF wsa_recv_buffer{static_cast<ULONG>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};

        // Post an asynchronous receive on the socket.
        error = WSARecvFrom(
            socket,
            &wsa_recv_buffer,
            1,
            nullptr,
            reinterpret_cast<LPDWORD>(&recv_flags),
            (PSOCKADDR)&sender_address,
            &sender_address_size,
            &overlapped,
            nullptr);
        if (error != 0) {
            int wsaerr = WSAGetLastError();
            if (wsaerr != WSA_IO_PENDING)
                FAIL("WSARecvFrom failed with " << wsaerr);
        }
    }

    void
    complete_async_receive()
    {
        int error = 0;
        // Wait for the receiver socket to receive the message.
        error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, 1000, TRUE);
        if (error != WSA_WAIT_EVENT_0)
            if (error == WSA_WAIT_TIMEOUT)
                FAIL("Receiver socket did not receive any message in 1 second.");
            else
                FAIL("Waiting on receiver socket failed with " << error);

        if (!WSAGetOverlappedResult(
                socket,
                &overlapped,
                reinterpret_cast<LPDWORD>(&bytes_received),
                FALSE,
                reinterpret_cast<LPDWORD>(&recv_flags)))
            FAIL("WSArecvFrom on the receiver socket failed with error: " << WSAGetLastError());
    }

    void
    get_received_message(uint32_t& message_size, _Out_ char*& message)
    {
        message_size = bytes_received;
        message = recv_buffer.data();
    }

    void
    get_sender_address(PSOCKADDR& from, int& from_length)
    {
        from = (PSOCKADDR)&sender_address;
        from_length = sender_address_size;
    }

  private:
    SOCKET socket;
    int sock_type;
    int protocol;
    WSAOVERLAPPED overlapped;
    std::vector<char> recv_buffer;
    uint32_t recv_flags;
    sockaddr_storage sender_address;
    int sender_address_size;
    uint32_t bytes_received = 0;
} receiver_socket_t;

TEST_CASE("xdp_encap_reflect_test", "[xdp_tests]")
{
    // Initialize the remote address.
    struct sockaddr_storage remote_address = {};
    ADDRESS_FAMILY address_family;
    _get_remote_address(remote_address, &address_family);
    REQUIRE((address_family == AF_INET || address_family == AF_INET6));
    int protocol = (address_family == AF_INET) ? IPPROTO_IPV4 : IPPROTO_IPV6;
    // Create a RAW receiver socket with protocol being IPV4 or IPV6 based on the address family of the remote host.
    receiver_socket_t receiver_socket(SOCK_RAW, protocol);
    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();
    // Send message to remote host on reflection port.
    const char* message = "Bo!ng";
    _send_message_to_remote_host(message, remote_address);
    // Complete the asynchronous receive and obtain the reflected message.
    receiver_socket.complete_async_receive();
    // Verify if the received message was reflected by remote host.
    PSOCKADDR sender_address = nullptr;
    int sender_length = 0;
    receiver_socket.get_sender_address(sender_address, sender_length);
    REQUIRE(INET_ADDR_EQUAL(
        remote_address.ss_family, INETADDR_ADDRESS((PSOCKADDR)&remote_address), INETADDR_ADDRESS(sender_address)));
    // Verify if the received message is expected.
    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    receiver_socket.get_received_message(bytes_received, received_message);
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
    receiver_socket_t receiver_socket(SOCK_DGRAM, IPPROTO_UDP);
    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();
    // Initialize the remote address.
    struct sockaddr_storage remote_address = {};
    _get_remote_address(remote_address);
    // Send message to remote host on reflection port.
    const char* message = "Bo!ng";
    _send_message_to_remote_host(message, remote_address);
    // Complete the asynchronous receive and obtain the reflected message.
    receiver_socket.complete_async_receive();
    // Verify if the received message is expected.
    uint32_t bytes_received = 0;
    char* received_message = nullptr;
    receiver_socket.get_received_message(bytes_received, received_message);
    REQUIRE(bytes_received == strlen(message));
    REQUIRE(memcmp(received_message, message, strlen(message)) == 0);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::clara;
    auto cli = session.cli() |
               Opt(_remote_ip, "remote IP address")["-rip"]["--remote-ip"]("remote host's IP address in string format");

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