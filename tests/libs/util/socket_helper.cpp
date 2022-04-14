// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Utility class and functions for doing socket I/O.
 */

#include "catch_wrapper.hpp"
#include "socket_helper.h"

void
get_address_from_string(
    std::string& address_string, sockaddr_storage& address, _Out_opt_ ADDRESS_FAMILY* address_family)
{
    int error = 0;
    // Initialize the remote address.
    ADDRINFO* address_info = nullptr;
    // Try converting address string to IP address.
    error = getaddrinfo(address_string.data(), nullptr, nullptr, &address_info);
    if (error != 0)
        FAIL("getaddrinfo for" << address_string << " failed with " << WSAGetLastError());
    if (address_info->ai_family == AF_INET) {
        IN6ADDR_SETV4MAPPED(
            (PSOCKADDR_IN6)&address, (IN_ADDR*)INETADDR_ADDRESS(address_info->ai_addr), scopeid_unspecified, 0);
    } else {
        REQUIRE(address_info->ai_family == AF_INET6);
        address.ss_family = AF_INET6;
        INETADDR_SET_ADDRESS((PSOCKADDR)&address, INETADDR_ADDRESS(address_info->ai_addr));
    }
    if (address_family != nullptr)
        *address_family = static_cast<ADDRESS_FAMILY>(address_info->ai_family);
    freeaddrinfo(address_info);
}

_base_socket::_base_socket(int _sock_type, int _protocol, uint16_t _port)
    : socket(INVALID_SOCKET), sock_type(_sock_type), protocol(_protocol), port(_port), local_address{},
      local_address_size(sizeof(local_address))
{
    int error = 0;

    socket = WSASocket(AF_INET6, sock_type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
        FAIL("Failed to create socket with error: " << WSAGetLastError());
    uint32_t ipv6_option = 0;
    error = setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(ULONG));
    if (error != 0)
        FAIL("Could not enable dual family endpoint: " << WSAGetLastError());

    // Bind it to the wildcard address and supplied port.
    SOCKADDR_STORAGE local_addr;
    local_addr.ss_family = AF_INET6;
    INETADDR_SETANY((PSOCKADDR)&local_addr);
    ((PSOCKADDR_IN6)&local_addr)->sin6_port = htons(port);

    error = bind(socket, (PSOCKADDR)&local_addr, sizeof(local_addr));
    if (error != 0)
        FAIL("Failed to bind socket with error: " << WSAGetLastError());

    error = getsockname(socket, (PSOCKADDR)&local_address, &local_address_size);
    if (error != 0)
        FAIL("Failed to query local address of socket with error: " << WSAGetLastError());
}

_base_socket::~_base_socket() { closesocket(socket); }

void
_base_socket::get_local_address(_Out_ PSOCKADDR& address, _Out_ int& address_length)
{
    address = (PSOCKADDR)&local_address;
    address_length = local_address_size;
}

_sender_socket::_sender_socket(int _sock_type, int _protocol, uint16_t _port)
    : _base_socket{_sock_type, _protocol, _port}
{}

_datagram_sender_socket::_datagram_sender_socket(int _sock_type, int _protocol, uint16_t _port)
    : _sender_socket{_sock_type, _protocol, _port}
{
    if (!(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) &&
        !(protocol == IPPROTO_UDP || protocol == IPPROTO_IPV4 || protocol == IPPROTO_IPV6))
        FAIL("datagram_sender_socket class only supports sockets of type SOCK_DGRAM or SOCK_RAW and protocols of type "
             "IPPROTO_UDP, IPPROTO_IPV4 or IPPROTO_IPV6)");
}

void
_datagram_sender_socket::send_message_to_remote_host(
    _In_z_ const char* message, sockaddr_storage& remote_address, uint16_t remote_port)
{
    int error = 0;

    // Send a message to the remote host using the sender socket.
    ((PSOCKADDR_IN6)&remote_address)->sin6_port = htons(remote_port);
    std::vector<char> send_buffer(message, message + strlen(message));
    WSABUF wsa_send_buffer{static_cast<ULONG>(send_buffer.size()), reinterpret_cast<char*>(send_buffer.data())};
    uint32_t bytes_sent = 0;
    uint32_t send_flags = 0;
    error = WSASendTo(
        socket,
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
}

void
_datagram_sender_socket::cancel_send_message()
{}

_stream_sender_socket::_stream_sender_socket(int _sock_type, int _protocol, uint16_t _port)
    : _sender_socket{_sock_type, _protocol, _port}, connectex(nullptr), overlapped{}
{
    if ((sock_type != SOCK_STREAM) || (protocol != IPPROTO_TCP))
        FAIL("stream_socket only supports these combinations (SOCK_STREAM, IPPROTO_TCP)");

    GUID guid = WSAID_CONNECTEX;
    uint32_t bytes;
    int error = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        sizeof(guid),
        &connectex,
        sizeof(connectex),
        reinterpret_cast<LPDWORD>(&bytes),
        NULL,
        NULL);

    if (error != 0)
        FAIL("Obtaining ConnectEx function pointer failed with " << WSAGetLastError());
}

void
_stream_sender_socket::send_message_to_remote_host(
    _In_z_ const char* message, sockaddr_storage& remote_address, uint16_t remote_port)
{
    // Send a message to the remote host using the sender socket.
    ((PSOCKADDR_IN6)&remote_address)->sin6_port = htons(remote_port);
    std::vector<char> send_buffer(message, message + strlen(message));
    uint32_t bytes_sent = 0;
    overlapped.hEvent = WSACreateEvent();
    if (!connectex(
            socket,
            (PSOCKADDR)&remote_address,
            sizeof(remote_address),
            send_buffer.data(),
            static_cast<DWORD>(send_buffer.size()),
            reinterpret_cast<LPDWORD>(&bytes_sent),
            &overlapped)) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING)
            FAIL("ConnectEx failed with " << wsaerr);
    }
}

void
_stream_sender_socket::cancel_send_message()
{
    CancelIoEx((HANDLE)socket, &overlapped);
    WSACloseEvent(overlapped.hEvent);
}

_receiver_socket::_receiver_socket(int _sock_type, int _protocol, uint16_t _port)
    : _base_socket{_sock_type, _protocol, _port}, overlapped{}, recv_buffer(std::vector<char>(1024)), recv_flags(0)
{}

_receiver_socket::~_receiver_socket() { WSACloseEvent(overlapped.hEvent); }

void
_receiver_socket::complete_async_receive(bool timeout_expected)
{
    int error = 0;
    // Wait for the receiver socket to receive the message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, 1000, TRUE);
    if (error == WSA_WAIT_EVENT_0) {
        if (timeout_expected)
            FAIL("Receiver socket received a message when timeout was expected.");

        if (!WSAGetOverlappedResult(
                socket,
                &overlapped,
                reinterpret_cast<LPDWORD>(&bytes_received),
                FALSE,
                reinterpret_cast<LPDWORD>(&recv_flags)))
            FAIL("WSARecvFrom on the receiver socket failed with error: " << WSAGetLastError());
        WSACloseEvent(overlapped.hEvent);
    } else {
        if (error == WSA_WAIT_TIMEOUT) {
            if (!timeout_expected)
                FAIL("Receiver socket did not receive any message in 1 second.");
        } else {
            FAIL("Waiting on receiver socket failed with " << error);
        }
    }
}

void
_receiver_socket::get_received_message(
    _Out_ uint32_t& message_size, _Outref_result_buffer_(message_size) char*& message)
{
    message_size = bytes_received;
    message = recv_buffer.data();
}

_datagram_receiver_socket::_datagram_receiver_socket(int _sock_type, int _protocol, uint16_t _port)
    : _receiver_socket{_sock_type, _protocol, _port}, sender_address{}, sender_address_size(sizeof(sender_address))

{
    if (!(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) &&
        !(protocol == IPPROTO_UDP || protocol == IPPROTO_IPV4 || protocol == IPPROTO_IPV6))
        FAIL("datagram_sender_socket class only supports sockets of type SOCK_DGRAM or SOCK_RAW and protocols of type "
             "IPPROTO_UDP, IPPROTO_IPV4 or IPPROTO_IPV6)");
}

void
_datagram_receiver_socket::post_async_receive()
{
    int error = 0;

    WSABUF wsa_recv_buffer{static_cast<ULONG>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL)
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());

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
_datagram_receiver_socket::get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length)
{
    from = (PSOCKADDR)&sender_address;
    from_length = sender_address_size;
}

_stream_receiver_socket::_stream_receiver_socket(int _sock_type, int _protocol, uint16_t _port)
    : _receiver_socket{_sock_type, _protocol, _port}, acceptex(nullptr), accept_socket(0),
      message_length(recv_buffer.size() - 2 * (sizeof(sockaddr_storage) + 16))
{
    if ((sock_type != SOCK_STREAM) || (protocol != IPPROTO_TCP))
        FAIL("stream_socket only supports these combinations (SOCK_STREAM, IPPROTO_TCP)");

    GUID guid = WSAID_ACCEPTEX;
    uint32_t bytes;
    int error = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        sizeof(guid),
        &acceptex,
        sizeof(acceptex),
        reinterpret_cast<LPDWORD>(&bytes),
        NULL,
        NULL);

    if (error != 0)
        FAIL("Obtaining AcceptEx function pointer failed with " << WSAGetLastError());

    // Post listen.
    listen(socket, SOMAXCONN);

    // Create accept socket.
    accept_socket = WSASocket(AF_INET6, sock_type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    uint32_t ipv6_option = 0;
    error = setsockopt(
        accept_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(ULONG));
    if (error != 0)
        FAIL("Could not enable dual family endpoint on accept socket: " << WSAGetLastError());
}

_stream_receiver_socket::~_stream_receiver_socket() { closesocket(accept_socket); }

void
_stream_receiver_socket::post_async_receive()
{
    WSABUF wsa_recv_buffer{static_cast<ULONG>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL)
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());

    // Post an asynchronous receive on the socket.
    if (!acceptex(
            socket,        // Listen socket.
            accept_socket, // Accept socket.
            recv_buffer.data(),
            static_cast<DWORD>(message_length),
            static_cast<DWORD>(sizeof(sockaddr_storage)) + 16,
            static_cast<DWORD>(sizeof(sockaddr_storage)) + 16,
            reinterpret_cast<LPDWORD>(&bytes_received),
            &overlapped)) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING)
            FAIL("AcceptEx failed with " << wsaerr);
    }
}

void
_stream_receiver_socket::get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length)
{
    from = (PSOCKADDR)(recv_buffer.data() + message_length);
    from_length = sizeof(sockaddr_storage);
}