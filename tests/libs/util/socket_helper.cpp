// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Utility class and functions for doing socket I/O.
 */

#include "catch_wrapper.hpp"
#include "socket_helper.h"

#define MAXIMUM_IP_BUFFER_SIZE 65

uint64_t
get_current_pid_tgid()
{
    return ((uint64_t)GetCurrentProcessId() << 32 | GetCurrentThreadId());
}

void
get_address_from_string(
    std::string& address_string, sockaddr_storage& address, bool dual_stack, _Out_opt_ ADDRESS_FAMILY* address_family)
{
    int error = 0;
    // Initialize the remote address.
    ADDRINFO* address_info = nullptr;
    // Try converting address string to IP address.
    error = getaddrinfo(address_string.data(), nullptr, nullptr, &address_info);
    if (error != 0) {
        FAIL("getaddrinfo for" << address_string << " failed with " << WSAGetLastError());
    }
    if (address_info->ai_family == AF_INET) {
        if (dual_stack) {
            IN6ADDR_SETV4MAPPED(
                (PSOCKADDR_IN6)&address, (IN_ADDR*)INETADDR_ADDRESS(address_info->ai_addr), scopeid_unspecified, 0);
        } else {
            address.ss_family = AF_INET;
            INETADDR_SET_ADDRESS((PSOCKADDR)&address, INETADDR_ADDRESS(address_info->ai_addr));
        }
    } else {
        REQUIRE(address_info->ai_family == AF_INET6);
        address.ss_family = AF_INET6;
        INETADDR_SET_ADDRESS((PSOCKADDR)&address, INETADDR_ADDRESS(address_info->ai_addr));
    }
    if (address_family != nullptr) {
        *address_family = static_cast<ADDRESS_FAMILY>(address_info->ai_family);
    }
    freeaddrinfo(address_info);
}

std::string
get_string_from_address(_In_ const SOCKADDR* sockaddr)
{
    char ip_string[MAXIMUM_IP_BUFFER_SIZE] = {0};

    unsigned long length = sizeof(ip_string);
    int error = WSAAddressToStringA(
        const_cast<SOCKADDR*>(sockaddr),
        (unsigned long)INET_SOCKADDR_LENGTH(sockaddr->sa_family),
        nullptr,
        ip_string,
        &length);
    if (error != 0) {
        error = WSAGetLastError();
        printf("Failure calling WSAAddressToStringA with error code %d\n", error);
    }
    return std::string(ip_string);
}

_base_socket::_base_socket(int _sock_type, int _protocol, uint16_t _port, socket_family_t _family)
    : socket(INVALID_SOCKET), family(_family), sock_type(_sock_type), protocol(_protocol), port(_port), local_address{},
      local_address_size(sizeof(local_address)), recv_buffer(std::vector<char>(1024)), recv_flags(0)
{
    int error = 0;

    ADDRESS_FAMILY address_family = (family == IPv4) ? AF_INET : AF_INET6;
    socket = WSASocket(address_family, sock_type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET) {
        FAIL("Failed to create socket with error: " << WSAGetLastError());
    }

    if (family == Dual) {
        uint32_t ipv6_option = 0;
        error = setsockopt(
            socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(unsigned long));
        if (error != 0) {
            FAIL("Could not enable dual family endpoint: " << WSAGetLastError());
        }
    }

    // Bind it to the wildcard address and supplied port.
    SOCKADDR_STORAGE local_addr;
    local_addr.ss_family = address_family;
    INETADDR_SETANY((PSOCKADDR)&local_addr);
    INETADDR_SET_PORT((PSOCKADDR)&local_addr, htons(port));

    error = bind(socket, (PSOCKADDR)&local_addr, sizeof(local_addr));
    if (error != 0) {
        FAIL("Failed to bind socket with error: " << WSAGetLastError());
    }

    error = getsockname(socket, (PSOCKADDR)&local_address, &local_address_size);
    if (error != 0) {
        FAIL("Failed to query local address of socket with error: " << WSAGetLastError());
    }
}

_base_socket::~_base_socket()
{
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
    }
}

void
_base_socket::get_local_address(_Out_ PSOCKADDR& address, _Out_ int& address_length) const
{
    address = (PSOCKADDR)&local_address;
    address_length = local_address_size;
}

void
_base_socket::get_received_message(_Out_ uint32_t& message_size, _Outref_result_buffer_(message_size) char*& message)
{
    message_size = bytes_received;
    message = recv_buffer.data();
}

_client_socket::_client_socket(int _sock_type, int _protocol, uint16_t _port, socket_family_t _family)
    : _base_socket{_sock_type, _protocol, _port, _family}, overlapped{}
{}

void
_client_socket::close()
{
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
    }
}

void
_client_socket::post_async_receive(bool error_expected)
{
    if (receive_posted) {
        return;
    }

    int error = 0;
    int wsaerr = 0;

    WSABUF wsa_recv_buffer{static_cast<unsigned long>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());
    }

    // Post an asynchronous receive on the socket.
    error = WSARecv(
        socket,
        &wsa_recv_buffer,
        1,
        reinterpret_cast<unsigned long*>(&bytes_received),
        reinterpret_cast<unsigned long*>(&recv_flags),
        &overlapped,
        nullptr);

    if (error != 0) {
        wsaerr = WSAGetLastError();
        if (!error_expected && wsaerr != WSA_IO_PENDING) {
            FAIL("_client_socket::post_async_receive: WSARecv failed with " << wsaerr);
        }
    }
    if (error == 0 || wsaerr == WSA_IO_PENDING) {
        receive_posted = true;
    }
}

void
_client_socket::complete_async_receive(int timeout_in_ms, bool timeout_or_error_expected)
{
    if (overlapped.hEvent == INVALID_HANDLE_VALUE) {
        printf("complete_async_receive: overlapped event already closed\n");
        return;
    }

    int error = 0;
    // Wait for the receiver socket to receive the message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, timeout_in_ms, TRUE);
    if (error == WSA_WAIT_EVENT_0) {
        if (timeout_or_error_expected) {
            FAIL("Receiver socket received a message when timeout was expected.");
        }

        bool result = WSAGetOverlappedResult(
            socket,
            &overlapped,
            reinterpret_cast<unsigned long*>(&bytes_received),
            FALSE,
            reinterpret_cast<unsigned long*>(&recv_flags));
        if (!result && !timeout_or_error_expected) {
            FAIL("WSARecvFrom on the receiver socket failed with error: " << WSAGetLastError());
        }
        WSACloseEvent(overlapped.hEvent);
        overlapped.hEvent = INVALID_HANDLE_VALUE;
        receive_posted = false;
    } else {
        if (error == WSA_WAIT_TIMEOUT) {
            if (!timeout_or_error_expected) {
                FAIL("Receiver socket did not receive any message in 1 second.");
            }
        } else {
            FAIL("Waiting on receiver socket failed with " << error);
        }
    }
}

_datagram_client_socket::_datagram_client_socket(int _sock_type, int _protocol, uint16_t _port, socket_family_t _family)
    : _client_socket{_sock_type, _protocol, _port, _family}
{
    if (!(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) &&
        !(protocol == IPPROTO_UDP || protocol == IPPROTO_IPV4 || protocol == IPPROTO_IPV6))
        FAIL("datagram_client_socket class only supports sockets of type SOCK_DGRAM or SOCK_RAW and protocols of type "
             "IPPROTO_UDP, IPPROTO_IPV4 or IPPROTO_IPV6)");
}

void
_datagram_client_socket::send_message_to_remote_host(
    _In_z_ const char* message, _Inout_ sockaddr_storage& remote_address, uint16_t remote_port)
{
    int error = 0;

    // Send a message to the remote host using the sender socket.
    ((PSOCKADDR_IN6)&remote_address)->sin6_port = htons(remote_port);
    std::vector<char> send_buffer(message, message + strlen(message));
    WSABUF wsa_send_buffer{static_cast<unsigned long>(send_buffer.size()), reinterpret_cast<char*>(send_buffer.data())};
    uint32_t bytes_sent = 0;
    uint32_t send_flags = 0;
    error = WSASendTo(
        socket,
        &wsa_send_buffer,
        1,
        reinterpret_cast<unsigned long*>(&bytes_sent),
        send_flags,
        (const SOCKADDR*)&remote_address,
        sizeof(remote_address),
        nullptr,
        nullptr);

    if (error != 0) {
        FAIL("Sending message to remote host failed with " << WSAGetLastError());
    }
}

void
_datagram_client_socket::cancel_send_message()
{}

void
_datagram_client_socket::complete_async_send(int timeout_in_ms, expected_result_t expected_result)
{
    UNREFERENCED_PARAMETER(timeout_in_ms);
    UNREFERENCED_PARAMETER(expected_result);
}

_stream_client_socket::_stream_client_socket(int _sock_type, int _protocol, uint16_t _port, socket_family_t _family)
    : _client_socket{_sock_type, _protocol, _port, _family}, connectex(nullptr)
{
    if ((sock_type != SOCK_STREAM) || (protocol != IPPROTO_TCP)) {
        FAIL("stream_socket only supports these combinations (SOCK_STREAM, IPPROTO_TCP)");
    }

    GUID guid = WSAID_CONNECTEX;
    uint32_t bytes;
    int error = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        sizeof(guid),
        &connectex,
        sizeof(connectex),
        reinterpret_cast<unsigned long*>(&bytes),
        NULL,
        NULL);

    if (error != 0) {
        FAIL("Obtaining ConnectEx function pointer failed with " << WSAGetLastError());
    }
}

void
_stream_client_socket::send_message_to_remote_host(
    _In_z_ const char* message, _Inout_ sockaddr_storage& remote_address, uint16_t remote_port)
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
            static_cast<unsigned long>(send_buffer.size()),
            reinterpret_cast<unsigned long*>(&bytes_sent),
            &overlapped)) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING) {
            FAIL("ConnectEx failed with " << wsaerr);
        }
    } else {
        // The operation completed synchronously. Close overlapped handle.
        WSACloseEvent(overlapped.hEvent);
        overlapped.hEvent = INVALID_HANDLE_VALUE;
        printf("send_message_to_remote_host: send already completed. Closing overlapped handle\n");
    }
}

void
_stream_client_socket::cancel_send_message()
{
    CancelIoEx((HANDLE)socket, &overlapped);
    WSACloseEvent(overlapped.hEvent);
    overlapped.hEvent = INVALID_HANDLE_VALUE;
}

void
_stream_client_socket::complete_async_send(int timeout_in_ms, expected_result_t expected_result)
{
    if (overlapped.hEvent == INVALID_HANDLE_VALUE) {
        printf("complete_async_send: overlapped event already closed\n");
        return;
    }

    int error = 0;
    uint32_t bytes_sent = 0;
    uint32_t send_flags = 0;
    // Wait for the receiver socket to receive the message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, timeout_in_ms, TRUE);
    if (error == WSA_WAIT_EVENT_0) {
        if (expected_result == expected_result_t::TIMEOUT) {
            FAIL("Send on socket succeeded when timeout was expected.");
        }
        if (!WSAGetOverlappedResult(
                socket,
                &overlapped,
                reinterpret_cast<unsigned long*>(&bytes_sent),
                FALSE,
                reinterpret_cast<unsigned long*>(&send_flags))) {
            if (expected_result != expected_result_t::FAILURE) {
                FAIL("WSASend on the socket failed with error: " << WSAGetLastError());
            }
        }
        WSACloseEvent(overlapped.hEvent);
        overlapped.hEvent = INVALID_HANDLE_VALUE;
    } else if (error == WSA_WAIT_TIMEOUT) {
        if (expected_result != expected_result_t::TIMEOUT) {
            FAIL("Async send timed out");
        }
    } else {
        FAIL("Async send complete failed with " << error);
    }
}

_server_socket::_server_socket(int _sock_type, int _protocol, uint16_t _port)
    : _base_socket{_sock_type, _protocol, _port, Dual}, overlapped{}
{
    overlapped.hEvent = INVALID_HANDLE_VALUE;

    GUID guid = WSAID_WSARECVMSG;
    uint32_t bytes;
    int error = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        sizeof(guid),
        &receive_message,
        sizeof(receive_message),
        reinterpret_cast<unsigned long*>(&bytes),
        NULL,
        NULL);

    if (error != 0) {
        FAIL("Obtaining ReceiveMsg function pointer failed with " << WSAGetLastError());
    }
}

_server_socket::~_server_socket()
{
    if (overlapped.hEvent != INVALID_HANDLE_VALUE) {
        WSACloseEvent(overlapped.hEvent);
    }
}

void
_server_socket::complete_async_receive(int timeout_in_ms, bool timeout_expected)
{
    int error = 0;
    // Wait for the receiver socket to receive the message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, timeout_in_ms, TRUE);
    if (error == WSA_WAIT_EVENT_0) {
        if (timeout_expected) {
            FAIL("Receiver socket received a message when timeout was expected.");
        }

        if (!WSAGetOverlappedResult(
                socket,
                &overlapped,
                reinterpret_cast<unsigned long*>(&bytes_received),
                FALSE,
                reinterpret_cast<unsigned long*>(&recv_flags)))
            FAIL("WSARecvFrom on the receiver socket failed with error: " << WSAGetLastError());
        WSACloseEvent(overlapped.hEvent);
        overlapped.hEvent = INVALID_HANDLE_VALUE;
    } else {
        if (error == WSA_WAIT_TIMEOUT) {
            if (!timeout_expected) {
                FAIL("Receiver socket did not receive any message in 1 second.");
            }
        } else {
            FAIL("Waiting on receiver socket failed with " << error);
        }
    }
}

void
_server_socket::complete_async_receive(bool timeout_expected)
{
    complete_async_receive(1000, timeout_expected);
}

_datagram_server_socket::_datagram_server_socket(int _sock_type, int _protocol, uint16_t _port)
    : _server_socket{_sock_type, _protocol, _port}, sender_address{}, sender_address_size(sizeof(sender_address))
{
    if (!(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) &&
        !(protocol == IPPROTO_UDP || protocol == IPPROTO_IPV4 || protocol == IPPROTO_IPV6))
        FAIL("datagram_client_socket class only supports sockets of type SOCK_DGRAM or SOCK_RAW and protocols of type "
             "IPPROTO_UDP, IPPROTO_IPV4 or IPPROTO_IPV6)");
}

void
_datagram_server_socket::post_async_receive()
{
    int error = 0;

    WSABUF wsa_recv_buffer{static_cast<unsigned long>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());
    }

    // Post an asynchronous receive on the socket.
    error = WSARecvFrom(
        socket,
        &wsa_recv_buffer,
        1,
        nullptr,
        reinterpret_cast<unsigned long*>(&recv_flags),
        (PSOCKADDR)&sender_address,
        &sender_address_size,
        &overlapped,
        nullptr);
    if (error != 0) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING) {
            FAIL("WSARecvFrom failed with " << wsaerr);
        }
    }
}

void
_datagram_server_socket::get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length)
{
    from = (PSOCKADDR)&sender_address;
    from_length = sender_address_size;
}

void
_datagram_server_socket::send_async_response(_In_z_ const char* message)
{
    int error = 0;

    // Send a response to the sender.
    std::vector<char> send_buffer(message, message + strlen(message));
    WSABUF wsa_send_buffer{static_cast<unsigned long>(send_buffer.size()), reinterpret_cast<char*>(send_buffer.data())};
    uint32_t bytes_sent = 0;
    uint32_t send_flags = 0;
    error = WSASendTo(
        socket,
        &wsa_send_buffer,
        1,
        reinterpret_cast<unsigned long*>(&bytes_sent),
        send_flags,
        (PSOCKADDR)&sender_address,
        sizeof(sender_address),
        nullptr,
        nullptr);

    if (error != 0) {
        FAIL("send_async_response failed with " << WSAGetLastError());
    }
}

void
_datagram_server_socket::complete_async_send(int timeout_in_ms)
{
    UNREFERENCED_PARAMETER(timeout_in_ms);
}

void
_datagram_server_socket::close()
{
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
    }
}

_stream_server_socket::_stream_server_socket(int _sock_type, int _protocol, uint16_t _port)
    : _server_socket{_sock_type, _protocol, _port}, acceptex(nullptr), accept_socket(INVALID_SOCKET),
      message_length(recv_buffer.size() - 2 * (sizeof(sockaddr_storage) + 16))
{
    if ((sock_type != SOCK_STREAM) || (protocol != IPPROTO_TCP)) {
        FAIL("stream_socket only supports these combinations (SOCK_STREAM, IPPROTO_TCP)");
    }

    GUID guid = WSAID_ACCEPTEX;
    uint32_t bytes;
    int error = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        sizeof(guid),
        &acceptex,
        sizeof(acceptex),
        reinterpret_cast<unsigned long*>(&bytes),
        NULL,
        NULL);

    if (error != 0) {
        FAIL("Obtaining AcceptEx function pointer failed with " << WSAGetLastError());
    }

    // Post listen.
    listen(socket, SOMAXCONN);

    // Create accept socket.
    initialize_accept_socket();
}

void
_stream_server_socket::initialize_accept_socket()
{
    // Close a previous accept socket, if present.
    if (accept_socket != INVALID_SOCKET) {
        closesocket(accept_socket);
        accept_socket = INVALID_SOCKET;
    }

    // Create accept socket.
    accept_socket = WSASocket(AF_INET6, sock_type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    uint32_t ipv6_option = 0;
    int error = setsockopt(
        accept_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(unsigned long));
    if (error != 0) {
        FAIL("Could not enable dual family endpoint on accept socket: " << WSAGetLastError());
    }
}

_stream_server_socket::~_stream_server_socket()
{
    if (accept_socket != INVALID_SOCKET) {
        closesocket(accept_socket);
    }
}

void
_stream_server_socket::post_async_receive()
{
    initialize_accept_socket();

    WSABUF wsa_recv_buffer{static_cast<unsigned long>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());
    }

    // Post an asynchronous receive on the socket.
    if (!acceptex(
            socket,        // Listen socket.
            accept_socket, // Accept socket.
            recv_buffer.data(),
            static_cast<unsigned long>(message_length),
            static_cast<unsigned long>(sizeof(sockaddr_storage)) + 16,
            static_cast<unsigned long>(sizeof(sockaddr_storage)) + 16,
            reinterpret_cast<unsigned long*>(&bytes_received),
            &overlapped)) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING) {
            FAIL("AcceptEx failed with " << wsaerr);
        }
    }
}

void
_stream_server_socket::send_async_response(_In_z_ const char* message)
{
    // Send a message to the remote host using the sender socket.
    std::vector<char> send_buffer(message, message + strlen(message));
    WSABUF wsa_send_buffer{static_cast<unsigned long>(send_buffer.size()), reinterpret_cast<char*>(send_buffer.data())};
    uint32_t bytes_sent = 0;
    overlapped.hEvent = WSACreateEvent();
    int32_t error = WSASend(
        accept_socket, &wsa_send_buffer, 1, reinterpret_cast<unsigned long*>(&bytes_sent), 0, &overlapped, NULL);
    if (error != 0) {
        int wsaerr = WSAGetLastError();
        FAIL("send_async_response failed with " << wsaerr);
    }
}

void
_stream_server_socket::complete_async_send(int timeout_in_ms)
{
    int error = 0;
    uint32_t bytes_sent = 0;
    uint32_t send_flags = 0;
    // Wait for the receiver socket to receive the message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, timeout_in_ms, TRUE);
    if (error == WSA_WAIT_EVENT_0) {

        if (!WSAGetOverlappedResult(
                socket,
                &overlapped,
                reinterpret_cast<unsigned long*>(&bytes_sent),
                FALSE,
                reinterpret_cast<unsigned long*>(&send_flags)))
            FAIL("WSASend on the receiver socket failed with error: " << WSAGetLastError());
        WSACloseEvent(overlapped.hEvent);
        overlapped.hEvent = INVALID_HANDLE_VALUE;
    } else {
        FAIL("Waiting on receiver socket failed with " << error);
    }
}

void
_stream_server_socket::get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length)
{
    from = (PSOCKADDR)(recv_buffer.data() + message_length);
    from_length = sizeof(sockaddr_storage);
}

void
_stream_server_socket::close()
{
    if (accept_socket != INVALID_SOCKET) {
        closesocket(accept_socket);
    }
}
