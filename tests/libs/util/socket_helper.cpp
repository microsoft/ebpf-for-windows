// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Utility class and functions for doing socket I/O.
 */

#include "catch_wrapper.hpp"
#include "socket_helper.h"

#include <cstring>

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
    } else if (address_info->ai_family == AF_INET6) {
        address.ss_family = AF_INET6;
        INETADDR_SET_ADDRESS((PSOCKADDR)&address, INETADDR_ADDRESS(address_info->ai_addr));
    } else {
        throw "Invalid address family";
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

void
clean_up_socket(_Inout_ SOCKET& socket)
{
    if (socket != INVALID_SOCKET) {
        shutdown(socket, SD_BOTH);
        closesocket(socket);
        socket = INVALID_SOCKET;
    }
}

_base_socket::_base_socket(
    int _sock_type, int _protocol, uint16_t _port, socket_family_t _family, const sockaddr_storage& _source_address)
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

    // Bind to the supplied address and port.
    SOCKADDR_STORAGE local_addr;
    memcpy(&local_addr, &_source_address, sizeof(_source_address));
    local_addr.ss_family = address_family;
    INETADDR_SET_PORT((PSOCKADDR)&local_addr, htons(port));

    // Retry bind operation a few times if it fails with WSAENOBUFS (10055) error as it may be transient.
    for (int i = 0; i < 5; ++i) {
        error = bind(socket, (PSOCKADDR)&local_addr, sizeof(local_addr));
        if (error == 0) {
            break;
        }
        if (WSAGetLastError() != WSAENOBUFS) {
            FAIL("Failed to bind socket with error: " << WSAGetLastError());
        }
        Sleep(1000); // Wait for a short duration before retrying.
    }
}

_base_socket::~_base_socket() { clean_up_socket(socket); }

void
_base_socket::get_local_address(_Out_ PSOCKADDR& address, _Out_ int& address_length) const
{
    // Query the current local address from the socket
    int error = getsockname(socket, (PSOCKADDR)&local_address, &local_address_size);
    if (error != 0) {
        FAIL("Failed to query local address of socket with error: " << WSAGetLastError());
    }

    // Return the freshly queried address
    address = (PSOCKADDR)&local_address;
    address_length = local_address_size;
}

void
_base_socket::get_received_message(_Out_ uint32_t& message_size, _Outref_result_buffer_(message_size) char*& message)
{
    message_size = bytes_received;
    message = recv_buffer.data();
}

_client_socket::_client_socket(
    int _sock_type, int _protocol, uint16_t _port, socket_family_t _family, const sockaddr_storage& _source_address)
    : _base_socket{_sock_type, _protocol, _port, _family, _source_address}, overlapped{}, receive_posted(false)
{
}

void
_client_socket::close()
{
    clean_up_socket(socket);
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

_datagram_client_socket::_datagram_client_socket(
    int _sock_type,
    int _protocol,
    uint16_t _port,
    socket_family_t _family,
    bool _connected_udp,
    const sockaddr_storage& _source_address)
    : _client_socket{_sock_type, _protocol, _port, _family, _source_address}, connected_udp{_connected_udp}
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

    ((PSOCKADDR_IN6)&remote_address)->sin6_port = htons(remote_port);

    // If this is a connected socket, issue a connect call prior to sending traffic.
    if (connected_udp && !connected) {
        error = WSAConnect(
            socket, (const SOCKADDR*)&remote_address, sizeof(remote_address), nullptr, nullptr, nullptr, nullptr);
        if (error != 0) {
            FAIL("WSAConnect failed with " << WSAGetLastError());
            return;
        }
        connected = true;
    }

    // Send a message to the remote host using the sender socket.
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
{
}

void
_datagram_client_socket::complete_async_send(int timeout_in_ms, expected_result_t expected_result)
{
    UNREFERENCED_PARAMETER(timeout_in_ms);
    UNREFERENCED_PARAMETER(expected_result);
}

_stream_client_socket::_stream_client_socket(
    int _sock_type, int _protocol, uint16_t _port, socket_family_t _family, const sockaddr_storage& source_address)
    : _client_socket{_sock_type, _protocol, _port, _family, source_address}, connectex(nullptr)
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

_server_socket::_server_socket(int _sock_type, int _protocol, uint16_t _port, const sockaddr_storage& local_address)
    : _base_socket{_sock_type, _protocol, _port, Dual, local_address}, overlapped{}
{
    overlapped.hEvent = INVALID_HANDLE_VALUE;
    receive_message = nullptr;

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
_server_socket::complete_async_receive(int timeout_in_ms, receiver_mode mode)
{
    int error = 0;
    // Wait for the receiver socket to receive the message.
    error = WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, timeout_in_ms, TRUE);
    if (error == WSA_WAIT_EVENT_0) {
        if (mode == MODE_TIMEOUT) {
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
            if (mode == MODE_NO_TIMEOUT) {
                FAIL("Receiver socket did not receive any message in 1 second.");
            }
        } else {
            FAIL("Waiting on receiver socket failed with " << error);
        }
    }
}

void
_server_socket::complete_async_receive(int timeout_in_ms, bool timeout_expected)
{
    complete_async_receive(timeout_in_ms, timeout_expected ? MODE_TIMEOUT : MODE_NO_TIMEOUT);
}

void
_server_socket::complete_async_receive(bool timeout_expected)
{
    complete_async_receive(1000, timeout_expected);
}

_datagram_server_socket::_datagram_server_socket(
    int _sock_type, int _protocol, uint16_t _port, const sockaddr_storage& local_address)
    : _server_socket{_sock_type, _protocol, _port, local_address}, sender_address{},
      sender_address_size(sizeof(sender_address)), control_buffer(2048), recv_msg{}
{
    if (!(sock_type == SOCK_DGRAM || sock_type == SOCK_RAW) &&
        !(protocol == IPPROTO_UDP || protocol == IPPROTO_IPV4 || protocol == IPPROTO_IPV6))
        FAIL("datagram_client_socket class only supports sockets of type SOCK_DGRAM or SOCK_RAW and protocols of type "
             "IPPROTO_UDP, IPPROTO_IPV4 or IPPROTO_IPV6)");

    // Enable redirect context for UDP sockets
    if (protocol == IPPROTO_UDP) {
        DWORD option_value = 1;

        // Enable IPv4 redirect context only for IPv4 and Dual stack sockets
        if (family == IPv4 || family == Dual) {
            int result = setsockopt(
                socket,
                IPPROTO_IP,
                IP_WFP_REDIRECT_CONTEXT,
                reinterpret_cast<const char*>(&option_value),
                sizeof(option_value));
            if (result != 0) {
                printf("Warning: Failed to set IP_WFP_REDIRECT_CONTEXT option: %d\n", WSAGetLastError());
            }
        }

        // Enable IPv6 redirect context only for IPv6 and Dual stack sockets
        if (family == IPv6 || family == Dual) {
            int result = setsockopt(
                socket,
                IPPROTO_IPV6,
                IPV6_WFP_REDIRECT_CONTEXT,
                reinterpret_cast<const char*>(&option_value),
                sizeof(option_value));
            if (result != 0) {
                printf("Warning: Failed to set IPV6_WFP_REDIRECT_CONTEXT option: %d\n", WSAGetLastError());
            }
        }
    }
}

void
_datagram_server_socket::post_async_receive()
{
    int error = 0;

    WSABUF wsa_recv_buffer{static_cast<unsigned long>(recv_buffer.size()), reinterpret_cast<char*>(recv_buffer.data())};
    WSABUF wsa_control_buffer{
        static_cast<unsigned long>(control_buffer.size()), reinterpret_cast<char*>(control_buffer.data())};

    // Create an event handle and set up the overlapped structure.
    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        FAIL("WSACreateEvent failed with error: " << WSAGetLastError());
    }

    // Set up WSAMSG structure for WSARecvMsg
    recv_msg.name = (LPSOCKADDR)&sender_address;
    recv_msg.namelen = sender_address_size;
    recv_msg.lpBuffers = &wsa_recv_buffer;
    recv_msg.dwBufferCount = 1;
    recv_msg.Control = wsa_control_buffer;
    recv_msg.dwFlags = 0;

    // Post an asynchronous receive using WSARecvMsg to get ancillary data
    error = receive_message(socket, &recv_msg, nullptr, &overlapped, nullptr);

    if (error != 0) {
        int wsaerr = WSAGetLastError();
        if (wsaerr != WSA_IO_PENDING) {
            FAIL("WSARecvMsg failed with " << wsaerr);
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

int
_datagram_server_socket::query_redirect_context(_Inout_ void* buffer, uint32_t buffer_size)
{
    // For UDP sockets, we need to extract redirect context from control messages
    // received via WSARecvMsg when IP_WFP_REDIRECT_CONTEXT option is enabled.

    // Check if we have any control data
    if (recv_msg.Control.len == 0 || recv_msg.Control.buf == nullptr) {
        return 1; // No control messages received
    }

    // Parse control messages to look for IP_WFP_REDIRECT_CONTEXT
    char* control_buf = recv_msg.Control.buf;
    DWORD control_len = recv_msg.Control.len;

    // Control message format: WSACMSGHDR followed by data
    DWORD offset = 0;
    const DWORD cmsg_hdr_size = static_cast<DWORD>(sizeof(WSACMSGHDR));
    while (offset + cmsg_hdr_size <= control_len) {
        WSACMSGHDR* cmsg = reinterpret_cast<WSACMSGHDR*>(control_buf + offset);

        // Validate cmsg_len field before using it
        DWORD msg_len = static_cast<DWORD>(cmsg->cmsg_len);
        if (msg_len == 0 || msg_len < cmsg_hdr_size) {
            break; // Invalid message length
        }

        // Ensure the entire message fits within the control buffer
        if (offset + msg_len > control_len) {
            break; // Message extends beyond buffer
        }

        // Check if this is an IP_WFP_REDIRECT_CONTEXT or IPV6_WFP_REDIRECT_CONTEXT message
        if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_WFP_REDIRECT_CONTEXT) ||
            (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_WFP_REDIRECT_CONTEXT)) {
            // Calculate the actual data size (message length minus header)
            DWORD data_size = msg_len - cmsg_hdr_size;
            // Only process data if it is non-zero in size.
            if (data_size > 0) {
                // Check if buffer is large enough to hold the redirect context data
                if (buffer_size < data_size) {
                    return 1; // Buffer too small
                }

                // Copy the actual redirect context data
                char* data_ptr = control_buf + offset + cmsg_hdr_size;
                memcpy(buffer, data_ptr, data_size);
                return 0; // Success
            }
        }

        // Move to next control message (align to pointer boundary)
        const DWORD align_size = static_cast<DWORD>(sizeof(ULONG_PTR));
        offset += ((msg_len + align_size - 1) & ~(align_size - 1));
    }

    // No IP_WFP_REDIRECT_CONTEXT found
    return 1; // Not found
}

void
_datagram_server_socket::close()
{
    clean_up_socket(socket);
}

_stream_server_socket::_stream_server_socket(
    int _sock_type, int _protocol, uint16_t _port, const sockaddr_storage& local_address)
    : _server_socket{_sock_type, _protocol, _port, local_address}, acceptex(nullptr), accept_socket(INVALID_SOCKET),
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
    clean_up_socket(accept_socket);

    // Create accept socket.
    accept_socket = WSASocket(AF_INET6, sock_type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    uint32_t ipv6_option = 0;
    int error = setsockopt(
        accept_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&ipv6_option), sizeof(unsigned long));
    if (error != 0) {
        FAIL("Could not enable dual family endpoint on accept socket: " << WSAGetLastError());
    }
}

_stream_server_socket::~_stream_server_socket() { clean_up_socket(accept_socket); }

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
    clean_up_socket(accept_socket);
}

int
_stream_server_socket::query_redirect_context(_Inout_ void* buffer, uint32_t buffer_size)
{
    uint32_t redirect_context_size = 0;
    return WSAIoctl(
        accept_socket,
        SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
        nullptr,
        0,
        buffer,
        static_cast<unsigned long>(buffer_size),
        reinterpret_cast<unsigned long*>(&redirect_context_size),
        nullptr,
        nullptr);
}
