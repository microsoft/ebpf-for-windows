// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @brief Utility class and functions for doing socket I/O.
 */

#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Mswsock.h>
#include <mstcpip.h>
#include <netiodef.h>

#define CLIENT_MESSAGE "request from client"
#define SERVER_MESSAGE "response from server"

typedef enum _socket_family
{
    IPv4,
    IPv6,
    Dual,
    Max
} socket_family_t;

/**
 * @brief Helper function that converts an IP address string into a sockaddr_storage with address family 6, unspecified
 * scope and port set to zero. A v4-mapped IPv6 address is returned if the input address string is IPv4.
 */
void
get_address_from_string(
    std::string& address_string,
    sockaddr_storage& address,
    bool dual_stack = true,
    _Out_opt_ ADDRESS_FAMILY* address_family = nullptr);

std::string
get_string_from_address(_In_ const SOCKADDR* sockaddr);

typedef enum _expected_result
{
    SUCCESS,
    TIMEOUT,
    FAILURE,
} expected_result_t;

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to receive datagrams.
 */
typedef class _base_socket
{
  public:
    _base_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family,
        const sockaddr_storage& source_address = {});
    virtual ~_base_socket();

    void
    get_local_address(_Out_ PSOCKADDR& address, _Out_ int& address_length) const;

    void
    get_received_message(_Out_ uint32_t& message_size, _Outref_result_buffer_(message_size) char*& message);

  protected:
    SOCKET socket;
    socket_family_t family;
    int sock_type;
    int protocol;
    uint16_t port;
    std::vector<char> recv_buffer;
    uint32_t recv_flags;
    uint32_t bytes_received = 0;

  private:
    sockaddr_storage local_address;
    int local_address_size;
} base_socket_t;

/**
 * @class An abstract base class for a client socket.
 */
typedef class _client_socket : public _base_socket
{
  public:
    _client_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family,
        const sockaddr_storage& source_address = {});
    virtual void
    send_message_to_remote_host(
        _In_z_ const char* message, _Inout_ sockaddr_storage& remote_address, uint16_t remote_port) = 0;
    virtual void
    complete_async_send(int timeout_in_ms, expected_result_t expected_result = expected_result_t::SUCCESS) = 0;
    virtual void
    post_async_receive(bool error_expected = false);
    virtual void
    complete_async_receive(int timeout_in_ms, bool timeout_or_error_expected);
    virtual void
    cancel_send_message() = 0;
    void
    close();

  protected:
    WSAOVERLAPPED overlapped;
    bool receive_posted;
} client_socket_t;

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to send messages to a remote host.
 */
typedef class _datagram_client_socket : public _client_socket
{
  public:
    _datagram_client_socket(
        int _sock_type, int _protocol, uint16_t port, socket_family_t family = Dual, bool connected_udp = false);
    void
    send_message_to_remote_host(
        _In_z_ const char* message, _Inout_ sockaddr_storage& remote_address, uint16_t remote_port);
    void
    cancel_send_message();
    void
    complete_async_send(int timeout_in_ms, expected_result_t expected_result = expected_result_t::SUCCESS);

  private:
    // Indicates if connected UDP should be used.
    bool connected_udp = false;

    // Indicates if we have already called connect on this socket.
    bool connected = false;
} datagram_client_socket_t;

/**
 * @class A dual stack stream socket bound to wildcard address that is used to connect to a remote host.
 */
typedef class _stream_client_socket : public _client_socket
{
  public:
    _stream_client_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family = Dual,
        const sockaddr_storage& source_address = {});
    void
    send_message_to_remote_host(
        _In_z_ const char* message, _Inout_ sockaddr_storage& remote_address, uint16_t remote_port);
    void
    cancel_send_message();
    void
    complete_async_send(int timeout_in_ms, expected_result_t expected_result = expected_result_t::SUCCESS);

  private:
    LPFN_CONNECTEX connectex;
} stream_client_socket_t;

/**
 * @class An abstract base class for a receiver socket.
 */
typedef class _server_socket : public _base_socket
{
  public:
    _server_socket(int _sock_type, int _protocol, uint16_t port);
    ~_server_socket();
    void
    complete_async_receive(bool timeout_expected = false);
    virtual void
    complete_async_send(int timeout_in_ms) = 0;
    void
    complete_async_receive(int timeout_in_ms, bool timeout_expected = false);

    virtual void
    post_async_receive() = 0;
    virtual void
    send_async_response(_In_z_ const char* message) = 0;
    virtual void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length) = 0;
    virtual void
    close() = 0;
    virtual int
    query_redirect_context(_Inout_ void* buffer, uint32_t buffer_size) = 0;

  protected:
    WSAOVERLAPPED overlapped;

  private:
    LPFN_WSARECVMSG receive_message;
} receiver_socket_t;

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to receive datagrams.
 */
typedef class _datagram_server_socket : public _server_socket
{
  public:
    _datagram_server_socket(int _sock_type, int _protocol, uint16_t port);
    void
    post_async_receive();
    void
    send_async_response(_In_z_ const char* message);
    void
    complete_async_send(int timeout_in_ms);
    void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length);
    void
    close();
    int
    query_redirect_context(_Inout_ void* buffer, uint32_t buffer_size);

  private:
    sockaddr_storage sender_address;
    int sender_address_size;
} datagram_server_socket_t;

/**
 * @class A dual stack stream socket bound to wildcard address that is used to accept inbound connection.
 */
typedef class _stream_server_socket : public _server_socket
{
  public:
    _stream_server_socket(int _sock_type, int _protocol, uint16_t port);
    ~_stream_server_socket();
    void
    post_async_receive();
    void
    send_async_response(_In_z_ const char* message);
    void
    complete_async_send(int timeout_in_ms);
    void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length);
    void
    close();
    int
    query_redirect_context(_Inout_ void* buffer, uint32_t buffer_size);

  private:
    void
    initialize_accept_socket();

    LPFN_ACCEPTEX acceptex;
    SOCKET accept_socket;
    size_t message_length;
} stream_server_socket_t;
