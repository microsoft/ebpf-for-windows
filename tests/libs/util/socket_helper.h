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
#include <vector>

#define CLIENT_MESSAGE "ClientRequestMessage"
#define SERVER_MESSAGE "ServerResponseMessage"

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
    /**
     * @brief Construct a socket and bind it to the specified address.
     *
     * Creates a socket with the specified type and protocol, then binds it to the given
     * port and address. The actual bind error can be retrieved via get_bind_error().
     *
     * @param[in] _sock_type Socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW).
     * @param[in] _protocol Protocol (IPPROTO_TCP, IPPROTO_UDP, etc.).
     * @param[in] port Port to bind to.
     * @param[in] family Socket family (IPv4, IPv6, or Dual).
     * @param[in] source_address Source address to bind to (optional, defaults to wildcard).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _base_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family,
        _In_ const sockaddr_storage& source_address = {},
        int expected_bind_error = 0);
    virtual ~_base_socket();

    /**
     * @brief Get the local address of the socket.
     *
     * @param[out] address Pointer to the local address structure.
     * @param[out] address_length Length of the address structure.
     */
    void
    get_local_address(_Out_ PSOCKADDR& address, _Out_ int& address_length) const;

    /**
     * @brief Get the received message from the socket.
     *
     * @param[out] message_size Size of the received message in bytes.
     * @param[out] message Pointer to the received message buffer.
     */
    void
    get_received_message(_Out_ uint32_t& message_size, _Outref_result_buffer_(message_size) char*& message);

    /**
     * @brief Get the actual error code from the bind operation.
     * @return Winsock error code from WSAGetLastError().
     */
    int
    get_bind_error() const
    {
        return _actual_bind_error;
    }

    /**
     * @brief Check if the bind operation succeeded.
     * @return true if bind succeeded, false otherwise.
     */
    bool
    bind_succeeded() const
    {
        return _bind_succeeded;
    }

  protected:
    SOCKET socket;
    socket_family_t family;
    int sock_type;
    int protocol;
    uint16_t port;
    std::vector<char> recv_buffer;
    uint32_t recv_flags;
    uint32_t bytes_received = 0;
    sockaddr_storage local_address;
    mutable int local_address_size;
    int _actual_bind_error{0};
    bool _bind_succeeded{false};
} base_socket_t;

/**
 * @class An abstract base class for a client socket.
 */
typedef class _client_socket : public _base_socket
{
  public:
    /**
     * @brief Construct a client socket.
     *
     * @param[in] _sock_type Socket type (SOCK_STREAM, SOCK_DGRAM).
     * @param[in] _protocol Protocol (IPPROTO_TCP, IPPROTO_UDP).
     * @param[in] port Port to bind to.
     * @param[in] family Socket family (IPv4, IPv6, or Dual).
     * @param[in] source_address Source address to bind to (optional).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _client_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family,
        _In_ const sockaddr_storage& source_address = {},
        int expected_bind_error = 0);
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
    /**
     * @brief Construct a datagram client socket.
     *
     * @param[in] _sock_type Socket type (SOCK_DGRAM or SOCK_RAW).
     * @param[in] _protocol Protocol (IPPROTO_UDP, etc.).
     * @param[in] port Port to bind to.
     * @param[in] family Socket family (IPv4, IPv6, or Dual).
     * @param[in] connected_udp Whether to use connected UDP mode.
     * @param[in] source_address Source address to bind to (optional).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _datagram_client_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family = Dual,
        bool connected_udp = false,
        _In_ const sockaddr_storage& source_address = {},
        int expected_bind_error = 0);
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
    /**
     * @brief Construct a stream client socket.
     *
     * @param[in] _sock_type Socket type (SOCK_STREAM).
     * @param[in] _protocol Protocol (IPPROTO_TCP).
     * @param[in] port Port to bind to.
     * @param[in] family Socket family (IPv4, IPv6, or Dual).
     * @param[in] source_address Source address to bind to (optional).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _stream_client_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        socket_family_t family = Dual,
        _In_ const sockaddr_storage& source_address = {},
        int expected_bind_error = 0);
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
    /**
     * @brief Receiver operation mode for timeout handling.
     */
    enum receiver_mode
    {
        MODE_TIMEOUT,    ///< Timeout is expected.
        MODE_NO_TIMEOUT, ///< No timeout expected.
        MODE_DONT_CARE   ///< Timeout status doesn't matter.
    };

    /**
     * @brief Construct a server socket.
     *
     * @param[in] _sock_type Socket type (SOCK_STREAM, SOCK_DGRAM).
     * @param[in] _protocol Protocol (IPPROTO_TCP, IPPROTO_UDP).
     * @param[in] port Port to bind to.
     * @param[in] local_address Local address to bind to (optional).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _server_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        _In_ const sockaddr_storage& local_address = {},
        int expected_bind_error = 0);
    ~_server_socket();

    /**
     * @brief Complete an asynchronous receive operation.
     *
     * @param[in] timeout_expected Whether a timeout is expected.
     */
    void
    complete_async_receive(bool timeout_expected = false);

    /**
     * @brief Complete an asynchronous send operation.
     *
     * @param[in] timeout_in_ms Timeout in milliseconds.
     */
    virtual void
    complete_async_send(int timeout_in_ms) = 0;

    /**
     * @brief Complete an asynchronous receive operation with timeout.
     *
     * @param[in] timeout_in_ms Timeout in milliseconds.
     * @param[in] timeout_expected Whether a timeout is expected.
     */
    void
    complete_async_receive(int timeout_in_ms, bool timeout_expected = false);

    /**
     * @brief Complete an asynchronous receive operation with mode.
     *
     * @param[in] timeout_in_ms Timeout in milliseconds.
     * @param[in] mode Receiver mode for timeout handling.
     */
    void
    complete_async_receive(int timeout_in_ms, receiver_mode mode);

    /**
     * @brief Post an asynchronous receive operation.
     */
    virtual void
    post_async_receive() = 0;

    /**
     * @brief Send an asynchronous response message.
     *
     * @param[in] message Null-terminated message string to send.
     */
    virtual void
    send_async_response(_In_z_ const char* message) = 0;

    /**
     * @brief Get the sender's address.
     *
     * @param[out] from Pointer to the sender's address structure.
     * @param[out] from_length Length of the address structure.
     */
    virtual void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length) = 0;

    /**
     * @brief Close the socket.
     */
    virtual void
    close() = 0;

    /**
     * @brief Query the redirect context for the received packet.
     *
     * @param[in,out] buffer Buffer to receive the redirect context.
     * @param[in] buffer_size Size of the buffer in bytes.
     * @return 0 on success, or Windows error code on failure.
     */
    virtual int
    query_redirect_context(_Inout_ void* buffer, uint32_t buffer_size) = 0;

  protected:
    WSAOVERLAPPED overlapped;
    LPFN_WSARECVMSG receive_message;
} receiver_socket_t;

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to receive datagrams.
 */
typedef class _datagram_server_socket : public _server_socket
{
  public:
    /**
     * @brief Construct a datagram server socket.
     *
     * @param[in] _sock_type Socket type (SOCK_DGRAM or SOCK_RAW).
     * @param[in] _protocol Protocol (IPPROTO_UDP, etc.).
     * @param[in] port Port to bind to.
     * @param[in] local_address Local address to bind to (optional).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _datagram_server_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        _In_ const sockaddr_storage& local_address = {},
        int expected_bind_error = 0);
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
    std::vector<char> control_buffer;
    WSAMSG recv_msg;
} datagram_server_socket_t;

/**
 * @class A dual stack stream socket bound to wildcard address that is used to accept inbound connection.
 */
typedef class _stream_server_socket : public _server_socket
{
  public:
    /**
     * @brief Construct a stream server socket.
     *
     * @param[in] _sock_type Socket type (SOCK_STREAM).
     * @param[in] _protocol Protocol (IPPROTO_TCP).
     * @param[in] port Port to bind to.
     * @param[in] local_address Local address to bind to (optional).
     * @param[in] expected_bind_error Expected bind error code (0 = expect success).
     */
    _stream_server_socket(
        int _sock_type,
        int _protocol,
        uint16_t port,
        _In_ const sockaddr_storage& local_address = {},
        int expected_bind_error = 0);
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

/**
 * @class A helper class for managing WSAStartup and WSACleanup.
 */
typedef class _wsa_helper
{
  public:
    _wsa_helper()
    {
        // Initialize the result value to a failure.
        startup_result = -1;
    }
    ~_wsa_helper()
    {
        if (startup_result != -1) {
            WSACleanup();
        }
    }

    int
    initialize()
    {
        WSADATA data{};
        startup_result = WSAStartup(WINSOCK_VERSION, &data);
        if (startup_result != 0) {
            FAIL("WSAStartup failed with error: " << WSAGetLastError());
        }
        return startup_result;
    }

  private:
    int startup_result;
} wsa_helper_t;