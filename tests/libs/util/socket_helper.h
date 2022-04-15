// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Utility class and functions for doing socket I/O.
 */

#pragma once
#include <netiodef.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <mstcpip.h>
#include <Mswsock.h>

/**
 * @brief Helper function that converts an IP address string into a sockaddr_storage with address family 6, unspecified
 * scope and port set to zero. A v4 mapped IPv6 address is returned if the input address string is IPv4.
 */
void
get_address_from_string(
    std::string& address_string, sockaddr_storage& address, _Out_opt_ ADDRESS_FAMILY* address_family = nullptr);

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to receive datagrams.
 */
typedef class _base_socket
{
  public:
    _base_socket(int _sock_type, int _protocol, uint16_t port);
    ~_base_socket();

    void
    get_local_address(_Out_ PSOCKADDR& address, _Out_ int& address_length);

  protected:
    SOCKET socket;
    int sock_type;
    int protocol;
    uint16_t port;

  private:
    sockaddr_storage local_address;
    int local_address_size;
} base_socket_t;

/**
 * @class An abstract base class for a sender socket.
 */
typedef class _sender_socket : public _base_socket
{
  public:
    _sender_socket(int _sock_type, int _protocol, uint16_t port);
    virtual void
    send_message_to_remote_host(_In_z_ const char* message, sockaddr_storage& remote_address, uint16_t remote_port) = 0;
    virtual void
    cancel_send_message() = 0;
} sender_socket_t;

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to send messages to a remote host.
 */
typedef class _datagram_sender_socket : public _sender_socket
{
  public:
    _datagram_sender_socket(int _sock_type, int _protocol, uint16_t port);
    void
    send_message_to_remote_host(_In_z_ const char* message, sockaddr_storage& remote_address, uint16_t remote_port);
    void
    cancel_send_message();
} datagram_sender_socket_t;

/**
 * @class A dual stack stream socket bound to wildcard address that is used to connect to a remote host.
 */
typedef class _stream_sender_socket : public _sender_socket
{
  public:
    _stream_sender_socket(int _sock_type, int _protocol, uint16_t port);
    void
    send_message_to_remote_host(_In_z_ const char* message, sockaddr_storage& remote_address, uint16_t remote_port);
    void
    cancel_send_message();

  private:
    LPFN_CONNECTEX connectex;
    WSAOVERLAPPED overlapped;
} stream_sender_socket_t;

/**
 * @class An abstract base class for a receiver socket.
 */
typedef class _receiver_socket : public _base_socket
{
  public:
    _receiver_socket(int _sock_type, int _protocol, uint16_t port);
    ~_receiver_socket();
    void
    complete_async_receive(bool timeout_expected = false);
    void
    get_received_message(_Out_ uint32_t& message_size, _Outref_result_buffer_(message_size) char*& message);

    virtual void
    post_async_receive() = 0;
    virtual void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length) = 0;

  protected:
    WSAOVERLAPPED overlapped;
    std::vector<char> recv_buffer;
    uint32_t recv_flags;
    uint32_t bytes_received = 0;

} receiver_socket_t;

/**
 * @class A dual stack UDP or raw socket bound to wildcard address that is used to receive datagrams.
 */
typedef class _datagram_receiver_socket : public _receiver_socket
{
  public:
    _datagram_receiver_socket(int _sock_type, int _protocol, uint16_t port);
    void
    post_async_receive();
    void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length);

  private:
    sockaddr_storage sender_address;
    int sender_address_size;
} datagram_receiver_socket_t;

/**
 * @class A dual stack stream socket bound to wildcard address that is used to accept inbound connection.
 */
typedef class _stream_receiver_socket : public _receiver_socket
{
  public:
    _stream_receiver_socket(int _sock_type, int _protocol, uint16_t port);
    ~_stream_receiver_socket();
    void
    post_async_receive();
    void
    get_sender_address(_Out_ PSOCKADDR& from, _Out_ int& from_length);

  private:
    LPFN_ACCEPTEX acceptex;
    SOCKET accept_socket;
    size_t message_length;
} stream_receiver_socket_t;
