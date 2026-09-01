// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This module facilitates testing various connect redirect scenarios by sending traffic to both
// local system and a remote system, both running TCP / UDP listeners.

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#include "catch_wrapper.hpp"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "common_tests.h"
#include "ebpf_nethooks.h"
#include "ebpf_structs.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "socket_helper.h"
#include "socket_tests_common.h"
#include "watchdog.h"

#include <memory>
#include <mstcpip.h>
#include <ntsecapi.h>

thread_local bool _is_main_thread = false;

CATCH_REGISTER_LISTENER(_watchdog)
static std::string _family;
static std::string _connection_type;
static std::string _vip_v4;
static std::string _vip_v6;
static std::string _local_ip_v4;
static std::string _local_ip_v6;
static std::string _remote_ip_v4;
static std::string _remote_ip_v6;
static std::string _user_name;
static std::string _password;
static std::string _user_type_string;
typedef enum _user_type
{
    ADMINISTRATOR,
    STANDARD_USER
} user_type_t;

typedef struct _test_addresses
{
    struct sockaddr_storage loopback_address;
    struct sockaddr_storage remote_address;
    struct sockaddr_storage local_address;
    struct sockaddr_storage vip_address;
} test_addresses_t;

typedef struct _test_globals
{
    user_type_t user_type = STANDARD_USER;
    HANDLE user_token = nullptr;
    ADDRESS_FAMILY family = 0;
    connection_type_t connection_type = connection_type_t::INVALID;
    uint16_t destination_port = 4444;
    uint16_t proxy_port = 5555;
    test_addresses_t addresses[socket_family_t::Max] = {0};
    bool attach_v4_program = false;
    bool attach_v6_program = false;
    bool attach_authorization_programs = false;
    bpf_object_ptr bpf_object;
} test_globals_t;

static test_globals_t _globals;
static volatile bool _globals_initialized = false;

static void
_impersonate_user()
{
    printf("Impersonating user [%s].\n", _user_name.c_str());
    bool result = ImpersonateLoggedOnUser(_globals.user_token);
    SAFE_REQUIRE(result == true);
}

uint64_t
_get_current_thread_authentication_id()
{
    TOKEN_GROUPS_AND_PRIVILEGES* privileges = nullptr;
    uint32_t size = 0;
    HANDLE thread_token_handle = GetCurrentThreadEffectiveToken();
    uint64_t authentication_id;

    bool result = GetTokenInformation(thread_token_handle, TokenGroupsAndPrivileges, nullptr, 0, (unsigned long*)&size);
    SAFE_REQUIRE(GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    privileges = (TOKEN_GROUPS_AND_PRIVILEGES*)malloc(size);
    SAFE_REQUIRE(privileges != nullptr);

    result =
        GetTokenInformation(thread_token_handle, TokenGroupsAndPrivileges, privileges, size, (unsigned long*)&size);
    SAFE_REQUIRE(result == true);

    authentication_id = *(uint64_t*)&privileges->AuthenticationId;

    free(privileges);
    return authentication_id;
}

static void
_revert_to_self()
{
    printf("Reverting to self.\n");
    RevertToSelf();
}

typedef class _impersonation_helper
{
  public:
    _impersonation_helper(user_type_t type)
    {
        if (type == user_type_t::STANDARD_USER) {
            _impersonate_user();
            impersonated = true;
        }
    }

    ~_impersonation_helper()
    {
        if (impersonated) {
            _revert_to_self();
        }
    }

  private:
    bool impersonated = false;
} impersonation_helper_t;

static HANDLE
_log_on_user(std::string& user_name, std::string& password)
{
    HANDLE token = 0;
    if (_globals.user_type != user_type_t::ADMINISTRATOR) {
        bool result = LogonUserA(
            user_name.c_str(), nullptr, password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
        if (result == false) {
            int error = GetLastError();
            printf("error = %d\n", error);
        }
        SAFE_REQUIRE(result == true);
    }

    return token;
}

inline static IPPROTO
_get_ip_proto_from_connection_type(connection_type_t connection_type)
{
    if (connection_type == connection_type_t::TCP) {
        return IPPROTO_TCP;
    } else if (
        (connection_type == connection_type_t::UNCONNECTED_UDP) ||
        (connection_type == connection_type_t::CONNECTED_UDP)) {
        return IPPROTO_UDP;
    }

    SAFE_REQUIRE(false);
    return IPPROTO_MAX;
}

static user_type_t
_get_user_type(std::string& user_type_string)
{
    if (user_type_string == "" || user_type_string == "Administrator") {
        return user_type_t::ADMINISTRATOR;
    }

    if (user_type_string == "StandardUser") {
        return user_type_t::STANDARD_USER;
    }

    return user_type_t::ADMINISTRATOR;
}

static void
_initialize_test_globals()
{
    if (_globals_initialized) {
        return;
    }

    int result;
    ADDRESS_FAMILY family;
    uint32_t v4_addresses = 0;
    uint32_t v6_addresses = 0;

    printf("Initializing test globals.\n");

    // Read v4 addresses.
    if (_remote_ip_v4 != "") {
        get_address_from_string(
            _remote_ip_v4, _globals.addresses[socket_family_t::IPv4].remote_address, false, &family);
        SAFE_REQUIRE(family == AF_INET);
        get_address_from_string(_remote_ip_v4, _globals.addresses[socket_family_t::Dual].remote_address, true, &family);
        SAFE_REQUIRE(family == AF_INET);
        v4_addresses++;
    }
    if (_local_ip_v4 != "") {
        get_address_from_string(_local_ip_v4, _globals.addresses[socket_family_t::IPv4].local_address, false, &family);
        SAFE_REQUIRE(family == AF_INET);
        get_address_from_string(_local_ip_v4, _globals.addresses[socket_family_t::Dual].local_address, true, &family);
        SAFE_REQUIRE(family == AF_INET);
        v4_addresses++;
    }
    if (_vip_v4 != "") {
        get_address_from_string(_vip_v4, _globals.addresses[socket_family_t::IPv4].vip_address, false, &family);
        SAFE_REQUIRE(family == AF_INET);
        get_address_from_string(_vip_v4, _globals.addresses[socket_family_t::Dual].vip_address, true, &family);
        SAFE_REQUIRE(family == AF_INET);
        v4_addresses++;
    }
    SAFE_REQUIRE((v4_addresses == 0 || v4_addresses == 3));
    _globals.attach_v4_program = (v4_addresses != 0);
    IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&_globals.addresses[socket_family_t::IPv4].loopback_address);
    IN6ADDR_SETV4MAPPED(
        (PSOCKADDR_IN6)&_globals.addresses[socket_family_t::Dual].loopback_address,
        &in4addr_loopback,
        scopeid_unspecified,
        0);

    // Read v6 addresses.
    if (_remote_ip_v6 != "") {
        get_address_from_string(
            _remote_ip_v6, _globals.addresses[socket_family_t::IPv6].remote_address, false, &family);
        SAFE_REQUIRE(family == AF_INET6);
        v6_addresses++;
    }
    if (_local_ip_v6 != "") {
        get_address_from_string(_local_ip_v6, _globals.addresses[socket_family_t::IPv6].local_address, false, &family);
        SAFE_REQUIRE(family == AF_INET6);
        v6_addresses++;
    }
    if (_vip_v6 != "") {
        get_address_from_string(_vip_v6, _globals.addresses[socket_family_t::IPv6].vip_address, false, &family);
        SAFE_REQUIRE(family == AF_INET6);
        v6_addresses++;
    }
    SAFE_REQUIRE((v6_addresses == 0 || v6_addresses == 3));
    _globals.attach_v6_program = (v6_addresses != 0);
    IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&_globals.addresses[socket_family_t::IPv6].loopback_address);

    // Load the user token.
    _globals.user_type = _get_user_type(_user_type_string);
    _globals.user_token = _log_on_user(_user_name, _password);

    // Load and attach the programs.
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2");
    _globals.bpf_object.reset(bpf_object__open(helper.get_file_name().c_str()));
    SAFE_REQUIRE(_globals.bpf_object.get() != nullptr);
    SAFE_REQUIRE(bpf_object__load(_globals.bpf_object.get()) == 0);
    if (_globals.attach_v4_program) {
        printf("Attaching IPv4 program\n");
        bpf_program* connect_program_v4 =
            bpf_object__find_program_by_name(_globals.bpf_object.get(), "connect_redirect4");
        SAFE_REQUIRE(connect_program_v4 != nullptr);

        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program_v4)), 0, BPF_CGROUP_INET4_CONNECT, 0);
        SAFE_REQUIRE(result == 0);
    }
    if (_globals.attach_v6_program) {
        printf("Attaching IPv6 program\n");
        bpf_program* connect_program_v6 =
            bpf_object__find_program_by_name(_globals.bpf_object.get(), "connect_redirect6");
        SAFE_REQUIRE(connect_program_v6 != nullptr);

        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program_v6)), 0, BPF_CGROUP_INET6_CONNECT, 0);
        SAFE_REQUIRE(result == 0);
    }

    printf("Done initializing globals.\n");
    _globals_initialized = true;
}

static void
_validate_audit_map_entry(uint64_t authentication_id)
{
    bpf_map* audit_map = bpf_object__find_map_by_name(_globals.bpf_object.get(), "audit_map");
    SAFE_REQUIRE(audit_map != nullptr);

    fd_t map_fd = bpf_map__fd(audit_map);

    uint64_t process_id = get_current_pid_tgid();
    sock_addr_audit_entry_t entry = {0};
    int result = bpf_map_lookup_elem(map_fd, &process_id, &entry);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(process_id == entry.process_id);
    SAFE_REQUIRE(entry.logon_id == authentication_id);
    SECURITY_LOGON_SESSION_DATA* data = NULL;
    result = LsaGetLogonSessionData((PLUID)&entry.logon_id, &data);
    SAFE_REQUIRE(result == ERROR_SUCCESS);

    if (_globals.user_type == user_type_t::ADMINISTRATOR) {
        SAFE_REQUIRE(entry.is_admin == 1);
    } else {
        SAFE_REQUIRE(entry.is_admin == 0);
    }

    SAFE_REQUIRE(entry.local_port != 0);
    SAFE_REQUIRE(entry.socket_cookie != 0);

    LsaFreeReturnBuffer(data);
}

static void
_update_policy_map(
    _In_ const sockaddr_storage& destination,
    _In_ const sockaddr_storage& proxy,
    uint16_t destination_port,
    uint16_t proxy_port,
    connection_type_t connection_type,
    bool dual_stack,
    bool add)
{
    bpf_map* policy_map = bpf_object__find_map_by_name(_globals.bpf_object.get(), "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);

    // Insert / delete redirect policy entry in the map.
    destination_entry_key_t key = {0};
    destination_entry_value_t value = {.verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT};

    if (_globals.family == AF_INET && dual_stack) {
        struct sockaddr_in6* v6_destination = (struct sockaddr_in6*)&destination;
        struct sockaddr_in6* v6_proxy = (struct sockaddr_in6*)&proxy;

        INET_SET_ADDRESS(
            AF_INET6, (PUCHAR)&key.destination_ip, IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&v6_destination->sin6_addr));
        INET_SET_ADDRESS(
            AF_INET6, (PUCHAR)&value.destination_ip, IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&v6_proxy->sin6_addr));
    } else {
        INET_SET_ADDRESS(_globals.family, (PUCHAR)&key.destination_ip, INETADDR_ADDRESS((PSOCKADDR)&destination));
        INET_SET_ADDRESS(_globals.family, (PUCHAR)&value.destination_ip, INETADDR_ADDRESS((PSOCKADDR)&proxy));
    }

    key.protocol = _get_ip_proto_from_connection_type(connection_type);
    value.connection_type = connection_type;

    key.destination_port = htons(destination_port);
    value.destination_port = htons(proxy_port);

    if (add) {
        SAFE_REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        SAFE_REQUIRE(bpf_map_delete_elem(map_fd, &key) == 0);
    }
}

// RAII guard that removes a policy map entry on destruction.
// Ensures cleanup even when Catch2 assertions throw during the test body.
typedef class _policy_map_guard
{
  public:
    _policy_map_guard(
        _In_ const sockaddr_storage& destination,
        _In_ const sockaddr_storage& proxy,
        uint16_t destination_port,
        uint16_t proxy_port,
        connection_type_t connection_type,
        bool dual_stack)
        : _destination(destination), _proxy(proxy), _destination_port(destination_port), _proxy_port(proxy_port),
          _connection_type(connection_type), _dual_stack(dual_stack)
    {
    }

    ~_policy_map_guard() noexcept
    {
        try {
            _update_policy_map(
                _destination, _proxy, _destination_port, _proxy_port, _connection_type, _dual_stack, false);
        } catch (...) {
            printf("WARNING: policy map cleanup failed during stack unwinding.\n");
        }
    }

    _policy_map_guard(const _policy_map_guard&) = delete;
    _policy_map_guard&
    operator=(const _policy_map_guard&) = delete;

  private:
    sockaddr_storage _destination;
    sockaddr_storage _proxy;
    uint16_t _destination_port;
    uint16_t _proxy_port;
    connection_type_t _connection_type;
    bool _dual_stack;
} policy_map_guard_t;

void
update_policy_map_and_test_connection(
    _In_ client_socket_t* sender_socket,
    _Inout_ sockaddr_storage& destination,
    _In_ const sockaddr_storage& proxy,
    uint16_t destination_port,
    uint16_t proxy_port,
    bool dual_stack)
{
    // Print source, destination, and redirected addresses for debugging purposes
    PSOCKADDR source_addr;
    int source_addr_len;
    sender_socket->get_local_address(source_addr, source_addr_len);

    uint16_t source_port = 0;
    if (source_addr->sa_family == AF_INET) {
        source_port = ntohs(((sockaddr_in*)source_addr)->sin_port);
    } else if (source_addr->sa_family == AF_INET6) {
        source_port = ntohs(((sockaddr_in6*)source_addr)->sin6_port);
    }

    std::string source_address_str = get_string_from_address(source_addr);
    std::string destination_address_str = get_string_from_address((SOCKADDR*)&destination);
    std::string proxy_address_str = get_string_from_address((SOCKADDR*)&proxy);
    CAPTURE(source_address_str, destination_address_str, proxy_address_str, proxy_port);

    bool add_policy = true;
    DWORD bytes_received = 0;
    char* received_message = nullptr;
    uint64_t authentication_id;
    bool redirected = (destination_port != proxy_port || !INETADDR_ISEQUAL((SOCKADDR*)&destination, (SOCKADDR*)&proxy));
    // IPv6 redirect tests always redirect to the IPv6 address. The IPv4 address may be the dual stack or IPv4 address,
    // depending on the inputs.
    socket_family_t remote_address_family = (_globals.family == AF_INET6)
                                                ? socket_family_t::IPv6
                                                : (dual_stack ? socket_family_t::Dual : socket_family_t::IPv4);
    bool local_redirect =
        !INETADDR_ISEQUAL((SOCKADDR*)&proxy, (SOCKADDR*)&_globals.addresses[remote_address_family].remote_address);

    // Update policy in the map to redirect the connection to the proxy.
    _update_policy_map(
        destination, proxy, destination_port, proxy_port, _globals.connection_type, dual_stack, add_policy);

    // RAII guard ensures the policy map entry is always cleaned up, even if an assertion fails.
    // - Avoids failures in later tests.
    policy_map_guard_t policy_guard(
        destination, proxy, destination_port, proxy_port, _globals.connection_type, dual_stack);

    {
        impersonation_helper_t helper(_globals.user_type);

        authentication_id = _get_current_thread_authentication_id();
        SAFE_REQUIRE(authentication_id != 0);

        // Try to send and receive message to "destination". It should succeed.
        sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.destination_port);
        sender_socket->complete_async_send(1000, expected_result_t::SUCCESS);

        sender_socket->post_async_receive();
        sender_socket->complete_async_receive(5000, false);

        sender_socket->get_received_message(bytes_received, received_message);

        // capture the local address again after the send
        sender_socket->get_local_address(source_addr, source_addr_len);
        std::string source_after_send_str = get_string_from_address(source_addr);
        CAPTURE(source_after_send_str);

        // For local redirection, the redirect context is expected to be set and returned.
        // If the connection is not redirected or is redirected to a remote address,
        // check for the SERVER_MESSAGE generic response.
        std::string expected_response;
        if (redirected && local_redirect) {
            expected_response = REDIRECT_CONTEXT_MESSAGE + std::to_string(proxy_port);
        } else {
            expected_response = SERVER_MESSAGE + std::to_string(proxy_port);
        }
        CAPTURE(expected_response, received_message);
        SAFE_REQUIRE(strlen(received_message) == strlen(expected_response.c_str()));
        SAFE_REQUIRE(memcmp(received_message, expected_response.c_str(), strlen(received_message)) == 0);
    }

    _validate_audit_map_entry(authentication_id);

    // Policy map entry will be removed by the policy guard.
}

void
get_client_socket(
    bool dual_stack, _Inout_ client_socket_t** sender_socket, const sockaddr_storage& source_address = {0});

void
authorize_test(_Inout_ client_socket_t** sender_socket, _Inout_ sockaddr_storage& destination, bool dual_stack)
{
    uint64_t authentication_id;
    // Default behavior of the eBPF program is to block the connection.

    // Send should fail as the connection is blocked.
    {
        impersonation_helper_t helper(_globals.user_type);

        authentication_id = _get_current_thread_authentication_id();
        SAFE_REQUIRE(authentication_id != 0);

        (*sender_socket)->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.destination_port);
        (*sender_socket)->complete_async_send(1000, expected_result_t::FAILURE);

        // Receive should time out as connection is blocked.
        (*sender_socket)->post_async_receive(true);
        (*sender_socket)->complete_async_receive(1000, true);
    }

    _validate_audit_map_entry(authentication_id);

    // The socket was closed during overlapped I/O cleanup; get a fresh one.
    get_client_socket(dual_stack, sender_socket);

    // Now update the policy map to allow the connection and test again.
    update_policy_map_and_test_connection(
        *sender_socket, destination, destination, _globals.destination_port, _globals.destination_port, dual_stack);
}

void
get_client_socket(bool dual_stack, _Inout_ client_socket_t** sender_socket, const sockaddr_storage& source_address)
{
    impersonation_helper_t helper(_globals.user_type);

    client_socket_t* old_socket = *sender_socket;
    client_socket_t* new_socket = nullptr;
    socket_family_t family = dual_stack
                                 ? socket_family_t::Dual
                                 : ((_globals.family == AF_INET) ? socket_family_t::IPv4 : socket_family_t::IPv6);
    if (_globals.connection_type == connection_type_t::TCP) {
        new_socket = (client_socket_t*)new stream_client_socket_t(SOCK_STREAM, IPPROTO_TCP, 0, family, source_address);
    } else {
        bool connected_udp = (_globals.connection_type == connection_type_t::CONNECTED_UDP);
        new_socket = (client_socket_t*)new datagram_client_socket_t(
            SOCK_DGRAM, IPPROTO_UDP, 0, family, connected_udp, source_address);
    }

    *sender_socket = new_socket;
    if (old_socket) {
        delete old_socket;
    }
}

void
authorize_test_wrapper(bool dual_stack, _Inout_ sockaddr_storage& destination)
{
    client_socket_t* raw_socket = nullptr;
    get_client_socket(dual_stack, &raw_socket);
    std::unique_ptr<client_socket_t> sender_socket(raw_socket);

    // authorize_test may close and replace the socket (expected-timeout receive closes the socket,
    // then a fresh one is created). Release ownership so authorize_test can manage the pointer,
    // then reclaim ownership of whatever it returns.
    raw_socket = sender_socket.release();
    try {
        authorize_test(&raw_socket, destination, dual_stack);
    } catch (...) {
        sender_socket.reset(raw_socket);
        throw;
    }
    sender_socket.reset(raw_socket);
}

// Helper to update the authorization_policy_map (separate from the redirect policy_map).
static void
_update_authorization_policy_map(
    _In_ const sockaddr_storage& destination, uint16_t destination_port, uint32_t verdict, bool dual_stack, bool add)
{
    bpf_map* auth_map = bpf_object__find_map_by_name(_globals.bpf_object.get(), "authorization_policy_map");
    SAFE_REQUIRE(auth_map != nullptr);

    fd_t map_fd = bpf_map__fd(auth_map);

    destination_entry_key_t key = {0};
    destination_entry_value_t value = {.verdict = verdict};

    if (_globals.family == AF_INET && dual_stack) {
        struct sockaddr_in6* v6_destination = (struct sockaddr_in6*)&destination;
        INET_SET_ADDRESS(
            AF_INET6, (PUCHAR)&key.destination_ip, IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)&v6_destination->sin6_addr));
    } else {
        INET_SET_ADDRESS(_globals.family, (PUCHAR)&key.destination_ip, INETADDR_ADDRESS((PSOCKADDR)&destination));
    }
    key.protocol = _get_ip_proto_from_connection_type(_globals.connection_type);
    key.destination_port = htons(destination_port);

    if (add) {
        SAFE_REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        SAFE_REQUIRE(bpf_map_delete_elem(map_fd, &key) == 0);
    }
}

// Test that authorization can reject a connection after redirect allows it.
// This proves the connect_authorization attach point runs after connect and
// sees the post-redirect destination.
void
redirect_then_auth_reject_test(
    bool dual_stack, _Inout_ sockaddr_storage& destination, _In_ const sockaddr_storage& proxy)
{
    client_socket_t* raw_socket = nullptr;
    get_client_socket(dual_stack, &raw_socket);
    std::unique_ptr<client_socket_t> sender_socket(raw_socket);

    // Set up redirect policy to allow and redirect.
    _update_policy_map(
        destination, proxy, _globals.destination_port, _globals.proxy_port, _globals.connection_type, dual_stack, true);
    policy_map_guard_t redirect_guard(
        destination, proxy, _globals.destination_port, _globals.proxy_port, _globals.connection_type, dual_stack);

    // Set up authorization policy to REJECT the proxy (post-redirect) destination.
    _update_authorization_policy_map(proxy, _globals.proxy_port, BPF_SOCK_ADDR_VERDICT_REJECT, dual_stack, true);

    // Connection should fail because authorization rejects after redirect.
    {
        impersonation_helper_t helper(_globals.user_type);
        sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.destination_port);
        sender_socket->complete_async_send(1000, expected_result_t::FAILURE);
        sender_socket->post_async_receive(true);
        sender_socket->complete_async_receive(1000, true);
    }

    // Clean up authorization policy (redirect policy cleaned up by guard).
    _update_authorization_policy_map(proxy, _globals.proxy_port, 0, dual_stack, false);
}

// Test that authorization allows a connection after redirect, proving the
// combined redirect + authorization flow works end-to-end.
void
redirect_then_auth_allow_test(
    bool dual_stack, _Inout_ sockaddr_storage& destination, _In_ const sockaddr_storage& proxy)
{
    client_socket_t* raw_socket = nullptr;
    get_client_socket(dual_stack, &raw_socket);
    std::unique_ptr<client_socket_t> sender_socket(raw_socket);

    // Set up redirect policy to allow and redirect.
    _update_policy_map(
        destination, proxy, _globals.destination_port, _globals.proxy_port, _globals.connection_type, dual_stack, true);
    policy_map_guard_t redirect_guard(
        destination, proxy, _globals.destination_port, _globals.proxy_port, _globals.connection_type, dual_stack);

    // Set up authorization policy to ALLOW the proxy (post-redirect) destination.
    _update_authorization_policy_map(proxy, _globals.proxy_port, BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT, dual_stack, true);

    // Connection should succeed: redirect then authorized.
    {
        impersonation_helper_t helper(_globals.user_type);
        sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.destination_port);
        sender_socket->complete_async_send(1000, expected_result_t::SUCCESS);
        sender_socket->post_async_receive();
        sender_socket->complete_async_receive(5000, false);
    }

    // Clean up authorization policy (redirect policy cleaned up by guard).
    _update_authorization_policy_map(proxy, _globals.proxy_port, 0, dual_stack, false);
}

void
connect_redirect_test_wrapper(
    _In_ const sockaddr_storage& source_address,
    _Inout_ sockaddr_storage& destination,
    _In_ const sockaddr_storage& proxy,
    bool dual_stack,
    bool implicit_bind)
{
    // Determine address family for lookups
    socket_family_t address_family = (_globals.family == AF_INET6)
                                         ? socket_family_t::IPv6
                                         : (dual_stack ? socket_family_t::Dual : socket_family_t::IPv4);

    // Certain combinations of parameters are not compatible with our test setup, so those tests are skipped.

    // Skip case 1: implicit bind and proxy == local_address.
    // local_address testcases require that the OS stack treats the traffic as loopback (to ensure we can obtain the
    // redirect_context). When an implicit bind is used, the sending interface may differ from the receiving interface.
    // As both interfaces are duonic interfaces, This can therefore result in the traffic being treated as non-loopback.
    if (implicit_bind &&
        INETADDR_ISEQUAL((SOCKADDR*)&proxy, (SOCKADDR*)&_globals.addresses[address_family].local_address)) {
        printf("  Skipping test variation: implicit bind and proxy == local_address\n");
        return;
    }

    // Skip case 2: explicit bind for src == loopback_address and destination == remote_address
    // When the loopback address is used for the source address, sending traffic to a remote address is determined as
    // not routable by the OS stack, and the connection fails.
    if (!implicit_bind &&
        INETADDR_ISEQUAL((SOCKADDR*)&source_address, (SOCKADDR*)&_globals.addresses[address_family].loopback_address)) {
        printf("  Skipping test variation: explicit bind and src == loopback_address\n");
        return;
    }

    // Skip case 3: explicit bind src == local_address and destination == loopback.
    // When the local_address is used as the source address, sending traffic to the loopback_address is determined as
    // not routable by the OS stack, and the connection fails.
    if (!implicit_bind &&
        INETADDR_ISEQUAL((SOCKADDR*)&source_address, (SOCKADDR*)&_globals.addresses[address_family].local_address) &&
        INETADDR_ISEQUAL((SOCKADDR*)&destination, (SOCKADDR*)&_globals.addresses[address_family].loopback_address)) {
        printf(
            "  Skipping test variation: explicit bind and src == local_address and destination == loopback_address\n");
        return;
    }

    client_socket_t* raw_socket = nullptr;
    if (implicit_bind) {
        // Use implicit bind (no source_address specified).
        get_client_socket(dual_stack, &raw_socket);
    } else {
        get_client_socket(dual_stack, &raw_socket, source_address);
    }
    std::unique_ptr<client_socket_t> sender_socket(raw_socket);

    update_policy_map_and_test_connection(
        sender_socket.get(), destination, proxy, _globals.destination_port, _globals.proxy_port, dual_stack);
}

#define DECLARE_CONNECTION_AUTHORIZATION_TEST_FUNCTION(destination)                                                  \
    void connection_authorization_tests_##destination##(                                                             \
        ADDRESS_FAMILY family, connection_type_t connection_type, bool dual_stack, _In_ test_addresses_t& addresses) \
    {                                                                                                                \
        _initialize_test_globals();                                                                                  \
        _globals.family = family;                                                                                    \
        _globals.connection_type = connection_type;                                                                  \
        const char* connection_type_string =                                                                         \
            (_globals.connection_type == connection_type_t::TCP)                                                     \
                ? "TCP"                                                                                              \
                : ((_globals.connection_type == connection_type_t::UNCONNECTED_UDP) ? "UNCONNECTED_UDP"              \
                                                                                    : "CONNECTED_UDP");              \
        const char* family_string = (_globals.family == AF_INET) ? "IPv4" : "IPv6";                                  \
        const char* dual_stack_string = dual_stack ? "Dual Stack" : "No Dual Stack";                                 \
        printf(                                                                                                      \
            "CONNECT: " #destination " | %s | %s | %s\n", connection_type_string, family_string, dual_stack_string); \
        authorize_test_wrapper(dual_stack, addresses.##destination##);                                               \
    }

// Declare connection_authorization_* test functions.

// connect to loopback address.
// connection_authorization_tests_loopback_address
DECLARE_CONNECTION_AUTHORIZATION_TEST_FUNCTION(loopback_address)
// connect to local address.
// connection_authorization_tests_local_address
DECLARE_CONNECTION_AUTHORIZATION_TEST_FUNCTION(local_address)
// connect to remote address.
// connection_authorization_tests_remote_address
DECLARE_CONNECTION_AUTHORIZATION_TEST_FUNCTION(remote_address)

#define DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_CASE(                                                           \
    socket_family_name, socket_family_type, dual_stack, connection_type, destination)                            \
    TEST_CASE(socket_family_name "_" #destination "_" #connection_type, "[connect_authorize_redirect_tests_v4]") \
    {                                                                                                            \
        connection_authorization_tests_##destination##(                                                          \
            AF_INET, connection_type, (dual_stack), _globals.addresses[##socket_family_type##]);                 \
    }

#define DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP(                                        \
    socket_family_name, socket_family_type, dual_stack, connection_type)                       \
    DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_CASE(                                             \
        socket_family_name, socket_family_type, dual_stack, connection_type, loopback_address) \
    DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_CASE(                                             \
        socket_family_name, socket_family_type, dual_stack, connection_type, local_address)    \
    DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_CASE(                                             \
        socket_family_name, socket_family_type, dual_stack, connection_type, remote_address)

#define DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_CASE(                                                           \
    socket_family_name, socket_family_type, dual_stack, connection_type, destination)                            \
    TEST_CASE(socket_family_name "_" #destination "_" #connection_type, "[connect_authorize_redirect_tests_v6]") \
    {                                                                                                            \
        connection_authorization_tests_##destination##(                                                          \
            AF_INET6, connection_type, (dual_stack), _globals.addresses[##socket_family_type##]);                \
    }

#define DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP(                                        \
    socket_family_name, socket_family_type, dual_stack, connection_type)                       \
    DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_CASE(                                             \
        socket_family_name, socket_family_type, dual_stack, connection_type, loopback_address) \
    DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_CASE(                                             \
        socket_family_name, socket_family_type, dual_stack, connection_type, local_address)    \
    DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_CASE(                                             \
        socket_family_name, socket_family_type, dual_stack, connection_type, remote_address)

// Connection Authorization test cases

// IPv4, TCP
DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::TCP)

// IPv4, UNCONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::UNCONNECTED_UDP)

// IPv4, CONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::CONNECTED_UDP)

// Dual stack socket, IPv4, TCP,
DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP("v4_mapped", socket_family_t::Dual, true, connection_type_t::TCP)

// Dual stack socket, IPv4, UNCONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP(
    "v4_mapped", socket_family_t::Dual, true, connection_type_t::UNCONNECTED_UDP)

// Dual stack socket, IPv4, CONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V4_TEST_GROUP(
    "v4_mapped", socket_family_t::Dual, true, connection_type_t::CONNECTED_UDP)

// IPv6, TCP,
DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::TCP)

// IPv6, UNCONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::UNCONNECTED_UDP)

// IPv6, CONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::CONNECTED_UDP)

// Dual stack socket, IPv6, TCP,
DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP("dual_ipv6", socket_family_t::IPv6, true, connection_type_t::TCP)

// Dual stack socket, IPv6, UNCONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP(
    "dual_ipv6", socket_family_t::IPv6, true, connection_type_t::UNCONNECTED_UDP)

// Dual stack socket, IPv6, CONNECTED_UDP
DECLARE_CONNECTION_AUTHORIZATION_V6_TEST_GROUP(
    "dual_ipv6", socket_family_t::IPv6, true, connection_type_t::CONNECTED_UDP)

// Combined redirect + authorization test cases.
// These tests verify that:
// 1. Authorization runs after redirect and sees the post-redirect destination.
// 2. Authorization can reject a connection that redirect allowed.
// 3. Authorization can allow a connection through the combined flow.

#define DECLARE_COMBINED_REDIRECT_AUTH_TEST_FUNCTION(destination, proxy)                                             \
    void combined_redirect_auth_tests_##destination##_##proxy##(                                                     \
        ADDRESS_FAMILY family, connection_type_t connection_type, bool dual_stack, _In_ test_addresses_t& addresses) \
    {                                                                                                                \
        _initialize_test_globals();                                                                                  \
        _globals.family = family;                                                                                    \
        _globals.connection_type = connection_type;                                                                  \
        /* Attach authorization programs if not already attached. */                                                 \
        if (!_globals.attach_authorization_programs) {                                                               \
            _globals.attach_authorization_programs = true;                                                           \
            int result;                                                                                              \
            if (_globals.attach_v4_program) {                                                                        \
                bpf_program* auth_v4 =                                                                               \
                    bpf_object__find_program_by_name(_globals.bpf_object.get(), "connect_authorization4");           \
                SAFE_REQUIRE(auth_v4 != nullptr);                                                                    \
                result = bpf_prog_attach(                                                                            \
                    bpf_program__fd(const_cast<const bpf_program*>(auth_v4)),                                        \
                    0,                                                                                               \
                    BPF_CGROUP_INET4_CONNECT_AUTHORIZATION,                                                          \
                    0);                                                                                              \
                SAFE_REQUIRE(result == 0);                                                                           \
            }                                                                                                        \
            if (_globals.attach_v6_program) {                                                                        \
                bpf_program* auth_v6 =                                                                               \
                    bpf_object__find_program_by_name(_globals.bpf_object.get(), "connect_authorization6");           \
                SAFE_REQUIRE(auth_v6 != nullptr);                                                                    \
                result = bpf_prog_attach(                                                                            \
                    bpf_program__fd(const_cast<const bpf_program*>(auth_v6)),                                        \
                    0,                                                                                               \
                    BPF_CGROUP_INET6_CONNECT_AUTHORIZATION,                                                          \
                    0);                                                                                              \
                SAFE_REQUIRE(result == 0);                                                                           \
            }                                                                                                        \
        }                                                                                                            \
        printf("COMBINED REDIRECT+AUTH: " #destination " -> " #proxy " | reject after redirect\n");                  \
        redirect_then_auth_reject_test(dual_stack, addresses.##destination##, addresses.##proxy##);                  \
        printf("COMBINED REDIRECT+AUTH: " #destination " -> " #proxy " | allow after redirect\n");                   \
        redirect_then_auth_allow_test(dual_stack, addresses.##destination##, addresses.##proxy##);                   \
    }

DECLARE_COMBINED_REDIRECT_AUTH_TEST_FUNCTION(vip_address, remote_address)
DECLARE_COMBINED_REDIRECT_AUTH_TEST_FUNCTION(vip_address, loopback_address)

#define DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_CASE(                                             \
    socket_family_name, socket_family_type, dual_stack, connection_type, destination, proxy)     \
    TEST_CASE(                                                                                   \
        socket_family_name "_" #destination "_" #proxy "_" #connection_type,                     \
        "[connect_combined_redirect_auth_tests_v4]")                                             \
    {                                                                                            \
        combined_redirect_auth_tests_##destination##_##proxy##(                                  \
            AF_INET, connection_type, (dual_stack), _globals.addresses[##socket_family_type##]); \
    }

#define DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP(                                                     \
    socket_family_name, socket_family_type, dual_stack, connection_type)                                  \
    DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_CASE(                                                          \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, remote_address) \
    DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_CASE(                                                          \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, loopback_address)

#define DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_CASE(                                              \
    socket_family_name, socket_family_type, dual_stack, connection_type, destination, proxy)      \
    TEST_CASE(                                                                                    \
        socket_family_name "_" #destination "_" #proxy "_" #connection_type,                      \
        "[connect_combined_redirect_auth_tests_v6]")                                              \
    {                                                                                             \
        combined_redirect_auth_tests_##destination##_##proxy##(                                   \
            AF_INET6, connection_type, (dual_stack), _globals.addresses[##socket_family_type##]); \
    }

#define DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP(                                                     \
    socket_family_name, socket_family_type, dual_stack, connection_type)                                  \
    DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_CASE(                                                          \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, remote_address) \
    DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_CASE(                                                          \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, loopback_address)

// IPv4 combined redirect + authorization tests.
DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::TCP)
DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::UNCONNECTED_UDP)
DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::CONNECTED_UDP)

// Dual stack socket, IPv4 combined redirect + authorization tests.
DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP("v4_mapped", socket_family_t::Dual, true, connection_type_t::TCP)
DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP(
    "v4_mapped", socket_family_t::Dual, true, connection_type_t::UNCONNECTED_UDP)
DECLARE_COMBINED_REDIRECT_AUTH_V4_TEST_GROUP("v4_mapped", socket_family_t::Dual, true, connection_type_t::CONNECTED_UDP)

// IPv6 combined redirect + authorization tests.
DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::TCP)
DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::UNCONNECTED_UDP)
DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::CONNECTED_UDP)

// Dual stack socket, IPv6 combined redirect + authorization tests.
DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP("dual_ipv6", socket_family_t::IPv6, true, connection_type_t::TCP)
DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP(
    "dual_ipv6", socket_family_t::IPv6, true, connection_type_t::UNCONNECTED_UDP)
DECLARE_COMBINED_REDIRECT_AUTH_V6_TEST_GROUP("dual_ipv6", socket_family_t::IPv6, true, connection_type_t::CONNECTED_UDP)

#define DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(source, original_destination, new_destination)                   \
    void connection_redirection_tests_##original_destination##_##new_destination##(                                   \
        ADDRESS_FAMILY family, connection_type_t connection_type, bool dual_stack, _In_ test_addresses_t& addresses)  \
    {                                                                                                                 \
        _initialize_test_globals();                                                                                   \
        _globals.family = family;                                                                                     \
        _globals.connection_type = connection_type;                                                                   \
        const char* connection_type_string =                                                                          \
            (_globals.connection_type == connection_type_t::TCP)                                                      \
                ? "TCP"                                                                                               \
                : ((_globals.connection_type == connection_type_t::UNCONNECTED_UDP) ? "UNCONNECTED_UDP"               \
                                                                                    : "CONNECTED_UDP");               \
        const char* family_string = (_globals.family == AF_INET) ? "IPv4" : "IPv6";                                   \
        const char* dual_stack_string = dual_stack ? "Dual Stack" : "No Dual Stack";                                  \
        printf(                                                                                                       \
            "REDIRECT: " #source " (explicit) -> " #original_destination " -> " #new_destination " | %s | %s | %s\n", \
            connection_type_string,                                                                                   \
            family_string,                                                                                            \
            dual_stack_string);                                                                                       \
        /* Test with explicit bind (bind to specific source address) */                                               \
        printf("  Testing with explicit bind to source address...\n");                                                \
        connect_redirect_test_wrapper(                                                                                \
            addresses.##source##,                                                                                     \
            addresses.##original_destination##,                                                                       \
            addresses.##new_destination##,                                                                            \
            dual_stack,                                                                                               \
            false);                                                                                                   \
        /* Test with implicit bind (bind to wildcard address) */                                                      \
        printf(                                                                                                       \
            "REDIRECT: " #source " (implicit) -> " #original_destination " -> " #new_destination " | %s | %s | %s\n", \
            connection_type_string,                                                                                   \
            family_string,                                                                                            \
            dual_stack_string);                                                                                       \
        connect_redirect_test_wrapper(                                                                                \
            addresses.##source##,                                                                                     \
            addresses.##original_destination##,                                                                       \
            addresses.##new_destination##,                                                                            \
            dual_stack,                                                                                               \
            true);                                                                                                    \
    }

// Declare connection_redirection_* test functions.

// remote (vip) address to another remote address.
// connection_redirection_tests_vip_address_remote_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(local_address, vip_address, remote_address)
// remote (vip) address to loopback address.
// connection_redirection_tests_vip_address_loopback_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(loopback_address, vip_address, loopback_address)
// remote (vip) address to local address.
// connection_redirection_tests_vip_address_local_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(local_address, vip_address, local_address)
// loopback address to remote address.
// connection_redirection_tests_loopback_address_remote_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(local_address, loopback_address, remote_address)
// loopback address to local address.
// connection_redirection_tests_loopback_address_local_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(local_address, loopback_address, local_address)
// local address to remote address.
// connection_redirection_tests_local_address_remote_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(local_address, local_address, remote_address)
// local address to loopback address.
// connection_redirection_tests_local_address_loopback_address
DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(loopback_address, local_address, loopback_address)

#define DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                            \
    socket_family_name, socket_family_type, dual_stack, connection_type, original_destination, new_destination) \
    TEST_CASE(                                                                                                  \
        socket_family_name "_" #original_destination "_" #new_destination "_" #connection_type,                 \
        "[connect_authorize_redirect_tests_v4]")                                                                \
    {                                                                                                           \
        connection_redirection_tests_##original_destination##_##new_destination##(                              \
            AF_INET, connection_type, (dual_stack), _globals.addresses[##socket_family_type##]);                \
    }

#define DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP(                                                          \
    socket_family_name, socket_family_type, dual_stack, connection_type)                                       \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, remote_address)      \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, loopback_address)    \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, local_address)       \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, loopback_address, remote_address) \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, loopback_address, local_address)  \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, local_address, loopback_address)  \
    DECLARE_CONNECTION_REDIRECTION_V4_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, local_address, remote_address)

#define DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                            \
    socket_family_name, socket_family_type, dual_stack, connection_type, original_destination, new_destination) \
    TEST_CASE(                                                                                                  \
        socket_family_name "_" #original_destination "_" #new_destination "_" #connection_type,                 \
        "[connect_authorize_redirect_tests_v6]")                                                                \
    {                                                                                                           \
        connection_redirection_tests_##original_destination##_##new_destination##(                              \
            AF_INET6, connection_type, (dual_stack), _globals.addresses[##socket_family_type##]);               \
    }

#define DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP(                                                          \
    socket_family_name, socket_family_type, dual_stack, connection_type)                                       \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, remote_address)      \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, loopback_address)    \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, vip_address, local_address)       \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, loopback_address, remote_address) \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, loopback_address, local_address)  \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, local_address, loopback_address)  \
    DECLARE_CONNECTION_REDIRECTION_V6_TEST_CASE(                                                               \
        socket_family_name, socket_family_type, dual_stack, connection_type, local_address, remote_address)

// Connection redirection test cases.

// IPv4, TCP
DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::TCP)

// IPv4, UNCONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::UNCONNECTED_UDP)

// IPv4, CONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP("ipv4", socket_family_t::IPv4, false, connection_type_t::CONNECTED_UDP)

// Dual stack socket, IPv4, TCP
DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP("v4_mapped", socket_family_t::Dual, true, connection_type_t::TCP)

// Dual stack socket, IPv4, UNCONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP(
    "v4_mapped", socket_family_t::Dual, true, connection_type_t::UNCONNECTED_UDP)

// Dual stack socket, IPv4, CONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V4_TEST_GROUP("v4_mapped", socket_family_t::Dual, true, connection_type_t::CONNECTED_UDP)

// IPv6, TCP
DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::TCP)

// IPv6, UNCONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::UNCONNECTED_UDP)

// IPv6, CONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP("ipv6", socket_family_t::IPv6, false, connection_type_t::CONNECTED_UDP)

// Dual stack socket, IPv6, TCP
DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP("dual_ipv6", socket_family_t::IPv6, true, connection_type_t::TCP)

// Dual stack socket, IPv6, UNCONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP(
    "dual_ipv6", socket_family_t::IPv6, true, connection_type_t::UNCONNECTED_UDP)

// Dual stack socket, IPv6, CONNECTED_UDP
DECLARE_CONNECTION_REDIRECTION_V6_TEST_GROUP("dual_ipv6", socket_family_t::IPv6, true, connection_type_t::CONNECTED_UDP)

// ---------------------------------------------------------------------------
// connect_redirect_mesh sample: real behavioral tests.
//
// The mesh sample is exercised end-to-end for BOTH IPv4 and IPv6, replacing the
// former load-only ("best-effort") check. Coverage includes:
//   - configuration of the proxy endpoint (proxy_config_map),
//   - the protocol / attachment scope guard (TCP only; UDP is left untouched),
//   - the original-destination tuple handed to the proxy through the WFP
//     REDIRECT_CONTEXT (SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT),
//   - the FULL 16-byte IPv6 proxy destination the program writes,
//   - proxy PID loop avoidance (proxy_pid_map) using the real socket-owner
//     process id (the upper 32 bits of bpf_get_current_pid_tgid()),
//   - the redirect counter map (read tolerantly so a yet-unseeded key 0 reports
//     zero rather than tripping a -ENOENT failure).
//
// These mirror the repo's real-socket harness (stream_client_socket_t /
// stream_server_socket_t) and the bpf_prog_test_run_opts pattern used by
// tests/socket/socket_tests.cpp for the CONNECT family. The CONNECT and
// CONNECT_AUTHORIZATION attach points are single-slot, so this module attaches
// the mesh programs and detaches them on completion; these cases are tagged
// [connect_mesh_redirect_tests] and are expected to run in isolation from the
// cgroup_sock_addr2 redirection suite.
//
// NOTE: This test needs the repository build environment to produce the
// connect_redirect_mesh native module.
// ---------------------------------------------------------------------------

// Mirrors mesh_original_destination_t in connect_redirect_mesh.c.
typedef struct _mesh_original_destination
{
    uint32_t family; ///< AF_INET or AF_INET6.
    union
    {
        uint32_t ipv4;    ///< Network byte order.
        uint32_t ipv6[4]; ///< Network byte order.
    } address;
    uint16_t port; ///< Network byte order (original destination port).
} mesh_original_destination_t;

// Mirrors mesh_proxy_config_t in connect_redirect_mesh.c.
typedef struct _mesh_proxy_config
{
    uint32_t proxy_ipv4;    ///< Network byte order (0 => 127.0.0.1).
    uint32_t proxy_ipv6[4]; ///< Network byte order (all 0 => IPv4-mapped loopback).
    uint16_t proxy_port;    ///< Host byte order (0 => 15001).
} mesh_proxy_config_t;

// RAII helper that opens/loads the connect_redirect_mesh module and manages the
// CONNECT / CONNECT_AUTHORIZATION program attachments at the cgroup connect hooks.
typedef class _mesh_module
{
  public:
    void
    initialize()
    {
        _helper.initialize("connect_redirect_mesh");
        bpf_object_ptr object(bpf_object__open(_helper.get_file_name().c_str()));
        SAFE_REQUIRE(object.get() != nullptr);
        SAFE_REQUIRE(bpf_object__load(object.get()) == 0);
        _object = std::move(object);
    }

    ~_mesh_module()
    {
        // Detach whatever we attached. Detach is idempotent and safe even if the
        // caller detached only a subset.
        if (_auth6_attached) {
            _detach_program("mesh_authorize_connect6", BPF_CGROUP_INET6_CONNECT_AUTHORIZATION);
        }
        if (_auth4_attached) {
            _detach_program("mesh_authorize_connect4", BPF_CGROUP_INET4_CONNECT_AUTHORIZATION);
        }
        if (_connect6_attached) {
            _detach_program("mesh_redirect_connect6", BPF_CGROUP_INET6_CONNECT);
        }
        if (_connect4_attached) {
            _detach_program("mesh_redirect_connect4", BPF_CGROUP_INET4_CONNECT);
        }
    }

    // Attach the IPv4 and/or IPv6 programs (redirect + authorization).
    void
    attach(bool attach_v4, bool attach_v6)
    {
        if (attach_v4) {
            _attach_program("mesh_redirect_connect4", BPF_CGROUP_INET4_CONNECT);
            _attach_program("mesh_authorize_connect4", BPF_CGROUP_INET4_CONNECT_AUTHORIZATION);
        }
        if (attach_v6) {
            _attach_program("mesh_redirect_connect6", BPF_CGROUP_INET6_CONNECT);
            _attach_program("mesh_authorize_connect6", BPF_CGROUP_INET6_CONNECT_AUTHORIZATION);
        }
    }

    bpf_object*
    object() const
    {
        return _object.get();
    }

    bpf_program*
    find_program(const char* name)
    {
        bpf_program* program = bpf_object__find_program_by_name(_object.get(), name);
        SAFE_REQUIRE(program != nullptr);
        return program;
    }

    // Configure proxy_config_map[0].
    void
    set_proxy_config(_In_ const mesh_proxy_config_t& config)
    {
        bpf_map* map = bpf_object__find_map_by_name(_object.get(), "proxy_config_map");
        SAFE_REQUIRE(map != nullptr);
        uint32_t key = 0;
        SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(map), &key, &config, BPF_ANY) == 0);
    }

    // Register or remove a proxy PID used for loop avoidance. The key is the
    // 8-byte process id (upper 32 bits of bpf_get_current_pid_tgid()).
    void
    set_proxy_pid(uint64_t process_id, bool is_proxy)
    {
        bpf_map* map = bpf_object__find_map_by_name(_object.get(), "proxy_pid_map");
        SAFE_REQUIRE(map != nullptr);
        fd_t map_fd = bpf_map__fd(map);
        if (is_proxy) {
            uint8_t value = 1;
            SAFE_REQUIRE(bpf_map_update_elem(map_fd, &process_id, &value, BPF_ANY) == 0);
        } else {
            SAFE_REQUIRE(bpf_map_delete_elem(map_fd, &process_id) == 0);
        }
    }

    // Read the redirect counter for key 0. A yet-unseeded key (bpf_map_lookup_elem
    // returning -ENOENT) is reported as zero rather than failing the test.
    uint64_t
    read_redirect_counter()
    {
        bpf_map* map = bpf_object__find_map_by_name(_object.get(), "redirect_counter_map");
        SAFE_REQUIRE(map != nullptr);
        fd_t map_fd = bpf_map__fd(map);
        uint32_t key = 0;
        uint64_t count = 0;
        int result = bpf_map_lookup_elem(map_fd, &key, &count);
        if (result < 0) {
            return 0;
        }
        return count;
    }

  private:
    void
    _attach_program(const char* name, bpf_attach_type_t attach_type)
    {
        bpf_program* program = find_program(name);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(program)), 0, attach_type, 0);
        SAFE_REQUIRE(result == 0);
        if (attach_type == BPF_CGROUP_INET4_CONNECT) {
            _connect4_attached = true;
        } else if (attach_type == BPF_CGROUP_INET6_CONNECT) {
            _connect6_attached = true;
        } else if (attach_type == BPF_CGROUP_INET4_CONNECT_AUTHORIZATION) {
            _auth4_attached = true;
        } else {
            _auth6_attached = true;
        }
    }

    void
    _detach_program(const char* name, bpf_attach_type_t attach_type)
    {
        bpf_program* program = find_program(name);
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(program)), 0, attach_type);
    }

    native_module_helper_t _helper;
    bpf_object_ptr _object;
    bool _connect4_attached = false;
    bool _connect6_attached = false;
    bool _auth4_attached = false;
    bool _auth6_attached = false;
} mesh_module_t;

// Run a mesh redirect program against a synthetic bpf_sock_addr_t context and
// return the mutated output so the test can compare the program's FULL output.
static void _mesh_synthetic_run(mesh_module_t& module, const char* program_name, _In_ const bpf_sock_addr_t& input, _Inout_ bpf_sock_addr_t& output)
{
    bpf_program* program = module.find_program(program_name);
    bpf_test_run_opts opts{.repeat = 1};
    opts.ctx_in = const_cast<bpf_sock_addr_t*>(&input);
    opts.ctx_size_in = sizeof(bpf_sock_addr_t);
    opts.ctx_out = &output;
    opts.ctx_size_out = sizeof(bpf_sock_addr_t);
    SAFE_REQUIRE(bpf_prog_test_run_opts(bpf_program__fd(const_cast<const bpf_program*>(program)), &opts) == 0);
}

// Open/load the module and sanity-check program and map resolution.
static void
_mesh_load_and_verify(mesh_module_t& module)
{
    module.initialize();

    const char* program_names[] = {
        "mesh_redirect_connect4", "mesh_redirect_connect6", "mesh_authorize_connect4", "mesh_authorize_connect6"};
    for (const char* name : program_names) {
        CAPTURE(name);
        fd_t program_fd = bpf_program__fd(static_cast<const bpf_program*>(module.find_program(name)));
        SAFE_REQUIRE(program_fd > 0);
    }

    const char* map_names[] = {"proxy_config_map", "proxy_pid_map", "redirect_counter_map"};
    for (const char* name : map_names) {
        CAPTURE(name);
        bpf_map* map = bpf_object__find_map_by_name(module.object(), name);
        SAFE_REQUIRE(map != nullptr);
        SAFE_REQUIRE(bpf_map__fd(map) > 0);
    }
}

TEST_CASE("connect_mesh_redirect_ipv4_config_and_protocol_scope", "[connect_mesh_redirect_tests]")
{
    mesh_module_t module;
    _mesh_load_and_verify(module);

    // Configure a DISTINCT IPv4 endpoint so the test proves proxy_config_map is
    // honored rather than the hardcoded default (127.0.0.1:15001).
    constexpr uint32_t test_proxy_ipv4 = 0x0A000002; // 10.0.0.2 in host order; converted below.
    constexpr uint16_t test_proxy_port = 16001;

    mesh_proxy_config_t config = {0};
    config.proxy_ipv4 = htonl(test_proxy_ipv4);
    config.proxy_ipv6[0] = 0;
    config.proxy_ipv6[1] = 0;
    config.proxy_ipv6[2] = 0;
    config.proxy_ipv6[3] = 0;
    config.proxy_port = test_proxy_port;
    module.set_proxy_config(config);

    // A TCP IPv4 outbound socket must be redirected to the configured endpoint.
    bpf_sock_addr_t input = {0};
    input.family = AF_INET;
    input.protocol = IPPROTO_TCP;
    input.user_ip4 = htonl(0x0A000001); // 10.0.0.1 original destination.
    input.user_port = htons(80);

    bpf_sock_addr_t output = {0};
    _mesh_synthetic_run(module, "mesh_redirect_connect4", input, output);

    SAFE_REQUIRE(output.family == AF_INET);
    SAFE_REQUIRE(output.user_ip4 == htonl(test_proxy_ipv4));
    SAFE_REQUIRE(output.user_port == htons(test_proxy_port));

    // Redirect counter must have been set/incremented (key 0 never -ENOENT here).
    SAFE_REQUIRE(module.read_redirect_counter() >= 1);

    // Protocol scope guard: a UDP connection is NOT redirected even for the same
    // address family, and must not increment the counter.
    bpf_sock_addr_t udp_input = input;
    udp_input.protocol = IPPROTO_UDP;
    bpf_sock_addr_t udp_output = {0};
    uint64_t before_udp = module.read_redirect_counter();
    _mesh_synthetic_run(module, "mesh_redirect_connect4", udp_input, udp_output);
    SAFE_REQUIRE(udp_output.user_ip4 == udp_input.user_ip4);
    SAFE_REQUIRE(udp_output.user_port == udp_input.user_port);
    SAFE_REQUIRE(module.read_redirect_counter() == before_udp);
}

TEST_CASE("connect_mesh_redirect_ipv6_all_sixteen_bytes", "[connect_mesh_redirect_tests]")
{
    mesh_module_t module;
    _mesh_load_and_verify(module);

    // Configure a DISTINCT full 16-byte IPv6 proxy endpoint: all four words are
    // non-trivial so the test verifies the FULL 16-byte output rather than masking
    // a bug where only a subset of the IPv6 address is written.
    const uint32_t test_proxy_ipv6[4] = {
        htonl(0x20010DB8), htonl(0x00001111), htonl(0x00002222), htonl(0x00003333)};
    constexpr uint16_t test_proxy_port = 16002;

    mesh_proxy_config_t config = {0};
    memcpy(config.proxy_ipv6, test_proxy_ipv6, sizeof(test_proxy_ipv6));
    config.proxy_port = test_proxy_port;
    module.set_proxy_config(config);

    // A TCP IPv6 outbound socket to an arbitrary original destination.
    bpf_sock_addr_t input = {0};
    input.family = AF_INET6;
    input.protocol = IPPROTO_TCP;
    input.user_ip6[0] = htonl(0x20010DB8);
    input.user_ip6[1] = htonl(0x0000AAAA);
    input.user_ip6[2] = htonl(0x0000BBBB);
    input.user_ip6[3] = htonl(0x0000CCCC);
    input.user_port = htons(200);

    bpf_sock_addr_t output = {0};
    _mesh_synthetic_run(module, "mesh_redirect_connect6", input, output);

    SAFE_REQUIRE(output.family == AF_INET6);
    SAFE_REQUIRE(memcmp(output.user_ip6, test_proxy_ipv6, sizeof(test_proxy_ipv6)) == 0);
    SAFE_REQUIRE(output.user_port == htons(test_proxy_port));

    // Loop avoidance is intentionally NOT asserted here: this is a synthetic
    // bpf_prog_test_run_opts run, which executes the program on a deferred
    // runtime work item and therefore does not attribute the test process PID to
    // bpf_get_current_pid_tgid(). A proxy_pid_map seeded with the test PID cannot
    // be matched under test_run, so the program necessarily rewrites user_ip6.
    // Loop avoidance is verified instead by connect_mesh_redirect_real_socket_ipv4
    // (a real attached socket runs the WFP callout in the owning process context,
    // where the PID IS attributed); the sample's IPv4 and IPv6 programs share the
    // identical is_proxy_process() path, so IPv4 real-socket coverage exercises it.
}

// Real-socket integration for IPv4: a connect() through the attached mesh program
// must land on the loopback proxy, hand off the original tuple in the WFP redirect
// context, and be loop-avoided once the owning PID is registered as the proxy.
TEST_CASE("connect_mesh_redirect_real_socket_ipv4", "[connect_mesh_redirect_tests][real_socket]")
{
    mesh_module_t module;
    _mesh_load_and_verify(module);

    // IPv4 loopback proxy listener.
    constexpr uint16_t proxy_port = 16010;
    sockaddr_storage proxy_addr = {};
    std::string loopback_str = "127.0.0.1";
    get_address_from_string(loopback_str, proxy_addr, false);
    SAFE_REQUIRE(proxy_addr.ss_family == AF_INET);

    mesh_proxy_config_t config = {0};
    uint32_t config_ipv4_value = 0;
    memcpy(&config_ipv4_value, INETADDR_ADDRESS((PSOCKADDR)&proxy_addr), sizeof(config_ipv4_value));
    config.proxy_ipv4 = config_ipv4_value; // Network byte order.
    config.proxy_port = proxy_port;
    module.set_proxy_config(config);

    // Attach the IPv4 mesh programs (single-slot CONNECT hooks; detached on exit).
    module.attach(true, false);

    // A decoy destination the client asks for; the mesh program rewrites it to the
    // loopback proxy. The address is distinct from the proxy so the original-tuple
    // handoff is observable.
    sockaddr_storage original_dest{};
    std::string decoy_str = "10.9.8.7";
    get_address_from_string(decoy_str, original_dest, false);

    // First connect: the test process is NOT the registered proxy, so it must be
    // redirected; the proxy server learns the original tuple via the redirect
    // context and the counter is incremented.
    {
        uint64_t before = module.read_redirect_counter();

        stream_server_socket_t proxy_server(
            SOCK_STREAM, IPPROTO_TCP, proxy_port, proxy_addr, 0, 0, socket_family_t::IPv4);
        proxy_server.post_async_receive();

        stream_client_socket_t sender(SOCK_STREAM, IPPROTO_TCP, 0, socket_family_t::IPv4);
        sender.send_message_to_remote_host(CLIENT_MESSAGE, original_dest, 29999);
        sender.complete_async_send(2000, expected_result_t::SUCCESS);

        proxy_server.complete_async_receive(5000, false);

        // The accepted connection lands on the proxy; its WFP redirect context must
        // carry the original (decoy) destination tuple.
        mesh_original_destination_t original = {0};
        int result = proxy_server.query_redirect_context(&original, sizeof(original));
        SAFE_REQUIRE(result == 0);
        SAFE_REQUIRE(original.family == AF_INET);
        uint32_t original_ipv4_value = 0;
        memcpy(&original_ipv4_value, INETADDR_ADDRESS((PSOCKADDR)&original_dest), sizeof(original_ipv4_value));
        SAFE_REQUIRE(original.address.ipv4 == original_ipv4_value);
        SAFE_REQUIRE(original.port == htons(29999));

        // A redirect happened.
        SAFE_REQUIRE(module.read_redirect_counter() == before + 1);
    }

    // Scenario: register the socket-owner PROCESS id as the mesh proxy so the
    // proxy's own outbound dial is loop-avoided (not redirected). The connection
    // reaches the loopback listener directly and the counter does not move.
    uint64_t process_id = get_current_pid_tgid() >> 32;
    module.set_proxy_pid(process_id, true);
    {
        uint64_t before_counter = module.read_redirect_counter();

        stream_server_socket_t proxy_server2(
            SOCK_STREAM, IPPROTO_TCP, proxy_port, proxy_addr, 0, 0, socket_family_t::IPv4);
        proxy_server2.post_async_receive();

        // The proxy dials the proxy listener itself; destination is left untouched.
        stream_client_socket_t sender2(SOCK_STREAM, IPPROTO_TCP, 0, socket_family_t::IPv4);
        sender2.send_message_to_remote_host(CLIENT_MESSAGE, proxy_addr, proxy_port);
        sender2.complete_async_send(2000, expected_result_t::SUCCESS);

        proxy_server2.complete_async_receive(5000, false);

        // Loop avoidance: the counter must NOT have grown.
        SAFE_REQUIRE(module.read_redirect_counter() == before_counter);
    }
    module.set_proxy_pid(process_id, false);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    _is_main_thread = true;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli = session.cli() | Opt(_vip_v4, "IPv4 VIP")["-v"]["--virtual-ip-v4"]("v4 Virtual / Load Balanced IP") |
               Opt(_vip_v6, "IPv6 VIP")["-v"]["--virtual-ip-v6"]("IPv6 VIPv6 Virtual / Load Balanced IP") |
               Opt(_local_ip_v4, "v4 local IP")["-l"]["--local-ip-v4"]("Local IPv4 IP") |
               Opt(_local_ip_v6, "v6 local IP")["-l"]["--local-ip-v6"]("Local IPv6 IP") |
               Opt(_remote_ip_v4, "v4 Remote IP")["-r"]["--remote-ip-v4"]("IPv4 Remote IP") |
               Opt(_remote_ip_v6, "v6 Remote IP")["-r"]["--remote-ip-v6"]("IPv6 Remote IP") |
               Opt(_globals.destination_port, "Destination Port")["-t"]["--destination-port"]("Destination Port") |
               Opt(_globals.proxy_port, "Proxy Port")["-pt"]["--proxy-port"]("Proxy Port") |
               Opt(_user_name, "User Name")["-u"]["--user-name"]("User Name") |
               Opt(_password, "Password")["-w"]["--password"]("Password") |
               Opt(_user_type_string, "User Type")["-x"]["--user-type"]("User Type");
    session.cli(cli);

    // Parse the command line.
    printf("Parsing command line...\n");
    int returnCode = session.applyCommandLine(argc, argv);
    if (returnCode != 0) {
        return returnCode;
    }

    // Debug parameter values.
    printf("Parameter values:\n");
    printf("- Virtual IPv4 address: %s\n", _vip_v4.c_str());
    printf("- Virtual IPv6 address: %s\n", _vip_v6.c_str());
    printf("- Local IPv4: %s\n", _local_ip_v4.c_str());
    printf("- Local IPv6: %s\n", _local_ip_v6.c_str());
    printf("- Remote IPv4: %s\n", _remote_ip_v4.c_str());
    printf("- Remote IPv6: %s\n", _remote_ip_v6.c_str());
    printf("- Destination Port: %d\n", _globals.destination_port);
    printf("- Proxy Port: %d\n", _globals.proxy_port);
    printf("- User Name: %s\n", _user_name.c_str());
    printf("- User Type: %s\n", _user_type_string.c_str());

    // Set up Windows Sockets.
    WSAData data;
    printf("Initializing Winsock...\n");
    int error = WSAStartup(MAKEWORD(2, 2), &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    // Run the tests.
    printf("Running tests...\n");
    returnCode = session.run();

    // Clean up Windows Sockets.
    printf("Cleaning up Winsock.\n");
    WSACleanup();

    return returnCode;
}
