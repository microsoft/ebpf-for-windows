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

#include <mstcpip.h>
#include <ntsecapi.h>

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
    uint16_t proxy_port = 4443;
    test_addresses_t addresses[socket_family_t::Max] = {0};
    bool attach_v4_program = false;
    bool attach_v6_program = false;
    bpf_object_ptr bpf_object;
} test_globals_t;

static test_globals_t _globals;
static volatile bool _globals_initialized = false;

static void
_impersonate_user()
{
    printf("Impersonating user [%s].\n", _user_name.c_str());
    bool result = ImpersonateLoggedOnUser(_globals.user_token);
    REQUIRE(result == true);
}

uint64_t
_get_current_thread_authentication_id()
{
    TOKEN_GROUPS_AND_PRIVILEGES* privileges = nullptr;
    uint32_t size = 0;
    HANDLE thread_token_handle = GetCurrentThreadEffectiveToken();
    uint64_t authentication_id;

    bool result = GetTokenInformation(thread_token_handle, TokenGroupsAndPrivileges, nullptr, 0, (unsigned long*)&size);
    REQUIRE(GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    privileges = (TOKEN_GROUPS_AND_PRIVILEGES*)malloc(size);
    REQUIRE(privileges != nullptr);

    result =
        GetTokenInformation(thread_token_handle, TokenGroupsAndPrivileges, privileges, size, (unsigned long*)&size);
    REQUIRE(result == true);

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
        REQUIRE(result == true);
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

    REQUIRE(false);
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
        REQUIRE(family == AF_INET);
        get_address_from_string(_remote_ip_v4, _globals.addresses[socket_family_t::Dual].remote_address, true, &family);
        REQUIRE(family == AF_INET);
        v4_addresses++;
    }
    if (_local_ip_v4 != "") {
        get_address_from_string(_local_ip_v4, _globals.addresses[socket_family_t::IPv4].local_address, false, &family);
        REQUIRE(family == AF_INET);
        get_address_from_string(_local_ip_v4, _globals.addresses[socket_family_t::Dual].local_address, true, &family);
        REQUIRE(family == AF_INET);
        v4_addresses++;
    }
    if (_vip_v4 != "") {
        get_address_from_string(_vip_v4, _globals.addresses[socket_family_t::IPv4].vip_address, false, &family);
        REQUIRE(family == AF_INET);
        get_address_from_string(_vip_v4, _globals.addresses[socket_family_t::Dual].vip_address, true, &family);
        REQUIRE(family == AF_INET);
        v4_addresses++;
    }
    REQUIRE((v4_addresses == 0 || v4_addresses == 3));
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
        REQUIRE(family == AF_INET6);
        v6_addresses++;
    }
    if (_local_ip_v6 != "") {
        get_address_from_string(_local_ip_v6, _globals.addresses[socket_family_t::IPv6].local_address, false, &family);
        REQUIRE(family == AF_INET6);
        v6_addresses++;
    }
    if (_vip_v6 != "") {
        get_address_from_string(_vip_v6, _globals.addresses[socket_family_t::IPv6].vip_address, false, &family);
        REQUIRE(family == AF_INET6);
        v6_addresses++;
    }
    REQUIRE((v6_addresses == 0 || v6_addresses == 3));
    _globals.attach_v6_program = (v6_addresses != 0);
    IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&_globals.addresses[socket_family_t::IPv6].loopback_address);

    // Load the user token.
    _globals.user_type = _get_user_type(_user_type_string);
    _globals.user_token = _log_on_user(_user_name, _password);

    // Load and attach the programs.
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2");
    _globals.bpf_object.reset(bpf_object__open(helper.get_file_name().c_str()));
    REQUIRE(_globals.bpf_object.get() != nullptr);
    REQUIRE(bpf_object__load(_globals.bpf_object.get()) == 0);
    if (_globals.attach_v4_program) {
        printf("Attaching IPv4 program\n");
        bpf_program* connect_program_v4 =
            bpf_object__find_program_by_name(_globals.bpf_object.get(), "connect_redirect4");
        REQUIRE(connect_program_v4 != nullptr);

        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program_v4)), 0, BPF_CGROUP_INET4_CONNECT, 0);
        REQUIRE(result == 0);
    }
    if (_globals.attach_v6_program) {
        printf("Attaching IPv6 program\n");
        bpf_program* connect_program_v6 =
            bpf_object__find_program_by_name(_globals.bpf_object.get(), "connect_redirect6");
        REQUIRE(connect_program_v6 != nullptr);

        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program_v6)), 0, BPF_CGROUP_INET6_CONNECT, 0);
        REQUIRE(result == 0);
    }

    printf("Done initializing globals.\n");
    _globals_initialized = true;
}

static void
_validate_audit_map_entry(uint64_t authentication_id)
{
    bpf_map* audit_map = bpf_object__find_map_by_name(_globals.bpf_object.get(), "audit_map");
    REQUIRE(audit_map != nullptr);

    fd_t map_fd = bpf_map__fd(audit_map);

    uint64_t process_id = get_current_pid_tgid();
    sock_addr_audit_entry_t entry = {0};
    int result = bpf_map_lookup_elem(map_fd, &process_id, &entry);
    REQUIRE(result == 0);

    REQUIRE(process_id == entry.process_id);
    REQUIRE(entry.logon_id == authentication_id);
    SECURITY_LOGON_SESSION_DATA* data = NULL;
    result = LsaGetLogonSessionData((PLUID)&entry.logon_id, &data);
    REQUIRE(result == ERROR_SUCCESS);

    if (_globals.user_type == user_type_t::ADMINISTRATOR) {
        REQUIRE(entry.is_admin == 1);
    } else {
        REQUIRE(entry.is_admin == 0);
    }

    REQUIRE(entry.local_port != 0);
    REQUIRE(entry.socket_cookie != 0);

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
    REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);

    // Insert / delete redirect policy entry in the map.
    destination_entry_key_t key = {0};
    destination_entry_value_t value = {0};

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
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        REQUIRE(bpf_map_delete_elem(map_fd, &key) == 0);
    }
}

void
update_policy_map_and_test_connection(
    _In_ client_socket_t* sender_socket,
    _Inout_ sockaddr_storage& destination,
    _In_ const sockaddr_storage& proxy,
    uint16_t destination_port,
    uint16_t proxy_port,
    bool dual_stack)
{
    bool add_policy = true;
    uint32_t bytes_received = 0;
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

    {
        impersonation_helper_t helper(_globals.user_type);

        authentication_id = _get_current_thread_authentication_id();
        REQUIRE(authentication_id != 0);

        // Try to send and receive message to "destination". It should succeed.
        sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.destination_port);
        sender_socket->complete_async_send(1000, expected_result_t::SUCCESS);

        sender_socket->post_async_receive();
        sender_socket->complete_async_receive(2000, false);

        sender_socket->get_received_message(bytes_received, received_message);

        // For local redirection, the redirect context is expected to be set and returned.
        // If the connection is not redirected or is redirected to a remote address,
        // check for the SERVER_MESSAGE generic response.
        std::string expected_response;
        if (redirected && local_redirect && (_globals.connection_type == connection_type_t::TCP)) {
            expected_response = REDIRECT_CONTEXT_MESSAGE + std::to_string(proxy_port);
        } else {
            expected_response = SERVER_MESSAGE + std::to_string(proxy_port);
        }
        REQUIRE(strlen(received_message) == strlen(expected_response.c_str()));
        REQUIRE(memcmp(received_message, expected_response.c_str(), strlen(received_message)) == 0);
    }

    _validate_audit_map_entry(authentication_id);

    // Remove entry from policy map.
    add_policy = false;
    _update_policy_map(
        destination, proxy, destination_port, proxy_port, _globals.connection_type, dual_stack, add_policy);
}

void
authorize_test(_In_ client_socket_t* sender_socket, _Inout_ sockaddr_storage& destination, bool dual_stack)
{
    uint64_t authentication_id;
    // Default behavior of the eBPF program is to block the connection.

    // Send should fail as the connection is blocked.
    {
        impersonation_helper_t helper(_globals.user_type);

        authentication_id = _get_current_thread_authentication_id();
        REQUIRE(authentication_id != 0);

        sender_socket->send_message_to_remote_host(CLIENT_MESSAGE, destination, _globals.destination_port);
        sender_socket->complete_async_send(1000, expected_result_t::FAILURE);

        // Receive should time out as connection is blocked.
        sender_socket->post_async_receive(true);
        sender_socket->complete_async_receive(1000, true);
    }

    _validate_audit_map_entry(authentication_id);

    // Now update the policy map to allow the connection and test again.
    update_policy_map_and_test_connection(
        sender_socket, destination, destination, _globals.destination_port, _globals.destination_port, dual_stack);
}

void
get_client_socket(bool dual_stack, _Inout_ client_socket_t** sender_socket, const sockaddr_storage& source_address = {})
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
        new_socket = (client_socket_t*)new datagram_client_socket_t(SOCK_DGRAM, IPPROTO_UDP, 0, family, connected_udp);
    }

    *sender_socket = new_socket;
    if (old_socket) {
        delete old_socket;
    }
}

void
authorize_test_wrapper(bool dual_stack, _Inout_ sockaddr_storage& destination)
{
    client_socket_t* sender_socket = nullptr;

    get_client_socket(dual_stack, &sender_socket);
    authorize_test(sender_socket, destination, dual_stack);
    delete sender_socket;
}

void
connect_redirect_test_wrapper(
    _In_ const sockaddr_storage& source_address,
    _Inout_ sockaddr_storage& destination,
    _In_ const sockaddr_storage& proxy,
    bool dual_stack)
{
    client_socket_t* sender_socket = nullptr;

    get_client_socket(dual_stack, &sender_socket, source_address);
    update_policy_map_and_test_connection(
        sender_socket, destination, proxy, _globals.destination_port, _globals.proxy_port, dual_stack);
    delete sender_socket;
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

#define DECLARE_CONNECTION_REDIRECTION_TEST_FUNCTION(source, original_destination, new_destination)                  \
    void connection_redirection_tests_##original_destination##_##new_destination##(                                  \
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
            "REDIRECT: " #original_destination " -> " #new_destination " | %s | %s | %s\n",                          \
            connection_type_string,                                                                                  \
            family_string,                                                                                           \
            dual_stack_string);                                                                                      \
        connect_redirect_test_wrapper(                                                                               \
            addresses.##source##, addresses.##original_destination##, addresses.##new_destination##, dual_stack);    \
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

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli = session.cli() | Opt(_vip_v4, "v4 Virtual / Load Balanced IP")["-v"]["--virtual-ip-v4"]("IPv4 VIP") |
               Opt(_vip_v6, "v6 Virtual / Load Balanced IP")["-v"]["--virtual-ip-v6"]("IPv6 VIP") |
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
