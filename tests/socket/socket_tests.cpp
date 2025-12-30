// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This module facilitates testing various socket related eBPF program types and hooks.
 */

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_nethooks.h"
#include "ebpf_structs.h"
#include "filter_helper.h"
#include "misc_helper.h"
#include "native_helper.hpp"
#include "socket_helper.h"
#include "socket_tests_common.h"
#include "watchdog.h"

#include <chrono>
#include <future>
#include <iostream>
#include <memory>
#include <tuple>
#include <variant>
using namespace std::chrono_literals;
#include <mstcpip.h>

CATCH_REGISTER_LISTENER(_watchdog)

#define MULTIPLE_ATTACH_PROGRAM_COUNT 3

thread_local bool _is_main_thread = false;

void
_change_egress_policy_test_ingress_block(
    _In_ bpf_map* egress_connection_policy_map,
    _In_ connection_tuple_t& tuple,
    _In_ client_socket_t& sender_socket,
    _In_ receiver_socket_t& receiver_socket,
    _In_ const char* message,
    _In_ sockaddr_storage& destination_address,
    uint32_t verdict)
{
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_connection_policy_map), &tuple, &verdict, EBPF_ANY) == 0);

    // Send the packet. It should be dropped by the receive/accept program.
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    receiver_socket.complete_async_receive(true);
    // Cancel send operation.
    sender_socket.cancel_send_message();
}

/**
 * @brief Sock_addr policy configuration for connection tests.
 */
struct sock_addr_policy
{
    std::optional<uint32_t> egress_verdict{};  // For connect hook.
    std::optional<uint32_t> ingress_verdict{}; // For recv_accept hook.
};

/**
 * @brief Bind policy configuration for bind tests.
 */
struct bind_policy
{
    uint64_t process_id{0};          ///< Process ID (0 = wildcard).
    uint16_t port{0};                ///< Port number (in host byte order).
    uint8_t protocol{0};             ///< IP protocol (e.g., IPPROTO_TCP).
    bind_action_t action{BIND_DENY}; ///< Action to take for this bind policy.
};

/**
 * @brief No policy (used for detach/reattach tests without map updates).
 */
struct no_policy
{};

/**
 * @brief Expected test result.
 */
enum class connection_test_result
{
    allow,
    block,
};

/**
 * @brief Test parameters for individual connection test.
 */
struct connection_test_params
{
    std::string_view description;

    // Expected bind error for server socket (0 = expect success).
    std::optional<int> expected_server_bind_error{};

    // Expected outcome.
    connection_test_result expected_result{connection_test_result::block};

    std::optional<uint32_t> egress_verdict{};  ///< Egress verdict for connect hook.
    std::optional<uint32_t> ingress_verdict{}; ///< Ingress verdict for recv_accept hook.
    std::optional<bind_policy> bind_policy{};  ///< Bind policy to apply for this test.
    std::optional<bind_action_t>
        bind_verdict{}; ///< Simplified bind policy (uses current process, test port, test protocol).
};

/**
 * @brief Program specification for attaching.
 */
struct program_spec
{
    std::string_view program_name; ///< Name of the program.
    bpf_attach_type attach_type;   ///< Attach type for the program.
};

/**
 * @brief Module specification containing object file and programs to load.
 */
struct module_spec
{
    std::string_view object_file;         ///< Object file name, e.g., "cgroup_sock_addr", "bind_policy".
    std::vector<program_spec> programs{}; ///< Programs to load from the object file.
};

/**
 * @brief Connection test case specification.
 *
 * Filters will be applied before test execution and removed after.
 *
 * @note currently hardcodes the expected ingress/egress/bind policy map names.
 */
struct connection_test_case
{
    std::string_view name{}; ///< Test case name.

    // Network parameters.
    ADDRESS_FAMILY address_family{AF_INET}; ///< AF_INET or AF_INET6.
    IPPROTO protocol{IPPROTO_TCP};          ///< IPPROTO_TCP or IPPROTO_UDP.

    std::vector<module_spec> modules{}; ///< Modules to load.

    std::vector<wfp_test_filter_spec> wfp_filters{}; ///< WFP filters to apply before the tests.
    std::vector<connection_test_params> tests{};     ///< Individual test parameters to execute in order.
};

/**
 * @brief Expected result types for bind operation testing.
 */
typedef enum _bind_test_result
{
    BIND_TEST_ALLOW,   ///< Bind should succeed without modification.
    BIND_TEST_DENY,    ///< Bind should be denied/blocked.
    BIND_TEST_REDIRECT ///< Bind should succeed but be redirected to a different port.
} bind_test_result_t;

/**
 * @brief Update or delete an entry in the bind policy map for testing.
 *
 * This helper function manages bind policy entries in the eBPF map used by test programs.
 * It supports adding new policies, updating existing ones, and removing policies for
 * cleanup. This enables precise control over bind behavior during testing.
 *
 * @param[in] map_fd File descriptor of the bind policy map.
 * @param[in] process_id Process ID for the policy (0 = wildcard).
 * @param[in] port Port number for the policy (0 = wildcard).
 * @param[in] protocol IP protocol for the policy (0 = wildcard).
 * @param[in] action Bind action to take (PERMIT_SOFT, PERMIT_HARD, DENY, REDIRECT).
 * @param[in] add True to add/update entry, false to delete entry.
 */
void
_update_bind_policy_map_entry(
    fd_t map_fd, uint64_t process_id, uint16_t port, uint8_t protocol, bind_action_t action, bool add = true)
{
    bind_policy_key_t key = {0};
    bind_policy_value_t value = {0};

    key.process_id = process_id;
    key.port = port;
    key.protocol = protocol;

    value.action = action;
    value.flags = 0;

    if (add) {
        SAFE_REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        bpf_map_delete_elem(map_fd, &key);
    }
}

/**
 * @brief Execute a connection attempt and validate the result.
 *
 * This function sends a test message from the client to the server on the specified port
 * and validates that the connection behaves according to the expected result (allow or block).
 *
 * @param[in,out] client Client socket that sends the test message.
 * @param[in,out] server Server socket that receives the test message.
 * @param[in] address_family Address family (AF_INET or AF_INET6) for the connection.
 * @param[in] expected_result Expected outcome of the connection attempt (allow or block).
 * @param[in] target_port Port number to connect to.
 */
static void
execute_connection_attempt(
    _Inout_ std::unique_ptr<client_socket_t>& client,
    _Inout_ std::unique_ptr<receiver_socket_t>& server,
    _In_ ADDRESS_FAMILY address_family,
    _In_ connection_test_result expected_result,
    _In_ uint16_t target_port)
{
    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }

    client->send_message_to_remote_host(message, destination_address, target_port);

    if (expected_result == connection_test_result::block) {
        server->complete_async_receive(true);
        client->cancel_send_message();
    } else if (expected_result == connection_test_result::allow) {
        client->complete_async_send(1000, expected_result_t::SUCCESS);
        server->complete_async_receive(false);
    } else {
        FAIL("Unsupported expected result");
    }
}

/**
 * @brief Execute a connection test case.
 *
 * This function orchestrates a complete connection test scenario including:
 * - Loading eBPF modules and programs from object files
 * - Creating WFP filters if specified
 * - Retrieving policy maps (sock_addr and bind)
 * - Attaching eBPF programs to their respective attach points
 * - Creating and managing client/server socket pairs
 * - Executing individual test steps with configured policies
 * - Validating connection behavior against expected results
 *
 * The function handles both TCP and UDP protocols across IPv4 and IPv6 address families,
 * and supports testing connect (ingress and or egress) and bind policies.
 *
 * @param[in] test_case Test case specification containing modules, programs, filters,
 *                      and individual test configurations to execute.
 */
static void
execute_connection_test(_In_ const connection_test_case& test_case)
{
    // Load modules (object files + programs).
    struct loaded_program
    {
        bpf_program* program;
        program_spec spec;
        bpf_link* link;
    };
    struct loaded_module
    {
        native_module_helper_t helper;
        bpf_object_ptr object;
        std::vector<loaded_program> programs;
    };
    std::vector<loaded_module> loaded_modules;

    for (const auto& module : test_case.modules) {
        loaded_module mod;
        mod.helper.initialize(module.object_file.data(), _is_main_thread);

        struct bpf_object* obj = bpf_object__open(mod.helper.get_file_name().c_str());
        SAFE_REQUIRE(obj != nullptr);
        SAFE_REQUIRE(bpf_object__load(obj) == 0);
        mod.object = bpf_object_ptr(obj);

        for (const auto& prog_spec : module.programs) {
            auto* prog = bpf_object__find_program_by_name(obj, prog_spec.program_name.data());
            SAFE_REQUIRE(prog != nullptr);
            mod.programs.push_back({prog, prog_spec, nullptr});
        }

        loaded_modules.push_back(std::move(mod));
    }

    // Create WFP filters if specified.
    std::unique_ptr<filter_helper> filter;
    if (!test_case.wfp_filters.empty()) {
        try {
            filter = std::make_unique<filter_helper>(test_case.wfp_filters);
        } catch (const std::exception& ex) {
            FAIL("Filter helper initialization failed: " << ex.what());
        }
    }

    // Get policy maps (sock_addr or bind).
    bpf_map* ingress_map = nullptr;
    bpf_map* egress_map = nullptr;
    bpf_map* bind_policy_map = nullptr;

    for (const auto& mod : loaded_modules) {
        if (!ingress_map) {
            ingress_map = bpf_object__find_map_by_name(mod.object.get(), "ingress_connection_policy_map");
        }
        if (!egress_map) {
            egress_map = bpf_object__find_map_by_name(mod.object.get(), "egress_connection_policy_map");
        }
        if (!bind_policy_map) {
            bind_policy_map = bpf_object__find_map_by_name(mod.object.get(), "bind_policy_map");
        }
    }

    // Setup connection tuple for sock_addr tests.
    connection_tuple_t tuple{0};
    if (test_case.address_family == AF_INET) {
        tuple.remote_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(tuple.remote_ip.ipv6, &in6addr_loopback, sizeof(tuple.remote_ip.ipv6));
    }
    tuple.remote_port = htons(SOCKET_TEST_PORT);
    tuple.protocol = test_case.protocol;

    // Initialize verdict maps to REJECT.
    ebpf_sock_addr_verdict_t sock_addr_reject_verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    if (ingress_map) {
        SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(ingress_map), &tuple, &sock_addr_reject_verdict, EBPF_ANY) == 0);
    }
    if (egress_map) {
        SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_map), &tuple, &sock_addr_reject_verdict, EBPF_ANY) == 0);
    }

    // Attach all programs before executing tests.
    for (auto& mod : loaded_modules) {
        CAPTURE(mod.helper.get_file_name());
        for (auto& loaded_program : mod.programs) {
            bpf_program* program = loaded_program.program;
            CAPTURE(
                std::string(loaded_program.spec.program_name),
                loaded_program.spec.attach_type,
                bpf_program__fd(loaded_program.program));
            ebpf_attach_type_t attach_type_guid{};
            SAFE_REQUIRE(ebpf_get_ebpf_attach_type(loaded_program.spec.attach_type, &attach_type_guid) == EBPF_SUCCESS);
            SAFE_REQUIRE(ebpf_program_attach(program, &attach_type_guid, nullptr, 0, nullptr) == EBPF_SUCCESS);
        }
    }

    // Execute tests.
    std::unique_ptr<client_socket_t> client;
    std::unique_ptr<receiver_socket_t> server;
    int test_index = 0;

    for (const auto& test : test_case.tests) {
        INFO("test " << test_index << ": " << test.description);
        CAPTURE(test.expected_result);

        // Update policy maps based on test policy.
        if (test.egress_verdict) {
            SAFE_REQUIRE(egress_map != nullptr);
            SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(egress_map), &tuple, &(*test.egress_verdict), EBPF_ANY) == 0);
        }
        if (test.ingress_verdict) {
            SAFE_REQUIRE(ingress_map != nullptr);
            SAFE_REQUIRE(
                bpf_map_update_elem(bpf_map__fd(ingress_map), &tuple, &(*test.ingress_verdict), EBPF_ANY) == 0);
        }
        if (test.bind_policy) {
            SAFE_REQUIRE(bind_policy_map != nullptr);
            _update_bind_policy_map_entry(
                bpf_map__fd(bind_policy_map),
                test.bind_policy->process_id,
                test.bind_policy->port,
                test.bind_policy->protocol,
                test.bind_policy->action);
        }
        if (test.bind_verdict) {
            SAFE_REQUIRE(bind_policy_map != nullptr);
            _update_bind_policy_map_entry(
                bpf_map__fd(bind_policy_map),
                0, // process_id = 0 (wildcard).
                static_cast<uint16_t>(SOCKET_TEST_PORT),
                static_cast<uint8_t>(test_case.protocol),
                *test.bind_verdict);
        }

        // Create sockets on init or after reset.
        if (!server) {
            int server_bind_error = test.expected_server_bind_error.value_or(0);

            if (test_case.protocol == IPPROTO_TCP) {
                server = std::make_unique<stream_server_socket_t>(
                    static_cast<uint16_t>(SOCK_STREAM),
                    IPPROTO_TCP,
                    static_cast<uint16_t>(SOCKET_TEST_PORT),
                    sockaddr_storage{},
                    server_bind_error);
            } else if (test_case.protocol == IPPROTO_UDP) {
                server = std::make_unique<datagram_server_socket_t>(
                    static_cast<uint16_t>(SOCK_DGRAM),
                    IPPROTO_UDP,
                    static_cast<uint16_t>(SOCKET_TEST_PORT),
                    sockaddr_storage{},
                    server_bind_error);
            }

            // If bind was expected to fail, skip connection testing.
            if (server_bind_error != 0) {
                server.reset();
                client.reset();
                continue;
            }
            SAFE_REQUIRE(server != nullptr);

            server->post_async_receive();
        }

        if (!client) {
            if (test_case.protocol == IPPROTO_TCP) {
                client = std::make_unique<stream_client_socket_t>(
                    static_cast<uint16_t>(SOCK_STREAM), IPPROTO_TCP, static_cast<uint16_t>(0));
            } else if (test_case.protocol == IPPROTO_UDP) {
                client = std::make_unique<datagram_client_socket_t>(
                    static_cast<uint16_t>(SOCK_DGRAM), IPPROTO_UDP, static_cast<uint16_t>(0));
            }
            SAFE_REQUIRE(client != nullptr);
        }

        // Connection test (sock_addr).
        execute_connection_attempt(client, server, test_case.address_family, test.expected_result, SOCKET_TEST_PORT);

        if (test.expected_result == connection_test_result::allow) {
            // Reset sockets for next test after allow.
            client.reset();
            server.reset();
        }

        ++test_index;
    }
}

// Type tuples for TEMPLATE_TEST_CASE: (address_family, protocol).
using tcp_v4_params =
    std::tuple<std::integral_constant<ADDRESS_FAMILY, AF_INET>, std::integral_constant<IPPROTO, IPPROTO_TCP>>;
using tcp_v6_params =
    std::tuple<std::integral_constant<ADDRESS_FAMILY, AF_INET6>, std::integral_constant<IPPROTO, IPPROTO_TCP>>;
using udp_v4_params =
    std::tuple<std::integral_constant<ADDRESS_FAMILY, AF_INET>, std::integral_constant<IPPROTO, IPPROTO_UDP>>;
using udp_v6_params =
    std::tuple<std::integral_constant<ADDRESS_FAMILY, AF_INET6>, std::integral_constant<IPPROTO, IPPROTO_UDP>>;

#define ALL_CONNECTION_TEST_PARAMS tcp_v4_params, tcp_v6_params, udp_v4_params, udp_v6_params

TEST_CASE("connection_test_attach_all", "[attach]")
{
    execute_connection_test({
        .name = "attach_all_programs",
        .address_family = AF_INET,
        .protocol = IPPROTO_TCP,
        .modules{
            {{
                 .object_file = "sockops",
                 .programs{{"connection_monitor", BPF_CGROUP_SOCK_OPS}},
             },
             {
                 .object_file = "bind_policy",
                 .programs{{"authorize_bind", BPF_ATTACH_TYPE_BIND}},
             },
             {
                 .object_file = "cgroup_sock_addr",
                 .programs{
                     {"authorize_connect4", BPF_CGROUP_INET4_CONNECT},
                     {"authorize_connect6", BPF_CGROUP_INET6_CONNECT},
                     {"authorize_recv_accept4", BPF_CGROUP_INET4_RECV_ACCEPT},
                     {"authorize_recv_accept6", BPF_CGROUP_INET6_RECV_ACCEPT},
                 },
             }}},
    });
}

TEMPLATE_TEST_CASE("connection_test_recv_accept", "[sock_addr_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test(
        {.name = "connection_test_recv_accept",
         .address_family = family,
         .protocol = protocol,
         .modules{
             {.object_file = "cgroup_sock_addr",
              .programs{
                  {.program_name = (family == AF_INET) ? "authorize_recv_accept4" : "authorize_recv_accept6",
                   .attach_type = (family == AF_INET) ? BPF_CGROUP_INET4_RECV_ACCEPT : BPF_CGROUP_INET6_RECV_ACCEPT}}}},
         .tests{
             {
                 .description = "recv_accept blocked with reject verdict",
             },
             {
                 .description = "recv_accept allowed with proceed verdict",
                 .expected_result = connection_test_result::allow,
                 .ingress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
             },
             {
                 .description = "recv_accept allowed with hard proceed verdict",
                 .expected_result = connection_test_result::allow,
                 .ingress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD,
             },
         }});
}

// Block/allow test with only connect program attached.
TEMPLATE_TEST_CASE("connection_test_connect", "[sock_addr_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test(
        {.name = "connection_test_connect",
         .address_family = family,
         .protocol = protocol,
         .modules{{{
             .object_file = "cgroup_sock_addr",
             .programs{
                 {(family == AF_INET) ? "authorize_connect4" : "authorize_connect6",
                  (family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT},
             },
         }}},
         .tests{
             {
                 .description = "connect blocked with reject verdict",
             },
             {
                 .description = "connect allowed with soft proceed verdict",
                 .expected_result = connection_test_result::allow,
                 .egress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
             },
             {
                 .description = "connect allowed with hard proceed verdict",
                 .expected_result = connection_test_result::allow,
                 .egress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD,
             },
         }});
}

// sock_addr ingress/egress policy tests.
TEMPLATE_TEST_CASE("connection_test_sock_addr", "[sock_addr_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test(
        {.name = "connection_test_sock_addr",
         .address_family = family,
         .protocol = protocol,
         .modules{
             {{.object_file = "cgroup_sock_addr",
               .programs{
                   {{(family == AF_INET) ? "authorize_connect4" : "authorize_connect6",
                     (family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT},
                    {(family == AF_INET) ? "authorize_recv_accept4" : "authorize_recv_accept6",
                     (family == AF_INET) ? BPF_CGROUP_INET4_RECV_ACCEPT : BPF_CGROUP_INET6_RECV_ACCEPT}}}}}},
         .tests{
             {
                 .description = "Initial reject egress+ingress",
             },
             {
                 .description = "Hard permit egress, reject ingress",
                 .egress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD,
             },
             {
                 .description = "Soft permit egress, reject ingress",
                 .egress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
             },
             {
                 .description = "Soft permit egress+ingress",
                 .expected_result = connection_test_result::allow,
                 .ingress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
             },
         }});
}

TEMPLATE_TEST_CASE("connection_test_recv_accept_hard_permit", "[sock_addr_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test(
        {.name = "connection_test_recv_accept_hard_permit",
         .address_family = family,
         .protocol = protocol,
         .modules{
             {{.object_file = "cgroup_sock_addr",
               .programs{
                   {(family == AF_INET) ? "authorize_recv_accept4" : "authorize_recv_accept6",
                    (family == AF_INET) ? BPF_CGROUP_INET4_RECV_ACCEPT : BPF_CGROUP_INET6_RECV_ACCEPT}}}}},
         .wfp_filters{
             {
                 .layer = (family == AF_INET) ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                 .local_port = static_cast<uint16_t>(SOCKET_TEST_PORT),
             },
         },
         .tests{
             {
                 .description = "Soft permit blocked by WFP",
                 .ingress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
             },
             {
                 .description = "Hard permit overrides WFP",
                 .expected_result = connection_test_result::allow,
                 .ingress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD,
             },
         }});
}

TEMPLATE_TEST_CASE("connection_test_connect_hard_permit", "[sock_addr_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test(
        {.name = "connection_test_connect_hard_permit",
         .address_family = family,
         .protocol = protocol,
         .modules{
             {{.object_file = "cgroup_sock_addr",
               .programs{
                   {(family == AF_INET) ? "authorize_connect4" : "authorize_connect6",
                    (family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT}}}}},
         .wfp_filters{
             {
                 .layer = (family == AF_INET) ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                 .remote_port = static_cast<uint16_t>(SOCKET_TEST_PORT),
             },
         },
         .tests{
             {
                 .description = "Soft permit blocked by WFP",
                 .egress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT,
             },
             {
                 .description = "Hard permit overrides WFP",
                 .expected_result = connection_test_result::allow,
                 .egress_verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD,
             },
         }});
}

// Bind policy basic functionality tests.
TEMPLATE_TEST_CASE("bind_policy_basic", "[bind_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test({
        .name = "bind_policy_basic",
        .address_family = family,
        .protocol = protocol,
        .modules{{{
            .object_file = "bind_policy",
            .programs{{"authorize_bind", BPF_ATTACH_TYPE_BIND}},
        }}},
        .tests{
            {
                .description = "Bind denied with deny policy",
                .expected_server_bind_error = WSAEACCES,
                .bind_verdict = BIND_DENY,
            },
            {
                .description = "Bind allowed with soft permit",
                .expected_result = connection_test_result::allow,
                .bind_verdict = BIND_PERMIT_SOFT,
            },
            {
                .description = "Bind allowed with hard permit",
                .expected_result = connection_test_result::allow,
                .bind_verdict = BIND_PERMIT_HARD,
            },
        },
    });
}

// Bind policy hard permit with WFP filter.
TEMPLATE_TEST_CASE("bind_policy_hard_permit_wfp", "[bind_tests]", ALL_CONNECTION_TEST_PARAMS)
{
    constexpr ADDRESS_FAMILY family = std::tuple_element_t<0, TestType>::value;
    constexpr IPPROTO protocol = std::tuple_element_t<1, TestType>::value;
    execute_connection_test({
        .name = "bind_policy_hard_permit_wfp",
        .address_family = family,
        .protocol = protocol,
        .modules{{{.object_file = "bind_policy", .programs{{"authorize_bind", BPF_ATTACH_TYPE_BIND}}}}},
        .wfp_filters{
            {
                .layer = FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
                .local_port = static_cast<uint16_t>(SOCKET_TEST_PORT),
            },
        },
        .tests{
            {
                .description = "Soft permit blocked by WFP filter",
                .expected_server_bind_error = WSAEACCES,
                .bind_verdict = BIND_PERMIT_SOFT,
            },
            {
                .description = "Hard permit overrides WFP filter",
                .expected_result = connection_test_result::allow,
                .bind_verdict = BIND_PERMIT_HARD,
            },
        },
    });
}

TEST_CASE("attach_sock_addr_programs", "[sock_addr_tests]")
{
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);

    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr", _is_main_thread);

    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* connect4_program = bpf_object__find_program_by_name(object, "authorize_connect4");
    SAFE_REQUIRE(connect4_program != nullptr);

    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_CONNECT,
        0);
    SAFE_REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    SAFE_REQUIRE(program_info.link_count == 1);
    SAFE_REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach(UNSPECIFIED_COMPARTMENT_ID, BPF_CGROUP_INET4_CONNECT);
    SAFE_REQUIRE(result == 0);

    ZeroMemory(&program_info, program_info_size);
    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), &program_info, &program_info_size) == 0);
    SAFE_REQUIRE(program_info.link_count == 0);

    bpf_program* recv_accept4_program = bpf_object__find_program_by_name(object, "authorize_recv_accept4");
    SAFE_REQUIRE(recv_accept4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT,
        0);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    SAFE_REQUIRE(program_info.link_count == 1);
    SAFE_REQUIRE(program_info.map_ids == 0);

    result = bpf_prog_detach2(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)),
        UNSPECIFIED_COMPARTMENT_ID,
        BPF_CGROUP_INET4_RECV_ACCEPT);
    SAFE_REQUIRE(result == 0);

    SAFE_REQUIRE(
        bpf_obj_get_info_by_fd(
            bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), &program_info, &program_info_size) ==
        0);
    SAFE_REQUIRE(program_info.link_count == 0);

    bpf_program* connect6_program = bpf_object__find_program_by_name(object, "authorize_connect6");
    SAFE_REQUIRE(connect6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_CONNECT,
        0);
    SAFE_REQUIRE(result == 0);

    bpf_program* recv_accept6_program = bpf_object__find_program_by_name(object, "authorize_recv_accept6");
    SAFE_REQUIRE(recv_accept6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept6_program)),
        DEFAULT_COMPARTMENT_ID,
        BPF_CGROUP_INET6_RECV_ACCEPT,
        0);
    SAFE_REQUIRE(result == 0);
}

void
connection_monitor_test(
    ADDRESS_FAMILY address_family,
    _Inout_ client_socket_t& sender_socket,
    _Inout_ receiver_socket_t& receiver_socket,
    uint32_t protocol,
    bool disconnect)
{
    native_module_helper_t helper;
    helper.initialize("sockops", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Ring buffer event callback context.
    std::unique_ptr<ring_buffer_test_event_context_t> context = std::make_unique<ring_buffer_test_event_context_t>();
    context->test_event_count = disconnect ? 4 : 2;

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    SAFE_REQUIRE(_program != nullptr);

    uint64_t process_id = get_current_pid_tgid();
    // Ignore the thread Id.
    process_id >>= 32;

    PSOCKADDR local_address = nullptr;
    int local_address_length = 0;
    sender_socket.get_local_address(local_address, local_address_length);

    connection_tuple_t tuple{}, reverse_tuple{};
    if (address_family == AF_INET) {
        tuple.local_ip.ipv4 = htonl(INADDR_LOOPBACK);
        tuple.remote_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(tuple.local_ip.ipv6, &in6addr_loopback, sizeof(tuple.local_ip.ipv6));
        memcpy(tuple.remote_ip.ipv6, &in6addr_loopback, sizeof(tuple.local_ip.ipv6));
    }
    tuple.local_port = INETADDR_PORT(local_address);
    tuple.remote_port = htons(SOCKET_TEST_PORT);
    tuple.protocol = protocol;
    NET_LUID net_luid = {};
    net_luid.Info.IfType = IF_TYPE_SOFTWARE_LOOPBACK;
    tuple.interface_luid = net_luid.Value;

    reverse_tuple.local_ip = tuple.remote_ip;
    reverse_tuple.remote_ip = tuple.local_ip;
    reverse_tuple.local_port = tuple.remote_port;
    reverse_tuple.remote_port = tuple.local_port;
    reverse_tuple.protocol = tuple.protocol;
    reverse_tuple.interface_luid = tuple.interface_luid;

    std::vector<std::vector<char>> audit_entry_list;
    audit_entry_t audit_entries[4] = {0};

    // Connect outbound.
    audit_entries[0].tuple = tuple;
    audit_entries[0].process_id = process_id;
    audit_entries[0].connected = true;
    audit_entries[0].outbound = true;
    char* p = reinterpret_cast<char*>(&audit_entries[0]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Connect inbound.
    audit_entries[1].tuple = reverse_tuple;
    audit_entries[1].process_id = process_id;
    audit_entries[1].connected = true;
    audit_entries[1].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[1]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create an audit entry for the disconnect case.
    // The direction bit is set to false.
    audit_entries[2].tuple = tuple;
    audit_entries[2].process_id = process_id;
    audit_entries[2].connected = false;
    audit_entries[2].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[2]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    // Create another audit entry for the disconnect event with the reverse packet tuple.
    audit_entries[3].tuple = reverse_tuple;
    audit_entries[3].process_id = process_id;
    audit_entries[3].connected = false;
    audit_entries[3].outbound = false;
    p = reinterpret_cast<char*>(&audit_entries[3]);
    audit_entry_list.push_back(std::vector<char>(p, p + sizeof(audit_entry_t)));

    context->records = &audit_entry_list;

    // Get the std::future from the promise field in ring buffer event context, which should be in ready state
    // once notifications for all events are received.
    auto ring_buffer_event_callback = context->ring_buffer_event_promise.get_future();

    // Create a new ring buffer manager and subscribe to ring buffer events (using async mode for automatic callbacks).
    bpf_map* ring_buffer_map = bpf_object__find_map_by_name(object, "audit_map");
    SAFE_REQUIRE(ring_buffer_map != nullptr);
    ebpf_ring_buffer_opts ring_opts{.sz = sizeof(ring_opts), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
    context->ring_buffer = ebpf_ring_buffer__new(
        bpf_map__fd(ring_buffer_map), (ring_buffer_sample_fn)ring_buffer_test_event_handler, context.get(), &ring_opts);
    SAFE_REQUIRE(context->ring_buffer != nullptr);

    bpf_map* connection_map = bpf_object__find_map_by_name(object, "connection_map");
    SAFE_REQUIRE(connection_map != nullptr);

    // Update connection map with loopback packet tuples.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &tuple, &verdict, EBPF_ANY) == 0);
    SAFE_REQUIRE(bpf_map_update_elem(bpf_map__fd(connection_map), &reverse_tuple, &verdict, EBPF_ANY) == 0);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket.post_async_receive();

    // Attach the sockops program.
    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    SAFE_REQUIRE(result == 0);

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }
    sender_socket.send_message_to_remote_host(message, destination_address, SOCKET_TEST_PORT);
    // Receive the packet on test port.
    receiver_socket.complete_async_receive();

    if (disconnect) {
        sender_socket.close();
        receiver_socket.close();
    }

    // Wait for event handler getting notifications for all connection audit events.
    SAFE_REQUIRE(ring_buffer_event_callback.wait_for(1s) == std::future_status::ready);

    // Mark the event context as canceled, such that the event callback stops processing events.
    context->canceled = true;

    // Unsubscribe.
    context->unsubscribe();
}

TEST_CASE("connection_monitor_test_udp_v4", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, false);
}
TEST_CASE("connection_monitor_test_disconnect_udp_v4", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, true);
}

TEST_CASE("connection_monitor_test_udp_v6", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, false);
}
TEST_CASE("connection_monitor_test_disconnect_udp_v6", "[sock_ops_tests]")
{
    datagram_client_socket_t datagram_client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    datagram_server_socket_t datagram_server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, datagram_client_socket, datagram_server_socket, IPPROTO_UDP, true);
}

TEST_CASE("connection_monitor_test_tcp_v4", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP, false);
}
TEST_CASE("connection_monitor_test_disconnect_tcp_v4", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET, stream_client_socket, stream_server_socket, IPPROTO_TCP, true);
}

TEST_CASE("connection_monitor_test_tcp_v6", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP, false);
}
TEST_CASE("connection_monitor_test_disconnect_tcp_v6", "[sock_ops_tests]")
{
    stream_client_socket_t stream_client_socket(SOCK_STREAM, IPPROTO_TCP, 0);
    stream_server_socket_t stream_server_socket(SOCK_STREAM, IPPROTO_TCP, SOCKET_TEST_PORT);

    connection_monitor_test(AF_INET6, stream_client_socket, stream_server_socket, IPPROTO_TCP, true);
}

TEST_CASE("attach_sockops_programs", "[sock_ops_tests]")
{
    native_module_helper_t helper;
    helper.initialize("sockops", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    bpf_object_ptr object_ptr(object);

    SAFE_REQUIRE(object != nullptr);
    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    bpf_program* _program = bpf_object__find_program_by_name(object, "connection_monitor");
    SAFE_REQUIRE(_program != nullptr);

    int result = bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(_program)), 0, BPF_CGROUP_SOCK_OPS, 0);
    SAFE_REQUIRE(result == 0);
}

// This function populates map policies for multi-attach tests.
// It assumes that the destination and proxy are loopback addresses.
static void
_update_map_entry_multi_attach(
    fd_t map_fd,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    uint32_t verdict,
    bool add)
{
    destination_entry_key_t key = {0};
    destination_entry_value_t value = {0};

    if (address_family == AF_INET) {
        key.destination_ip.ipv4 = htonl(INADDR_LOOPBACK);
        value.destination_ip.ipv4 = htonl(INADDR_LOOPBACK);
    } else {
        memcpy(key.destination_ip.ipv6, &in6addr_loopback, sizeof(key.destination_ip.ipv6));
        memcpy(value.destination_ip.ipv6, &in6addr_loopback, sizeof(value.destination_ip.ipv6));
    }
    key.destination_port = destination_port;
    key.protocol = protocol;
    value.destination_port = proxy_port;
    value.verdict = verdict;

    if (add) {
        SAFE_REQUIRE(bpf_map_update_elem(map_fd, &key, &value, 0) == 0);
    } else {
        bpf_map_delete_elem(map_fd, &key);
    }
}

static void
_update_map_entry_multi_attach(
    fd_t map_fd,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    bool add)
{
    _update_map_entry_multi_attach(
        map_fd, address_family, destination_port, proxy_port, protocol, BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT, add);
}

static void
_update_map_entry_multi_attach(
    fd_t map_fd,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    uint32_t verdict)
{
    _update_map_entry_multi_attach(map_fd, address_family, destination_port, proxy_port, protocol, verdict, true);
}

typedef enum _connection_result
{
    RESULT_ALLOW,
    RESULT_DROP,
    RESULT_DONT_CARE
} connection_result_t;

void
get_client_socket(socket_family_t family, uint16_t protocol, _Inout_ client_socket_t** sender_socket)
{
    client_socket_t* old_socket = *sender_socket;
    client_socket_t* new_socket = nullptr;
    if (protocol == IPPROTO_TCP) {
        new_socket = (client_socket_t*)new stream_client_socket_t(SOCK_STREAM, IPPROTO_TCP, 0, family);
    } else {
        new_socket = (client_socket_t*)new datagram_client_socket_t(SOCK_DGRAM, IPPROTO_UDP, 0, family);
    }

    *sender_socket = new_socket;
    if (old_socket) {
        delete old_socket;
    }
}

void
validate_connection_multi_attach(
    socket_family_t family,
    ADDRESS_FAMILY address_family,
    uint16_t receiver_port,
    uint16_t destination_port,
    uint16_t protocol,
    connection_result_t expected_result)
{
    client_socket_t* sender_socket = nullptr;
    receiver_socket_t* receiver_socket = nullptr;

    if (protocol == IPPROTO_UDP) {
        receiver_socket = new datagram_server_socket_t(SOCK_DGRAM, IPPROTO_UDP, receiver_port);
    } else if (protocol == IPPROTO_TCP) {
        receiver_socket = new stream_server_socket_t(SOCK_STREAM, IPPROTO_TCP, receiver_port);
    } else {
        SAFE_REQUIRE(false);
    }
    get_client_socket(family, protocol, &sender_socket);

    // Post an asynchronous receive on the receiver socket.
    receiver_socket->post_async_receive();

    // Send loopback message to test port.
    const char* message = CLIENT_MESSAGE;
    sockaddr_storage destination_address{};
    if (address_family == AF_INET) {
        if (family == socket_family_t::Dual) {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        } else {
            IN4ADDR_SETLOOPBACK((PSOCKADDR_IN)&destination_address);
        }
    } else {
        IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
    }

    sender_socket->send_message_to_remote_host(message, destination_address, destination_port);

    if (expected_result == RESULT_DROP) {
        // The packet should be blocked.
        receiver_socket->complete_async_receive(true);
        // Cancel send operation.
        sender_socket->cancel_send_message();
    } else if (expected_result == RESULT_ALLOW) {
        // The packet should be allowed by the connect program.
        receiver_socket->complete_async_receive();
    } else {
        // The result is not deterministic, so we don't care about the result.
        receiver_socket->complete_async_receive(1000, receiver_socket_t::MODE_DONT_CARE);
    }

    delete sender_socket;
    delete receiver_socket;
}

void
multi_attach_test_common(
    bpf_object* object,
    socket_family_t family,
    ADDRESS_FAMILY address_family,
    uint32_t compartment_id,
    uint16_t protocol,
    bool detach_program)
{
    // This function assumes that all the attached programs already allow the connection.
    // It then proceeds to test the following:
    // 1. For the provided program object, update policy map to block the connection
    //    and validate that the connection is blocked.
    // 2. Revert the policy to allow the connection, validate that the connection is now allowed.
    //
    // Along with the above, if "detach_program" is true, the function will also test the following:
    // 1. Update policy map to block the connection, validate that the connection is blocked.
    // 2. Detach the program, validate that the connection should now be allowed.
    // 3. Re-attach the program, and validate that the connection is again blocked.
    // 4. Update policy map to allow the connection, validate that the connection is allowed.

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    uint32_t verdict = compartment_id == UNSPECIFIED_COMPARTMENT_ID ? BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT
                                                                    : BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;

    // Deleting the map entry will result in the program blocking the connection.
    _update_map_entry_multi_attach(
        map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, false);

    // The packet should be blocked.
    validate_connection_multi_attach(family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

    // Revert the policy to "allow" the connection.
    _update_map_entry_multi_attach(
        map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, verdict);

    // The packet should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

    if (detach_program) {
        // Block the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, false);

        // The packet should be blocked.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

        // Detach the program.
        int result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, attach_type);
        SAFE_REQUIRE(result == 0);

        // The packet should now be allowed.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

        // Re-attach the program.
        result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);

        // The packet should be blocked.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_DROP);

        // Update the policy to "allow" the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, verdict);

        // The packet should now be allowed.
        validate_connection_multi_attach(
            family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);
    }
}

void
multi_attach_test(uint32_t compartment_id, socket_family_t family, ADDRESS_FAMILY address_family, uint16_t protocol)
{
    // This test is to verify that multiple programs can be attached to the same hook, and they work as expected.
    // Scenarios covered:
    // 1. Multiple programs attached to the same hook.
    // 2. For multiple programs attached to same hook, validate the order of execution.
    // 3. For multiple programs attached to same hook, validate the verdict based on the order of execution.
    // 4. Programs attached to different hooks -- only one should be invoked.

    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    uint32_t verdict = compartment_id == UNSPECIFIED_COMPARTMENT_ID ? BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT
                                                                    : BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;

    // Load the programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2", _is_main_thread);
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";

    // Attach all the programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);
    }

    // Configure policy maps for all programs to "allow" the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
        SAFE_REQUIRE(policy_map != nullptr);
        fd_t map_fd = bpf_map__fd(policy_map);
        SAFE_REQUIRE(map_fd != ebpf_fd_invalid);
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), protocol, verdict);
    }

    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);

    // Test that the connection is blocked if any of the programs block the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        multi_attach_test_common(objects[i], family, address_family, compartment_id, protocol, false);
    }

    // Next section tests detach and re-attach of programs.
    // Current attach order is 0 --> 1 --> 2. Detach "first" program and check if the verdict changes.
    multi_attach_test_common(objects[0], family, address_family, compartment_id, protocol, true);

    // Now the program attach order is 1 --> 2 --> 0. Repeat detach / reattach with the "middle" program.
    multi_attach_test_common(objects[2], family, address_family, compartment_id, protocol, true);

    // Now the program attach order is 1 --> 0 --> 2. Repeat it with the "last" program.
    multi_attach_test_common(objects[2], family, address_family, compartment_id, protocol, true);

    // Now attach a 4th program to different compartment. It should not get invoked, and its verdict should not affect
    // the connection.
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);

    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Attach the connect program at BPF_CGROUP_INET4_CONNECT / BPF_CGROUP_INET6_CONNECT.
    bpf_program* connect_program = bpf_object__find_program_by_name(object, connect_program_name);
    SAFE_REQUIRE(connect_program != nullptr);
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id + 2, attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Not updating policy map for this program should mean that this program (if invoked) will block the connection.
    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, protocol, RESULT_ALLOW);
}

void
multi_attach_test_redirection(
    socket_family_t family, ADDRESS_FAMILY address_family, uint32_t compartment_id, uint16_t protocol)
{
    uint32_t verdict = compartment_id == UNSPECIFIED_COMPARTMENT_ID ? BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT
                                                                    : BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;

    // This test validates combination of redirection and other program verdicts.
    native_module_helper_t helpers[MULTIPLE_ATTACH_PROGRAM_COUNT];
    struct bpf_object* objects[MULTIPLE_ATTACH_PROGRAM_COUNT] = {nullptr};
    bpf_object_ptr object_ptrs[MULTIPLE_ATTACH_PROGRAM_COUNT];
    uint16_t proxy_port = SOCKET_TEST_PORT;
    uint16_t destination_port = proxy_port - 1;
    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load 3 programs.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        helpers[i].initialize("cgroup_sock_addr2", _is_main_thread);
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    // Attach all the 3 programs to the same hook (i.e. same attach parameters).
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);
    }

    // Lambda function to update the policy map entry, and validate the connection.
    auto validate_program_redirection = [&](uint32_t program_index) {
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            // Configure ith program to redirect the connection. Configure all other programs to "allow" the connection.
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[i], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            if (i != program_index) {
                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(destination_port), htons(destination_port), protocol, verdict);

                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, verdict);
            } else {
                _update_map_entry_multi_attach(
                    map_fd, address_family, htons(destination_port), htons(proxy_port), protocol, verdict);
            }
        }

        // Validate that the connection is successfully redirected.
        validate_connection_multi_attach(family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

        if (program_index > 0) {
            // If this is not the first program, configure the preceding program to block the connection.
            // That should result in the connection being blocked.
            bpf_map* policy_map = bpf_object__find_map_by_name(objects[program_index - 1], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);
            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);

            // Validate that the connection is blocked.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_DROP);

            // Now detach the preceding program, and validate that the connection is allowed.
            bpf_program* connect_program =
                bpf_object__find_program_by_name(objects[program_index - 1], connect_program_name);
            SAFE_REQUIRE(connect_program != nullptr);

            int result = bpf_prog_detach2(
                bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type);
            SAFE_REQUIRE(result == 0);

            // The connection should now be allowed.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Revert the policy to allow the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, verdict);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, verdict);
        }

        // Reset the whole state by detaching and re-attaching all the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], connect_program_name);
            SAFE_REQUIRE(program != nullptr);
            bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, attach_type);
        }

        // Re-attach the programs in-order.
        for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
            bpf_program* program = bpf_object__find_program_by_name(objects[i], connect_program_name);
            SAFE_REQUIRE(program != nullptr);
            int result = bpf_prog_attach(
                bpf_program__fd(const_cast<const bpf_program*>(program)), compartment_id, attach_type, 0);
            SAFE_REQUIRE(result == 0);
        }

        // Validate that the connection is again allowed.
        validate_connection_multi_attach(family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

        if (program_index < MULTIPLE_ATTACH_PROGRAM_COUNT - 1) {
            // If this is not the last program, configure the following program to block the connection.
            // That should result in the connection still be redirected.

            bpf_map* policy_map = bpf_object__find_map_by_name(objects[program_index + 1], "policy_map");
            SAFE_REQUIRE(policy_map != nullptr);

            fd_t map_fd = bpf_map__fd(policy_map);
            SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

            // Delete the map entry to block the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);

            // Validate that the connection is still redirected.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Next configure the last program to redirect the connection to proxy_port + 1.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port + 1), protocol, verdict);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(proxy_port + 1), protocol, verdict);

            // Validate that the connection is not redirected to proxy_port + 1. This is because the connection is
            // already redirected by the previous program.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);

            // Revert the policy to allow the connection.
            _update_map_entry_multi_attach(
                map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, verdict);

            _update_map_entry_multi_attach(
                map_fd, address_family, htons(destination_port), htons(destination_port), protocol, verdict);

            // Validate that the connection is allowed.
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);
        }
    };

    // For each program, detach and re-attach it, and validate the connection.
    for (uint32_t i = 0; i < MULTIPLE_ATTACH_PROGRAM_COUNT; i++) {
        validate_program_redirection(i);
    }
}

TEST_CASE("multi_attach_test_TCP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    multi_attach_test(compartment_id, socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_TCP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    multi_attach_test(compartment_id, socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_UDP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    multi_attach_test(compartment_id, socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_UDP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test(compartment_id, socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    multi_attach_test(compartment_id, socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_wildcard_TCP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_wildcard_TCP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_wildcard_UDP_IPv4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_wildcard_UDP_IPv6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    multi_attach_test(UNSPECIFIED_COMPARTMENT_ID, socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

typedef enum _program_action
{
    ACTION_ALLOW,
    ACTION_REDIRECT,
    ACTION_BLOCK,
    ACTION_MAX,
} program_action_t;

void
multi_attach_configure_map(
    bpf_object* object,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    uint16_t proxy_port,
    uint16_t protocol,
    program_action_t action)
{
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);
    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    if (action == ACTION_ALLOW) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

        _update_map_entry_multi_attach(map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, true);
    } else if (action == ACTION_REDIRECT) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(proxy_port), protocol, true);
    } else if (action == ACTION_BLOCK) {
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

        _update_map_entry_multi_attach(map_fd, address_family, htons(proxy_port), htons(proxy_port), protocol, false);
    } else {
        SAFE_REQUIRE(false);
    }
}

static program_action_t
_multi_attach_get_combined_verdict(program_action_t* actions, uint32_t count)
{
    SAFE_REQUIRE(count % 2 == 0);

    for (uint32_t i = 0; i < count; i++) {
        if (actions[i] == ACTION_BLOCK) {
            return ACTION_BLOCK;
        } else if (actions[i] == ACTION_REDIRECT) {
            return ACTION_REDIRECT;
        }
    }
    return ACTION_ALLOW;
}

void
test_multi_attach_combined(socket_family_t family, ADDRESS_FAMILY address_family, uint16_t protocol)
{
    // This test case loads and attaches program_count_per_hook * 2 programs:
    // program_count_per_hook programs with specific compartment id, and
    // program_count_per_hook programs with wildcard compartment id.
    // Then the test case iterates over all the possible combinations of program actions (allow, redirect, block) for
    // each program, and validates the connection based on the expected result.

    constexpr uint32_t program_count_per_hook = 2;
    native_module_helper_t helpers[program_count_per_hook * 2];
    struct bpf_object* objects[program_count_per_hook * 2] = {nullptr};
    bpf_object_ptr object_ptrs[program_count_per_hook * 2];
    program_action_t actions[program_count_per_hook * 2] = {ACTION_ALLOW};
    uint16_t proxy_port = SOCKET_TEST_PORT;
    uint16_t destination_port = proxy_port - 1;
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the programs.
    for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
        helpers[i].initialize("cgroup_sock_addr2", _is_main_thread);
        objects[i] = bpf_object__open(helpers[i].get_file_name().c_str());
        SAFE_REQUIRE(objects[i] != nullptr);
        object_ptrs[i] = bpf_object_ptr(objects[i]);
        SAFE_REQUIRE(bpf_object__load(objects[i]) == 0);
    }

    const char* connect_program_name = (address_family == AF_INET) ? "connect_redirect4" : "connect_redirect6";

    // Attach all the programs.
    for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
        bpf_program* connect_program = bpf_object__find_program_by_name(objects[i], connect_program_name);
        SAFE_REQUIRE(connect_program != nullptr);
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)),
            i < program_count_per_hook ? 1 : UNSPECIFIED_COMPARTMENT_ID,
            attach_type,
            0);
        SAFE_REQUIRE(result == 0);
    }

    // This loop will iterate over all the possible combinations of program actions for each program.
    while (true) {
        // Configure program actions.
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            multi_attach_configure_map(objects[i], address_family, destination_port, proxy_port, protocol, actions[i]);
        }

        program_action_t expected_action = _multi_attach_get_combined_verdict(actions, program_count_per_hook * 2);

        // Validate the connection based on the expected action.
        switch (expected_action) {
        case ACTION_ALLOW:
            validate_connection_multi_attach(
                family, address_family, destination_port, destination_port, protocol, RESULT_ALLOW);
            break;
        case ACTION_REDIRECT:
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_ALLOW);
            break;
        case ACTION_BLOCK:
            validate_connection_multi_attach(
                family, address_family, proxy_port, destination_port, protocol, RESULT_DROP);
            break;
        default:
            SAFE_REQUIRE(false);
        }

        // Increment the program actions.
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            actions[i] = static_cast<program_action_t>(actions[i] + 1);
            if (actions[i] == ACTION_MAX) {
                actions[i] = ACTION_ALLOW;
            } else {
                break;
            }
        }

        // Print the program actions.
        printf("Program actions: ");
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            printf("%d ", actions[i]);
        }
        printf("\n");

        // Break if all the program actions are ACTION_BLOCK.
        bool should_break = true;
        for (uint32_t i = 0; i < program_count_per_hook * 2; i++) {
            if (actions[i] != ACTION_BLOCK) {
                should_break = false;
                break;
            }
        }

        if (should_break) {
            break;
        }
    }
}

TEST_CASE("multi_attach_test_combined_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET, IPPROTO_TCP);
    test_multi_attach_combined(socket_family_t::IPv4, AF_INET, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_combined_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET, IPPROTO_UDP);
    test_multi_attach_combined(socket_family_t::IPv4, AF_INET, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_combined_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET6, IPPROTO_TCP);
    test_multi_attach_combined(socket_family_t::IPv6, AF_INET6, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_combined_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    test_multi_attach_combined(socket_family_t::Dual, AF_INET6, IPPROTO_UDP);
    test_multi_attach_combined(socket_family_t::IPv6, AF_INET6, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, compartment_id, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, compartment_id, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, compartment_id, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, compartment_id, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, compartment_id, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, compartment_id, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    uint32_t compartment_id = 1;
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, compartment_id, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, compartment_id, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_TCP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_TCP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_TCP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_UDP_IPV4", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv4, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_redirection_wildcard_UDP_IPV6", "[sock_addr_tests][multi_attach_tests]")
{
    multi_attach_test_redirection(socket_family_t::IPv6, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
    multi_attach_test_redirection(socket_family_t::Dual, AF_INET6, UNSPECIFIED_COMPARTMENT_ID, IPPROTO_UDP);
}

TEST_CASE("multi_attach_test_invocation_order", "[sock_addr_tests][multi_attach_tests]")
{
    // This test case validates that a program attached with specific compartment id is always invoked before a
    // program attached with wildcard compartment id, irrespective of the order of attachment.

    int result = 0;
    native_module_helper_t native_helpers_specific;
    native_module_helper_t native_helpers_wildcard;
    native_helpers_specific.initialize("cgroup_sock_addr2", _is_main_thread);
    native_helpers_wildcard.initialize("cgroup_sock_addr2", _is_main_thread);
    socket_family_t family = socket_family_t::Dual;
    ADDRESS_FAMILY address_family = AF_INET;
    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    struct bpf_object* object_specific = bpf_object__open(native_helpers_specific.get_file_name().c_str());
    SAFE_REQUIRE(object_specific != nullptr);
    bpf_object_ptr object_specific_ptr(object_specific);

    struct bpf_object* object_wildcard = bpf_object__open(native_helpers_wildcard.get_file_name().c_str());
    SAFE_REQUIRE(object_wildcard != nullptr);
    bpf_object_ptr object_wildcard_ptr(object_wildcard);

    // Load the programs.
    SAFE_REQUIRE(bpf_object__load(object_specific) == 0);
    SAFE_REQUIRE(bpf_object__load(object_wildcard) == 0);

    bpf_program* connect_program_specific = bpf_object__find_program_by_name(object_specific, "connect_redirect4");
    SAFE_REQUIRE(connect_program_specific != nullptr);

    bpf_program* connect_program_wildcard = bpf_object__find_program_by_name(object_wildcard, "connect_redirect4");
    SAFE_REQUIRE(connect_program_wildcard != nullptr);

    // Attach the program with specific compartment id first.
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type, 0);
    SAFE_REQUIRE(result == 0);

    // Attach the program with wildcard compartment id next.
    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program_wildcard)),
        UNSPECIFIED_COMPARTMENT_ID,
        attach_type,
        0);
    SAFE_REQUIRE(result == 0);

    // First configure both the programs to allow the connection.
    bpf_map* policy_map_specific = bpf_object__find_map_by_name(object_specific, "policy_map");
    SAFE_REQUIRE(policy_map_specific != nullptr);

    fd_t map_fd_specific = bpf_map__fd(policy_map_specific);
    SAFE_REQUIRE(map_fd_specific != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    bpf_map* policy_map_wildcard = bpf_object__find_map_by_name(object_wildcard, "policy_map");
    SAFE_REQUIRE(policy_map_wildcard != nullptr);

    fd_t map_fd_wildcard = bpf_map__fd(policy_map_wildcard);
    SAFE_REQUIRE(map_fd_wildcard != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the program with specific compartment id to block the connection.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // The connection should be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Configure the program with wildcard compartment id to use hard permit.
    uint32_t verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, verdict);

    // The connection should still be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, verdict);

    // The connection should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the program with wildcard compartment id to block the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // The connection should be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Configure the program with specific compartment id to use hard permit.
    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_HARD;
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, verdict);

    // The connection should still be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_DROP);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, verdict);

    // The connection should be allowed.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, SOCKET_TEST_PORT, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure the specific program to redirect the connection.
    uint16_t destination_port = SOCKET_TEST_PORT - 1;
    // uint16_t proxy_port = destination_port + 1;

    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is redirected to the final port.
    // The order of attach and invocation should be: specific --> wildcard.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure blocking rule for wildcard program.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, false);

    // Validate that the connection is still redirected to the final port.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Revert the policy to allow the connection.
    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(SOCKET_TEST_PORT), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Now detach the program with specific compartment id.
    result =
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type);

    // The connection should now be blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_DROP);

    // Re-attach the program with specific compartment id.
    result =
        bpf_prog_attach(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type, 0);

    // The connection should be allowed. This validates that the program with specific compartment id is always
    // invoked before the program with wildcard compartment id.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Now configure allow rule for specific program and redirect rule for wildcard program.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, true);

    _update_map_entry_multi_attach(
        map_fd_wildcard, address_family, htons(destination_port), htons(SOCKET_TEST_PORT), IPPROTO_TCP, true);

    // Validate that the connection is redirected to the final port.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);

    // Block the connection for specific program.
    _update_map_entry_multi_attach(
        map_fd_specific, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, false);

    // Validate that the connection is now blocked.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_DROP);

    // Detach the program with specific compartment id.
    result =
        bpf_prog_detach2(bpf_program__fd(const_cast<const bpf_program*>(connect_program_specific)), 1, attach_type);
    SAFE_REQUIRE(result == 0);

    // Since the specific program is now detached, the connection should be correctly redirected by wildcard program.
    validate_connection_multi_attach(
        family, address_family, SOCKET_TEST_PORT, destination_port, IPPROTO_TCP, RESULT_ALLOW);
}

/**
 * @brief This function sends messages to the receiver port in a loop using UDP socket.
 *
 * @param token Stop token to stop the thread.
 * @param address_family Address family to use.
 * @param receiver_port Port to send the message to.
 */
void
thread_function_invoke_connection(std::stop_token token, ADDRESS_FAMILY address_family, uint16_t receiver_port)
{
    uint32_t count = 0;

    while (!token.stop_requested()) {
        datagram_client_socket_t sender_socket(SOCK_DGRAM, IPPROTO_UDP, 0);

        // Send loopback message to test port.
        const char* message = CLIENT_MESSAGE;
        sockaddr_storage destination_address{};
        if (address_family == AF_INET) {
            IN6ADDR_SETV4MAPPED((PSOCKADDR_IN6)&destination_address, &in4addr_loopback, scopeid_unspecified, 0);
        } else {
            IN6ADDR_SETLOOPBACK((PSOCKADDR_IN6)&destination_address);
        }

        sender_socket.send_message_to_remote_host(message, destination_address, receiver_port);

        count++;
    }

    std::cout << "Thread (invoke_connection)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
thread_function_attach_detach(std::stop_token token, uint32_t compartment_id, uint16_t destination_port)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);
    uint32_t count = 0;
    ADDRESS_FAMILY address_family = AF_INET;

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the program.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Configure policy map to allow the connection (TCP and UDP).
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), IPPROTO_TCP, true);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), IPPROTO_UDP, true);

    while (!token.stop_requested()) {
        // Attach and detach the program in a loop.
        int result = bpf_prog_attach(
            bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);
        SAFE_REQUIRE(result == 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        result = bpf_prog_detach2(bpf_program__fd(connect_program), compartment_id, attach_type);
        SAFE_REQUIRE(result == 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        count++;
    }

    std::cout << "Thread (attach_detach)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
thread_function_allow_block_connection(
    std::stop_token token,
    ADDRESS_FAMILY address_family,
    uint16_t protocol,
    uint16_t destination_port,
    uint32_t compartment_id)
{
    native_module_helper_t helper;
    helper.initialize("cgroup_sock_addr2", _is_main_thread);
    struct bpf_object* object = bpf_object__open(helper.get_file_name().c_str());
    SAFE_REQUIRE(object != nullptr);
    bpf_object_ptr object_ptr(object);
    uint32_t count = 0;
    socket_family_t family = socket_family_t::Dual;

    bpf_program* connect_program = bpf_object__find_program_by_name(object, "connect_redirect4");
    SAFE_REQUIRE(connect_program != nullptr);

    bpf_attach_type_t attach_type = (address_family == AF_INET) ? BPF_CGROUP_INET4_CONNECT : BPF_CGROUP_INET6_CONNECT;

    // Load the program.
    SAFE_REQUIRE(bpf_object__load(object) == 0);

    // Attach the program at BPF_CGROUP_INET4_CONNECT / BPF_CGROUP_INET6_CONNECT.
    int result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect_program)), compartment_id, attach_type, 0);

    SAFE_REQUIRE(result == 0);

    // Configure policy map to allow the connection.
    bpf_map* policy_map = bpf_object__find_map_by_name(object, "policy_map");
    SAFE_REQUIRE(policy_map != nullptr);

    fd_t map_fd = bpf_map__fd(policy_map);
    SAFE_REQUIRE(map_fd != ebpf_fd_invalid);

    // Since the default policy is to block the connection, update the policy map to allow the connection for the
    // "other" protocol. This will ensure this program does not interfere with the connections for the second thread
    // that is also running in parallel.
    _update_map_entry_multi_attach(
        map_fd,
        address_family,
        htons(destination_port),
        htons(destination_port),
        (uint16_t)(protocol == IPPROTO_TCP ? IPPROTO_UDP : IPPROTO_TCP),
        true);

    _update_map_entry_multi_attach(
        map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

    while (!token.stop_requested()) {
        // Block the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, false);

        // The connection should be blocked. Due to race, it can sometimes be allowed, so we don't care about the
        // result.
        validate_connection_multi_attach(
            family, address_family, destination_port, destination_port, protocol, RESULT_DONT_CARE);

        // Allow the connection.
        _update_map_entry_multi_attach(
            map_fd, address_family, htons(destination_port), htons(destination_port), protocol, true);

        // The connection should be allowed. Due to race, it can sometimes be blocked, so we don't care about the
        // result.
        validate_connection_multi_attach(
            family, address_family, destination_port, destination_port, protocol, RESULT_DONT_CARE);

        count++;
    }

    std::cout << "Thread (allow_block)" << std::this_thread::get_id() << " executed " << count << " times."
              << std::endl;
}

void
multi_attach_test_thread_function1(
    std::stop_token token,
    uint32_t index,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    std::atomic<bool>& failed)
{
    // Get the mode.
    uint32_t mode = index % 7;
    uint32_t default_compartment = 1;
    uint32_t unspecified_compartment = 0;

    try {
        switch (mode) {
        case 0:
            __fallthrough;
            // break;
        case 1:
            thread_function_invoke_connection(token, address_family, destination_port);
            break;
        case 2:
            thread_function_attach_detach(token, unspecified_compartment, destination_port);
            break;
        case 3:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 4:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 5:
            thread_function_allow_block_connection(
                token, address_family, IPPROTO_TCP, destination_port, default_compartment);
            break;
        case 6:
            thread_function_allow_block_connection(
                token, address_family, IPPROTO_UDP, destination_port, default_compartment);
            break;
        }
    } catch (const test_failure& e) {
        std::cerr << "Thread " << std::this_thread::get_id() << " failed: " << e.message << std::endl;
        failed = true;
    }
}

TEST_CASE("multi_attach_concurrency_test1", "[multi_attach_tests][concurrent_tests]")
{
    // This test case validates that multiple threads can attach / detach programs concurrently, and the connection
    // verdict is as expected. The test case will have the following threads:
    //
    // Thread 0,1: Invokes connections in a loop.
    // Thread 2,3,4: Attach a program, sleep for few ms, detach the program.
    // Thread 5,6: Block and allow the connection in a loop, and invoke the connection to validate.

    uint16_t destination_port = SOCKET_TEST_PORT;
    std::vector<std::jthread> threads;
    uint32_t thread_count = 7;
    uint32_t thread_run_time = 60;
    std::atomic<bool> failed;

    for (uint32_t i = 0; i < thread_count; i++) {
        // Can only pass variables by value, not by references, hence the need for the shared_ptr<bool>.
        threads.emplace_back(
            multi_attach_test_thread_function1, i, (ADDRESS_FAMILY)AF_INET, destination_port, std::ref(failed));
    }

    std::this_thread::sleep_for(std::chrono::seconds(thread_run_time));

    for (auto& thread : threads) {
        thread.request_stop();
    }

    for (auto& thread : threads) {
        thread.join();
    }

    SAFE_REQUIRE(!failed);
}

void
multi_attach_test_thread_function2(
    std::stop_token token,
    uint32_t index,
    ADDRESS_FAMILY address_family,
    uint16_t destination_port,
    std::atomic<bool>& failed)
{
    // Get the mode.
    uint32_t mode = index % 7;
    uint32_t default_compartment = 1;
    uint32_t unspecified_compartment = 0;

    try {
        switch (mode) {
        case 0:
            __fallthrough;
        case 1:
            thread_function_invoke_connection(token, address_family, destination_port);
            break;
        case 2:
            thread_function_attach_detach(token, default_compartment, destination_port);
            break;
        case 3:
            thread_function_attach_detach(token, unspecified_compartment, destination_port);
            break;
        }
    } catch (const test_failure& e) {
        std::cerr << "Thread " << std::this_thread::get_id() << " failed: " << e.message << std::endl;
        failed = true;
    }
}

TEST_CASE("multi_attach_concurrency_test2", "[multi_attach_tests][concurrent_tests]")
{
    // This test case stresses the code path where 2 program -- one of type wildcard and other of specific attach
    // types are attaching and detaching in parallel, and a third thread invokes the hook by sending packets.
    //
    // Thread 0,1: Invokes connections in a loop.
    // Thread 2: Attach / detach program with wildcard.
    // Thread 3: Attach / detach program with specific compartment id.

    uint16_t destination_port = SOCKET_TEST_PORT;
    std::vector<std::jthread> threads;
    uint32_t thread_count = 4;
    uint32_t thread_run_time = 60;
    std::atomic<bool> failed = false;

    for (uint32_t i = 0; i < thread_count; i++) {
        // Can only pass variables by value, not by references, hence the need for the shared_ptr<bool>.
        threads.emplace_back(
            multi_attach_test_thread_function2, i, (ADDRESS_FAMILY)AF_INET, destination_port, std::ref(failed));
    }

    std::this_thread::sleep_for(std::chrono::seconds(thread_run_time));

    for (auto& thread : threads) {
        thread.request_stop();
    }

    for (auto& thread : threads) {
        thread.join();
    }

    SAFE_REQUIRE(!failed);
}

int
main(int argc, char* argv[])
{
    WSAData data;

    _is_main_thread = true;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    int result = Catch::Session().run(argc, argv);

    WSACleanup();

    return result;
}
