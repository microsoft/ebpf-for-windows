// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "ebpf_fault_injection.h"
#include "netebpf_ext_helper.h"
#include "passed_test_log.h"
#include "watchdog.h"

#include <map>

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(_passed_test_log)

#define CONCURRENT_THREAD_RUN_TIME_IN_SECONDS 10

typedef enum _sock_addr_test_type
{
    SOCK_ADDR_TEST_TYPE_CONNECT,
    SOCK_ADDR_TEST_TYPE_RECV_ACCEPT
} sock_addr_test_type_t;

typedef enum _sock_addr_test_action
{
    SOCK_ADDR_TEST_ACTION_PERMIT,
    SOCK_ADDR_TEST_ACTION_BLOCK,
    SOCK_ADDR_TEST_ACTION_REDIRECT,
    SOCK_ADDR_TEST_ACTION_FAILURE,
    SOCK_ADDR_TEST_ACTION_ROUND_ROBIN
} sock_addr_test_action_t;

typedef enum _xdp_test_action
{
    XDP_TEST_ACTION_PASS,   ///< Allow the packet to pass.
    XDP_TEST_ACTION_DROP,   ///< Drop the packet.
    XDP_TEST_ACTION_TX,     ///< Bounce the received packet back out the same NIC it arrived on.
    XDP_TEST_ACTION_FAILURE ///< Failed to invoke the eBPF program.
} xdp_test_action_t;

TEST_CASE("query program info", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    std::vector<GUID> expected_guids = {
        EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, EBPF_PROGRAM_TYPE_SOCK_OPS, EBPF_PROGRAM_TYPE_XDP, EBPF_PROGRAM_TYPE_BIND};
    std::vector<std::string> expected_program_names = {"sock_addr", "sockops", "bind", "xdp"};

    auto guid_less = [](const GUID& lhs, const GUID& rhs) { return memcmp(&lhs, &rhs, sizeof(lhs)) < 0; };

    // Get list of program info providers (attach points and helper functions).
    std::vector<GUID> guids = helper.program_info_provider_guids();

    // Make sure they match.
    std::sort(expected_guids.begin(), expected_guids.end(), guid_less);
    std::sort(guids.begin(), guids.end(), guid_less);
    REQUIRE(guids == expected_guids);

    // Get the names of the program types.
    std::vector<std::string> program_names;
    for (const auto& guid : guids) {
        ebpf_extension_data_t extension_data = helper.get_program_info_provider_data(guid);
        auto& program_data = *reinterpret_cast<ebpf_program_data_t*>(extension_data.data);
        program_names.push_back(program_data.program_info->program_type_descriptor.name);
    }

    // Make sure they match.
    std::sort(expected_program_names.begin(), expected_program_names.end());
    std::sort(program_names.begin(), program_names.end());
    REQUIRE(expected_program_names == program_names);
}

#pragma region xdp

typedef struct _test_xdp_client_context
{
    netebpfext_helper_base_client_context_t base;
    void* provider_binding_context;
    xdp_test_action_t xdp_action;
} test_xdp_client_context_t;

// This callback occurs when netebpfext gets a packet and submits it to our dummy
// eBPF program to handle.
_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_xdp_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    ebpf_result_t return_result = EBPF_SUCCESS;
    auto client_context = (test_xdp_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);

    switch (client_context->xdp_action) {
    case XDP_TEST_ACTION_PASS:
        *result = XDP_PASS;
        break;
    case XDP_TEST_ACTION_DROP:
        *result = XDP_DROP;
        break;
    case XDP_TEST_ACTION_TX:
        *result = XDP_TX;
        break;
    case XDP_TEST_ACTION_FAILURE:
        return_result = EBPF_FAILED;
        break;
    default:
        *result = XDP_DROP;
        break;
    }

    return return_result;
}

TEST_CASE("classify_packet", "[netebpfext]")
{
    NET_IFINDEX if_index = 0;
    ebpf_extension_data_t npi_specific_characteristics = {.size = sizeof(if_index), .data = &if_index};
    test_xdp_client_context_t client_context = {};
    client_context.base.desired_attach_type = BPF_XDP;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_xdp_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    // Classify an inbound packet that should pass.
    client_context.xdp_action = XDP_TEST_ACTION_PASS;
    FWP_ACTION_TYPE result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify an inbound packet that should be hairpinned.
    client_context.xdp_action = XDP_TEST_ACTION_TX;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Classify an inbound packet that should be dropped.
    client_context.xdp_action = XDP_TEST_ACTION_DROP;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Classify an inbound packet when eBPF program invocation failed.
    client_context.xdp_action = XDP_TEST_ACTION_FAILURE;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);
}

TEST_CASE("xdp_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto xdp_extension_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_XDP);
    auto xdp_program_data = (ebpf_program_data_t*)xdp_extension_data.data;

    std::vector<uint8_t> input_data(100);
    std::vector<uint8_t> output_data(100);
    size_t output_data_size = output_data.size();
    xdp_md_t input_context = {};
    size_t output_context_size = sizeof(xdp_md_t);
    xdp_md_t output_context = {};
    xdp_md_t* xdp_context;

    input_context.data_meta = 12345;
    input_context.ingress_ifindex = 67890;

    // Negative test:
    // Null data
    REQUIRE(
        xdp_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&xdp_context) ==
        EBPF_INVALID_ARGUMENT);

    // Positive test:
    // Null context
    REQUIRE(
        xdp_program_data->context_create(input_data.data(), input_data.size(), nullptr, 0, (void**)&xdp_context) ==
        EBPF_SUCCESS);

    xdp_program_data->context_destroy(xdp_context, nullptr, &output_data_size, nullptr, &output_context_size);

    REQUIRE(
        xdp_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&xdp_context) == 0);

    bpf_xdp_adjust_head_t adjust_head = reinterpret_cast<bpf_xdp_adjust_head_t>(
        xdp_program_data->program_type_specific_helper_function_addresses->helper_function_address[0]);

    // Modify the context.
    REQUIRE(adjust_head(xdp_context, 10) == 0);
    xdp_context->data_meta++;
    xdp_context->ingress_ifindex--;

    output_data_size = output_data.size();

    xdp_program_data->context_destroy(
        xdp_context, output_data.data(), &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 90);
    REQUIRE(output_context.data_meta == 12346);
    REQUIRE(output_context.ingress_ifindex == 67889);
}

#pragma endregion xdp
#pragma region bind

typedef struct test_bind_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    bind_action_t bind_action;
} test_bind_client_context_t;

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_bind_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_bind_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);
    *result = client_context->bind_action;
    return EBPF_SUCCESS;
}

TEST_CASE("bind_invoke", "[netebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_bind_client_context_t client_context = {};
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_bind_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Classify a bind that should be allowed.
    client_context.bind_action = BIND_PERMIT;
    FWP_ACTION_TYPE result = helper.test_bind_ipv4(&parameters); // TODO(issue #526): support IPv6.
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify a bind that should be redirected.
    client_context.bind_action = BIND_REDIRECT;
    result = helper.test_bind_ipv4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify a bind that should be blocked.
    client_context.bind_action = BIND_DENY;
    result = helper.test_bind_ipv4(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);
}

TEST_CASE("bind_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto bind_extension_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_BIND);
    auto bind_program_data = (ebpf_program_data_t*)bind_extension_data.data;

    std::vector<uint8_t> input_data(100);
    std::vector<uint8_t> output_data(100);
    size_t output_data_size = output_data.size();
    bind_md_t input_context = {
        .app_id_start = nullptr,
        .app_id_end = nullptr,
        .process_id = 12345,
        .socket_address = {0x1, 0x2, 0x3, 0x4},
        .socket_address_length = 4,
        .operation = BIND_OPERATION_BIND,
        .protocol = IPPROTO_TCP,
    };
    size_t output_context_size = sizeof(bind_md_t);
    bind_md_t output_context = {};
    bind_md_t* bind_context;

    // Positive test:
    // Null data
    REQUIRE(
        bind_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&bind_context) == EBPF_SUCCESS);

    bind_program_data->context_destroy(bind_context, nullptr, &output_data_size, nullptr, &output_context_size);

    // Negative test:
    // Null context
    REQUIRE(
        bind_program_data->context_create(input_data.data(), input_data.size(), nullptr, 0, (void**)&bind_context) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        bind_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&bind_context) == 0);

    // Modify the context.
    bind_context->process_id++;
    bind_context->socket_address[0] = 0x5;
    bind_context->socket_address[1] = 0x6;
    bind_context->socket_address[2] = 0x7;
    bind_context->socket_address[3] = 0x8;
    bind_context->socket_address_length = 8;
    bind_context->operation = BIND_OPERATION_UNBIND;
    bind_context->protocol = IPPROTO_UDP;

    output_context_size = sizeof(bind_md_t);
    output_data_size = output_data.size();

    bind_program_data->context_destroy(
        bind_context, output_data.data(), &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == input_data.size());
    REQUIRE(output_context_size == sizeof(bind_md_t));
    REQUIRE(output_context.app_id_start == nullptr);
    REQUIRE(output_context.app_id_end == nullptr);
    REQUIRE(output_context.process_id == 12346);
    REQUIRE(output_context.socket_address[0] == 0x5);
    REQUIRE(output_context.socket_address[1] == 0x6);
    REQUIRE(output_context.socket_address[2] == 0x7);
    REQUIRE(output_context.socket_address[3] == 0x8);
    REQUIRE(output_context.socket_address_length == 8);
    REQUIRE(output_context.operation == BIND_OPERATION_UNBIND);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
}

#pragma endregion bind
#pragma region cgroup_sock_addr

typedef struct test_sock_addr_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    int sock_addr_action;
    bool validate_sock_addr_entries = true;
} test_sock_addr_client_context_t;

static inline sock_addr_test_action_t
_get_sock_addr_action(uint16_t destination_port)
{
    return (sock_addr_test_action_t)(destination_port % SOCK_ADDR_TEST_ACTION_ROUND_ROBIN);
}

static inline FWP_ACTION_TYPE
_get_fwp_sock_addr_action(uint16_t destination_port)
{
    sock_addr_test_action_t action = _get_sock_addr_action(destination_port);
    if (action == SOCK_ADDR_TEST_ACTION_PERMIT || action == SOCK_ADDR_TEST_ACTION_REDIRECT) {
        return FWP_ACTION_PERMIT;
    }

    return FWP_ACTION_BLOCK;
}

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_sock_addr_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    ebpf_result_t return_result = EBPF_SUCCESS;
    auto client_context = (test_sock_addr_client_context_t*)client_binding_context;
    auto sock_addr_context = (bpf_sock_addr_t*)context;
    int action;

    // Verify context fields match what the netebpfext helper set.
    // Note that the helper sets the first four bytes of the address to the
    // same value regardless of whether it is IPv4 or IPv6, so we just look
    // at the first four bytes as if it were an IPv4 address.
    if (client_context->validate_sock_addr_entries) {
        REQUIRE((sock_addr_context->family == AF_INET || sock_addr_context->family == AF_INET6));
        REQUIRE(sock_addr_context->user_ip4 == htonl(0x01020304));
        REQUIRE(sock_addr_context->msg_src_ip4 == htonl(0x05060708));
        REQUIRE(sock_addr_context->protocol == IPPROTO_TCP);
        REQUIRE(sock_addr_context->user_port == htons(1234));
        REQUIRE(sock_addr_context->msg_src_port == htons(5678));
    }

    // If the action is round robin, decide the action based on the port number.
    if (client_context->sock_addr_action == SOCK_ADDR_TEST_ACTION_ROUND_ROBIN) {
        action = _get_sock_addr_action(sock_addr_context->user_port);
    } else {
        action = client_context->sock_addr_action;
    }

    switch (action) {
    case SOCK_ADDR_TEST_ACTION_PERMIT:
        *result = BPF_SOCK_ADDR_VERDICT_PROCEED;
        break;
    case SOCK_ADDR_TEST_ACTION_BLOCK:
        *result = BPF_SOCK_ADDR_VERDICT_REJECT;
        break;
    case SOCK_ADDR_TEST_ACTION_REDIRECT:
        sock_addr_context->user_port++;
        if (sock_addr_context->family == AF_INET) {
            sock_addr_context->user_ip4++;
        } else {
            auto first_octet = &sock_addr_context->user_ip6[0];
            (*first_octet)++;
        }
        *result = BPF_SOCK_ADDR_VERDICT_PROCEED;
        break;
    case SOCK_ADDR_TEST_ACTION_FAILURE:
        return_result = EBPF_FAILED;
        break;
    default:
        *result = BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    return return_result;
}

TEST_CASE("sock_addr_invoke", "[netebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_sock_addr_client_context_t client_context = {};
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Classify operations that should be allowed.
    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_PERMIT;
    client_context.validate_sock_addr_entries = true;

    FWP_ACTION_TYPE result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify operations that should be blocked.
    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_BLOCK;

    result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Classify operations for redirect.
    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_REDIRECT;

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Test eBPF program invocation failure.
    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_FAILURE;

    result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    // Test reauthorization flag.
    // Classify operations that should be allowed.
    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_PERMIT;
    client_context.validate_sock_addr_entries = true;

    parameters.reauthorization_flag = FWP_CONDITION_FLAG_IS_REAUTHORIZE;

    result = helper.test_cgroup_inet4_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_recv_accept(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet4_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_cgroup_inet6_connect(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);
}

void
sock_addr_thread_function(
    std::stop_token token,
    _In_ netebpf_ext_helper_t* helper,
    _In_ fwp_classify_parameters_t* parameters,
    sock_addr_test_type_t type,
    uint16_t start_port,
    uint16_t end_port)
{
    FWP_ACTION_TYPE result;
    uint16_t port_number;

    bool fault_injection_enabled = ebpf_fault_injection_is_enabled();

    if (start_port != end_port) {
        port_number = start_port - 1;
    } else {
        port_number = htons(parameters->destination_port);
    }

    while (!token.stop_requested()) {
        // If start_port and end_port are same, then the port number for each
        // invocation will remain the same.
        if (start_port != end_port) {
            port_number++;
            if (port_number > end_port) {
                port_number = start_port;
            }
            parameters->destination_port = htons(port_number);
        }

        switch (type) {
        case SOCK_ADDR_TEST_TYPE_RECV_ACCEPT:
            result = helper->test_cgroup_inet4_recv_accept(parameters);
            break;
        case SOCK_ADDR_TEST_TYPE_CONNECT:
        default:
            result = helper->test_cgroup_inet4_connect(parameters);
            break;
        }

        REQUIRE((result == _get_fwp_sock_addr_action(port_number) || fault_injection_enabled));
    }
}

// Invoke SOCK_ADDR_CONNECT concurrently with same classify parameters.
TEST_CASE("sock_addr_invoke_concurrent1", "[netebpfext_concurrent]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_sock_addr_client_context_t client_context = {};
    fwp_classify_parameters_t parameters = {};
    std::vector<std::jthread> threads;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);
    client_context.validate_sock_addr_entries = true;

    // Classify operations that should be allowed.
    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_PERMIT;

    uint32_t thread_count = 2 * ebpf_get_cpu_count();
    for (uint32_t i = 0; i < thread_count; i++) {
        threads.emplace_back(
            sock_addr_thread_function,
            &helper,
            &parameters,
            SOCK_ADDR_TEST_TYPE_CONNECT,
            parameters.destination_port,
            parameters.destination_port);
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(CONCURRENT_THREAD_RUN_TIME_IN_SECONDS));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }
}

// Invoke SOCK_ADDR_CONNECT concurrently with different classify parameters.
TEST_CASE("sock_addr_invoke_concurrent2", "[netebpfext_concurrent]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_sock_addr_client_context_t client_context = {};
    std::vector<std::jthread> threads;
    std::vector<fwp_classify_parameters_t> parameters;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_ROUND_ROBIN;
    client_context.validate_sock_addr_entries = false;

    uint32_t thread_count = 2 * ebpf_get_cpu_count();
    parameters.resize(thread_count);

    for (uint32_t i = 0; i < thread_count; i++) {
        netebpfext_initialize_fwp_classify_parameters(&parameters[i]);
        threads.emplace_back(
            sock_addr_thread_function,
            &helper,
            &parameters[i],
            SOCK_ADDR_TEST_TYPE_CONNECT,
            (uint16_t)(i * 1000),
            (uint16_t)(i * 1000 + 1000));
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(CONCURRENT_THREAD_RUN_TIME_IN_SECONDS));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }
}

// Invoke SOCK_ADDR_RECV_ACCEPT concurrently with different classify parameters.
TEST_CASE("sock_addr_invoke_concurrent3", "[netebpfext_concurrent]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_sock_addr_client_context_t client_context = {};
    std::vector<std::jthread> threads;
    std::vector<fwp_classify_parameters_t> parameters;

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_addr_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    client_context.sock_addr_action = SOCK_ADDR_TEST_ACTION_ROUND_ROBIN;
    client_context.validate_sock_addr_entries = false;

    uint32_t thread_count = 2 * ebpf_get_cpu_count();
    parameters.resize(thread_count);

    for (uint32_t i = 0; i < thread_count; i++) {
        netebpfext_initialize_fwp_classify_parameters(&parameters[i]);
        threads.emplace_back(
            sock_addr_thread_function,
            &helper,
            &parameters[i],
            SOCK_ADDR_TEST_TYPE_RECV_ACCEPT,
            (uint16_t)(i * 1000),
            (uint16_t)(i * 1000 + 1000));
    }

    // Wait for 10 seconds.
    std::this_thread::sleep_for(std::chrono::seconds(CONCURRENT_THREAD_RUN_TIME_IN_SECONDS));

    // Stop all threads.
    for (auto& thread : threads) {
        thread.request_stop();
    }

    // Wait for all threads to stop.
    for (auto& thread : threads) {
        thread.join();
    }
}

TEST_CASE("sock_addr_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto sock_addr_extension_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR);
    auto sock_addr_program_data = (ebpf_program_data_t*)sock_addr_extension_data.data;

    size_t output_data_size = 0;
    bpf_sock_addr_t input_context = {
        AF_INET,
        0x12345678,
        0x1234,
        0x90abcdef,
        0x5678,
        IPPROTO_TCP,
        0x12345678,
        0x1234567890abcdef,
    };
    size_t output_context_size = sizeof(bpf_sock_addr_t);
    bpf_sock_addr_t output_context = {};
    bpf_sock_addr_t* sock_addr_context;

    std::vector<uint8_t> input_data(100);

    // Negative test:
    // Data present
    REQUIRE(
        sock_addr_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&sock_addr_context) == EBPF_INVALID_ARGUMENT);

    // Negative test:
    // Context missing
    REQUIRE(
        sock_addr_program_data->context_create(nullptr, 0, nullptr, 0, (void**)&sock_addr_context) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        sock_addr_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&sock_addr_context) == 0);

    // Modify the context.
    sock_addr_context->family = AF_INET6;
    sock_addr_context->msg_src_ip4++;
    sock_addr_context->msg_src_port--;
    sock_addr_context->user_ip4++;
    sock_addr_context->user_port--;
    sock_addr_context->protocol = IPPROTO_UDP;
    sock_addr_context->compartment_id++;
    sock_addr_context->interface_luid--;

    sock_addr_program_data->context_destroy(
        sock_addr_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 0);
    REQUIRE(output_context_size == sizeof(bpf_sock_addr_t));
    REQUIRE(output_context.family == AF_INET6);
    REQUIRE(output_context.msg_src_ip4 == 0x12345679);
    REQUIRE(output_context.msg_src_port == 0x1233);
    REQUIRE(output_context.user_ip4 == 0x90abcdf0);
    REQUIRE(output_context.user_port == 0x5677);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
    REQUIRE(output_context.compartment_id == 0x12345679);
    REQUIRE(output_context.interface_luid == 0x1234567890abcdee);
}
#pragma endregion cgroup_sock_addr
#pragma region sock_ops

typedef struct test_sock_ops_client_context_t
{
    netebpfext_helper_base_client_context_t base;
    uint32_t sock_ops_action;
} test_sock_ops_client_context_t;

_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_sock_ops_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_sock_ops_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);
    *result = client_context->sock_ops_action;
    return EBPF_SUCCESS;
}

TEST_CASE("sock_ops_invoke", "[netebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_sock_ops_client_context_t client_context = {};
    fwp_classify_parameters_t parameters = {};

    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_sock_ops_program,
        (netebpfext_helper_base_client_context_t*)&client_context);

    netebpfext_initialize_fwp_classify_parameters(&parameters);

    // Do some operations that return success.
    client_context.sock_ops_action = 0;

    FWP_ACTION_TYPE result = helper.test_sock_ops_v4(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    result = helper.test_sock_ops_v6(&parameters);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Do some operations that return failure.
    client_context.sock_ops_action = -1;

    result = helper.test_sock_ops_v4(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);

    result = helper.test_sock_ops_v6(&parameters);
    REQUIRE(result == FWP_ACTION_BLOCK);
}

TEST_CASE("sock_ops_context", "[netebpfext]")
{
    netebpf_ext_helper_t helper;
    auto sock_ops_extension_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_SOCK_OPS);
    auto sock_ops_program_data = (ebpf_program_data_t*)sock_ops_extension_data.data;

    size_t output_data_size = 0;
    bpf_sock_ops_t input_context = {
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        AF_INET,
        0x12345678,
        0x1234,
        0x90abcdef,
        0x5678,
        IPPROTO_TCP,
        0x12345678,
        0x1234567890abcdef,
    };
    size_t output_context_size = sizeof(bpf_sock_ops_t);
    bpf_sock_ops_t output_context = {};
    bpf_sock_ops_t* sock_ops_context;

    std::vector<uint8_t> input_data(100);

    // Negative test:
    // Data present
    REQUIRE(
        sock_ops_program_data->context_create(
            input_data.data(),
            input_data.size(),
            (const uint8_t*)&input_context,
            sizeof(input_context),
            (void**)&sock_ops_context) == EBPF_INVALID_ARGUMENT);

    // Negative test:
    // Context missing
    REQUIRE(
        sock_ops_program_data->context_create(nullptr, 0, nullptr, 0, (void**)&sock_ops_context) ==
        EBPF_INVALID_ARGUMENT);

    REQUIRE(
        sock_ops_program_data->context_create(
            nullptr, 0, (const uint8_t*)&input_context, sizeof(input_context), (void**)&sock_ops_context) == 0);

    // Modify the context.
    sock_ops_context->op = BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
    sock_ops_context->family = AF_INET6;
    sock_ops_context->local_ip4++;
    sock_ops_context->local_port--;
    sock_ops_context->remote_ip4++;
    sock_ops_context->remote_port--;
    sock_ops_context->protocol = IPPROTO_UDP;
    sock_ops_context->compartment_id++;
    sock_ops_context->interface_luid--;

    sock_ops_program_data->context_destroy(
        sock_ops_context, nullptr, &output_data_size, (uint8_t*)&output_context, &output_context_size);

    REQUIRE(output_data_size == 0);
    REQUIRE(output_context_size == sizeof(bpf_sock_ops_t));
    REQUIRE(output_context.op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB);
    REQUIRE(output_context.family == AF_INET6);
    REQUIRE(output_context.local_ip4 == 0x12345679);
    REQUIRE(output_context.local_port == 0x1233);
    REQUIRE(output_context.remote_ip4 == 0x90abcdf0);
    REQUIRE(output_context.remote_port == 0x5677);
    REQUIRE(output_context.protocol == IPPROTO_UDP);
    REQUIRE(output_context.compartment_id == 0x12345679);
    REQUIRE(output_context.interface_luid == 0x1234567890abcdee);
}
#pragma endregion sock_ops
