// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "netebpf_ext_helper.h"

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

typedef struct _test_client_context
{
    bpf_attach_type_t desired_attach_type;
    void* provider_binding_context;
    xdp_action_t xdp_action;
} test_client_context_t;

// This callback occurs when netebpfext gets a packet and submits it to our dummy
// eBPF program to handle.
_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(context);
    *result = client_context->xdp_action;
    return EBPF_SUCCESS;
}

// Netebpfext is ready for us to attach to it as if we were ebpfcore.
NTSTATUS
netebpf_unit_attach_extension(
    _In_ HANDLE nmr_binding_handle,
    _Inout_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    const void* provider_dispatch_table;
    ebpf_extension_dispatch_table_t client_dispatch_table = {.size = 1};
    client_dispatch_table.function[0] = (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_program;
    auto provider_characteristics =
        (const ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    auto provider_data = (const ebpf_attach_provider_data_t*)provider_characteristics->data;
    auto test_client_context = (test_client_context_t*)client_context;
    if (provider_data->bpf_attach_type != test_client_context->desired_attach_type) {
        return STATUS_ACCESS_DENIED;
    }

    return NmrClientAttachProvider(
        nmr_binding_handle,
        test_client_context, // Client binding context.
        &client_dispatch_table,
        &test_client_context->provider_binding_context,
        &provider_dispatch_table);
}

// Detach from netebpfext.
NTSTATUS
netebpf_unit_detach_extension(_Inout_ void* client_binding_context)
{
    auto test_client_context = (test_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(test_client_context);

    // Return STATUS_SUCCESS if all callbacks we implement are done, or return
    // STATUS_PENDING if we will call NmrProviderDetachClientComplete() when done.
    return STATUS_SUCCESS;
}

void
netebpfext_unit_cleanup_binding_context(_In_ const void* client_binding_context)
{
    auto test_client_context = (test_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(test_client_context);
}

TEST_CASE("classify_packet", "[netebpfext]")
{
    netebpf_ext_helper_t helper;

    // Register with NMR as if we were ebpfcore.sys.
    NPI_CLIENT_CHARACTERISTICS client_characteristics = {};
    client_characteristics.ClientRegistrationInstance.NpiId = &EBPF_HOOK_EXTENSION_IID;
    NPI_MODULEID module_id = {};
    client_characteristics.ClientRegistrationInstance.ModuleId = &module_id;
    NET_IFINDEX if_index = 0;
    ebpf_extension_data_t npi_specific_characteristics = {.size = sizeof(if_index), .data = &if_index};
    client_characteristics.ClientRegistrationInstance.NpiSpecificCharacteristics = &npi_specific_characteristics;
    client_characteristics.ClientAttachProvider = netebpf_unit_attach_extension;
    client_characteristics.ClientDetachProvider = netebpf_unit_detach_extension;
    client_characteristics.ClientCleanupBindingContext =
        (NPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN*)netebpfext_unit_cleanup_binding_context;
    test_client_context_t client_context = {.desired_attach_type = BPF_XDP};
    HANDLE nmr_client_handle;
    REQUIRE(NmrRegisterClient(&client_characteristics, &client_context, &nmr_client_handle) == STATUS_SUCCESS);

    // Verify we successfully attached to netebpfext.
    REQUIRE(client_context.provider_binding_context != nullptr);

    // Classify an inbound packet that should pass.
    client_context.xdp_action = XDP_PASS;
    FWP_ACTION_TYPE result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_PERMIT);

    // Classify an inbound packet that should be dropped.
    client_context.xdp_action = XDP_DROP;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    REQUIRE(result == FWP_ACTION_BLOCK);

    NmrDeregisterClient(nmr_client_handle);
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