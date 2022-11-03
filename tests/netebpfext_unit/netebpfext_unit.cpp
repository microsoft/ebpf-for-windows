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
    _In_ void* client_context,
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
netebpf_unit_detach_extension(_In_ void* client_binding_context)
{
    auto test_client_context = (test_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(test_client_context);

    // Return STATUS_SUCCESS if all callbacks we implement are done, or return
    // STATUS_PENDING if we will call NmrProviderDetachClientComplete() when done.
    return STATUS_SUCCESS;
}

void
netebpfext_unit_cleanup_binding_context(_In_ void* client_binding_context)
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
    client_characteristics.ClientCleanupBindingContext = netebpfext_unit_cleanup_binding_context;
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
