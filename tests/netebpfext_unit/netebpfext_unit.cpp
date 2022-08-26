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

    // Make sure they match
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
} test_client_context_t;

NTSTATUS
attach_netebpf_extension(
    _In_ HANDLE nmr_binding_handle,
    _In_ PVOID client_context,
    _In_ PNPI_REGISTRATION_INSTANCE provider_registration_instance)
{
    void* provider_binding_context;
    const void* provider_dispatch_table;
    ebpf_extension_dispatch_table_t client_dispatch_table = {};
    auto provider_characteristics =
        (const ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    auto provider_data = (const ebpf_attach_provider_data_t*)provider_characteristics->data;
    auto test_client_context = (const test_client_context_t*)client_context;
    if (provider_data->bpf_attach_type == test_client_context->desired_attach_type) {
        REQUIRE(
            NmrClientAttachProvider(
                nmr_binding_handle,
                nullptr, // client_binding_context,
                &client_dispatch_table,
                &provider_binding_context,
                &provider_dispatch_table) == STATUS_SUCCESS);
    }
    return STATUS_SUCCESS;
}

TEST_CASE("start_stop_test2", "[netebpfext]")
{
    netebpf_ext_helper_t helper;

    ebpf_extension_data_t program_type_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_XDP);
    REQUIRE(program_type_data.size == sizeof(ebpf_program_data_t));
    auto program_data = (ebpf_program_data_t*)program_type_data.data;
    REQUIRE(program_data->program_info->program_type_descriptor.bpf_prog_type == BPF_PROG_TYPE_XDP);

    // Find pointer to _net_ebpf_extension_program_info_provider_attach_client
    NPI_CLIENT_CHARACTERISTICS client_characteristics = {};
    client_characteristics.ClientRegistrationInstance.NpiId = &EBPF_HOOK_EXTENSION_IID;
    NPI_MODULEID module_id = {};
    client_characteristics.ClientRegistrationInstance.ModuleId = &module_id;
    NET_IFINDEX if_index = 0;
    ebpf_extension_data_t npi_specific_characteristics = {.size = sizeof(if_index), .data = &if_index};
    client_characteristics.ClientRegistrationInstance.NpiSpecificCharacteristics = &npi_specific_characteristics;
    client_characteristics.ClientAttachProvider = attach_netebpf_extension;
    test_client_context_t client_context = {.desired_attach_type = BPF_XDP};
    HANDLE nmr_client_handle;
    REQUIRE(NmrRegisterClient(&client_characteristics, &client_context, &nmr_client_handle) == STATUS_SUCCESS);

    FWP_ACTION_TYPE result = helper.classify_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE);
    REQUIRE(result == FWP_ACTION_PERMIT);
}
