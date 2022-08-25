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

TEST_CASE("start_stop_test2", "[netebpfext]")
{
    netebpf_ext_helper_t helper;

    ebpf_extension_data_t program_type_data = helper.get_program_info_provider_data(EBPF_PROGRAM_TYPE_XDP);
    REQUIRE(program_type_data.size == sizeof(ebpf_program_data_t));
    auto program_data = (ebpf_program_data_t*)program_type_data.data;
    REQUIRE(program_data->program_info->program_type_descriptor.bpf_prog_type == BPF_PROG_TYPE_XDP);

    // Register a logical eBPF program.
    // TODO

    FWP_ACTION_TYPE result = FwThunkClassifyPacket(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE);
    REQUIRE(result == FWP_ACTION_PERMIT);
}
