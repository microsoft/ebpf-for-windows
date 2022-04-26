// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <iostream>

#include "ebpf_api.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"

#define SAMPLE_PATH ""
#define CILIUM_XDP_SECTIONS_SNAT 10
#define CILIUM_XDP_SECTIONS_DSR 12

void
verify_program(_In_ const char* file, uint32_t expected_section_count)
{
    struct bpf_object_open_opts opts = {0};
    bpf_program* program = nullptr;
    uint32_t section_count = 0;
    struct bpf_object* object = bpf_object__open_file(file, &opts);
    REQUIRE(object != nullptr);

    while (true) {
        program = bpf_program__next(program, object);
        if (program == nullptr) {
            break;
        }
        section_count++;
        const char* section_name = bpf_program__section_name(program);
        REQUIRE(section_name != nullptr);

#ifndef SKIP_VERIFICATION
        uint32_t result;
        ebpf_api_verifier_stats_t stats;
        const char* error_message = nullptr;
        const char* report = nullptr;
        REQUIRE(
            (result = ebpf_api_elf_verify_section_from_file(file, section_name, false, &report, &error_message, &stats),
             ebpf_free_string(error_message),
             error_message = nullptr,
             result == 0));
        REQUIRE(report != nullptr);
        ebpf_free_string(report);
#endif
    }

    REQUIRE(section_count == expected_section_count);
}

TEST_CASE("verify_snat_program", "[cilium][xdp]")
{
    verify_program(SAMPLE_PATH "bpf_xdp_snat.o", CILIUM_XDP_SECTIONS_SNAT);
}
TEST_CASE("verify_dsr_program", "[cilium][xdp]")
{
    verify_program(SAMPLE_PATH "bpf_xdp_dsr.o", CILIUM_XDP_SECTIONS_DSR);
}
