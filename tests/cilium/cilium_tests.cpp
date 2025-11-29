// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_program_types.h"
#include "ebpf_store_helper.h"
#include "ebpf_shared_framework.h"

#include <iostream>
#include <stdexcept>

#define SAMPLE_PATH ""
#define CILIUM_XDP_SECTIONS_SNAT 10
#define CILIUM_XDP_SECTIONS_DSR 12

// XDP context structure for mock registration
typedef struct xdp_md_
{
    void* data;               ///< Pointer to start of packet data.
    void* data_end;           ///< Pointer to end of packet data.
    uint64_t data_meta;       ///< Packet metadata.
    uint32_t ingress_ifindex; ///< Ingress interface index.
} xdp_md_t;

#define XDP_EXT_HELPER_FUNCTION_START EBPF_MAX_GENERAL_HELPER_FUNCTION
#define FALSE 0
#define TRUE 1
#define HELPER_FUNCTION_REALLOCATE_PACKET TRUE

// XDP helper function prototype descriptors
static const ebpf_helper_function_prototype_t _xdp_test_ebpf_extension_helper_function_prototype[] = {
    {EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER,
     XDP_EXT_HELPER_FUNCTION_START + 1,
     "bpf_xdp_adjust_head",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_ANYTHING},
     {HELPER_FUNCTION_REALLOCATE_PACKET}}};

// XDP program context descriptor
static const ebpf_context_descriptor_t _ebpf_xdp_test_context_descriptor = {
    sizeof(xdp_md_t),
    EBPF_OFFSET_OF(xdp_md_t, data),
    EBPF_OFFSET_OF(xdp_md_t, data_end),
    EBPF_OFFSET_OF(xdp_md_t, data_meta)};

// Mock XDP program type descriptor
static const ebpf_program_type_descriptor_t _mock_xdp_program_type_descriptor = {
    EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
    "xdp",
    &_ebpf_xdp_test_context_descriptor,
    EBPF_PROGRAM_TYPE_XDP_GUID,
    BPF_PROG_TYPE_XDP};

// Mock XDP program info
static const ebpf_program_info_t _mock_xdp_program_info = {
    EBPF_PROGRAM_INFORMATION_HEADER,
    &_mock_xdp_program_type_descriptor,
    EBPF_COUNT_OF(_xdp_test_ebpf_extension_helper_function_prototype),
    _xdp_test_ebpf_extension_helper_function_prototype};

// Mock XDP section info
static ebpf_program_section_info_t _mock_xdp_section_info[] = {
    {{EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE},
     L"xdp",
     &EBPF_PROGRAM_TYPE_XDP,
     &EBPF_ATTACH_TYPE_XDP,
     BPF_PROG_TYPE_XDP,
     BPF_XDP}};

// RAII wrapper to ensure XDP program information is unregistered on scope exit
class xdp_program_info_guard
{
  public:
    xdp_program_info_guard()
    {
        uint32_t status = register_xdp_program_information();
        if (status != ERROR_SUCCESS) {
            throw std::runtime_error("Failed to register XDP program information");
        }
    }

    ~xdp_program_info_guard()
    {
        unregister_xdp_program_information();
    }

    // Delete copy constructor and assignment operator
    xdp_program_info_guard(const xdp_program_info_guard&) = delete;
    xdp_program_info_guard& operator=(const xdp_program_info_guard&) = delete;

  private:
    static uint32_t register_xdp_program_information();
    static void unregister_xdp_program_information();
    static bool g_xdp_registered;
};

// Initialize static member
bool xdp_program_info_guard::g_xdp_registered = false;

// Register XDP program information with the store
uint32_t
xdp_program_info_guard::register_xdp_program_information()
{
    if (g_xdp_registered) {
        return ERROR_SUCCESS;
    }

    uint32_t status = ebpf_store_update_program_information_array(&_mock_xdp_program_info, 1);
    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to register XDP program information: " << status << std::endl;
        return status;
    }

    status = ebpf_store_update_section_information(_mock_xdp_section_info, EBPF_COUNT_OF(_mock_xdp_section_info));
    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to register XDP section information: " << status << std::endl;
        return status;
    }

    g_xdp_registered = true;
    return ERROR_SUCCESS;
}

// Unregister XDP program information from the store
void
xdp_program_info_guard::unregister_xdp_program_information()
{
    if (!g_xdp_registered) {
        return;
    }

    ebpf_result_t result;

    // Delete section information
    for (size_t i = 0; i < EBPF_COUNT_OF(_mock_xdp_section_info); i++) {
        result = ebpf_store_delete_section_information(&_mock_xdp_section_info[i]);
        if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
            std::cerr << "Failed to delete XDP section information: " << result << std::endl;
        }
    }

    // Delete program information
    result = ebpf_store_delete_program_information(&_mock_xdp_program_info);
    if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
        std::cerr << "Failed to delete XDP program information: " << result << std::endl;
    }

    g_xdp_registered = false;
}

void
verify_program(_In_z_ const char* file, uint32_t expected_section_count)
{
    // RAII guard to ensure XDP program information is registered and unregistered
    xdp_program_info_guard guard;

    struct bpf_object_open_opts opts = {0};
    bpf_program* program = nullptr;
    uint32_t section_count = 0;
    struct bpf_object* object = bpf_object__open_file(file, &opts);
    REQUIRE(object != nullptr);

    while (true) {
        program = bpf_object__next_program(object, program);
        if (program == nullptr) {
            break;
        }
        section_count++;
        const char* section_name = bpf_program__section_name(program);
        REQUIRE(section_name != nullptr);

        const char* program_name = bpf_program__name(program);
        REQUIRE(program_name != nullptr);

#ifndef SKIP_VERIFICATION
        uint32_t result;
        ebpf_api_verifier_stats_t stats;
        const char* log_buffer = nullptr;
        const char* report = nullptr;
        REQUIRE(
            (result = ebpf_api_elf_verify_program_from_file(
                 file,
                 section_name,
                 program_name,
                 &EBPF_PROGRAM_TYPE_XDP,
                 EBPF_VERIFICATION_VERBOSITY_NORMAL,
                 &report,
                 &log_buffer,
                 &stats),
             ebpf_free_string(log_buffer),
             log_buffer = nullptr,
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
