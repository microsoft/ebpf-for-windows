// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_internal.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_verifier_wrapper.hpp"
#include "header.h"
#include "rpc_client.h"
#include "rpc_interface_h.h"
#include "service_helper.h"

#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

static service_install_helper _service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);

static void
_get_program_byte_code_helper(const char* file_name, const char* section_name, ebpf_program_verify_info* info)
{
    EbpfMapDescriptor* descriptors = nullptr;
    int descriptors_count;
    ebpf_result_t result = EBPF_SUCCESS;
    const char* error_message = nullptr;
    std::vector<ebpf_program_t*> programs;
    ebpf_program_t* program;

    // Get byte code and map descriptors from ELF file.
    REQUIRE(
        (result = ebpf_get_program_byte_code(
             file_name,
             section_name,
             true, // mock map fd
             programs,
             &descriptors,
             &descriptors_count,
             &error_message),
         error_message ? printf("ebpf_get_program_byte_code failed with %s\n", error_message) : 0,
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == EBPF_SUCCESS));

    REQUIRE(programs.size() == 1);
    program = programs[0];
    REQUIRE(program->byte_code_size != 0);

    info->program_type = program->program_type;
    info->byte_code = program->byte_code;
    info->byte_code_size = program->byte_code_size;
    info->map_descriptors_count = descriptors_count;
    info->execution_context = execution_context_kernel_mode;
    if (descriptors != nullptr) {
        info->map_descriptors = reinterpret_cast<ebpf_map_descriptor*>(descriptors);
    }

    printf("instruction_array_size = %d\n", program->byte_code_size);
    ebpf_free_string(error_message);
}

TEST_CASE("verify-program-droppacket", "[verify-program-droppacket]")
{
    uint32_t result;
    const char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("droppacket.o", "xdp", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
         verifier_message ? printf("ebpf_rpc_verify_program failed with: %s\n", verifier_message) : 0,
         ebpf_free_string(verifier_message),
         verifier_message = nullptr,
         result == ERROR_SUCCESS));

    ebpf_free_string(verifier_message);
    clean_up_rpc_binding();
}

TEST_CASE("verify-program-bindmonitor", "[verify-program-bindmonitor]")
{
    uint32_t result;
    const char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("bindmonitor.o", "bind", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
         verifier_message ? printf("ebpf_rpc_verify_program failed with %s\n", verifier_message) : 0,
         ebpf_free_string(verifier_message),
         verifier_message = nullptr,
         result == ERROR_SUCCESS));

    ebpf_free_string(verifier_message);
    clean_up_rpc_binding();
}

TEST_CASE("verify-program-divide_by_zero", "[verify-program-divide_by_zero]")
{
    uint32_t result;
    const char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("divide_by_zero.o", "xdp", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
         verifier_message ? printf("ebpf_rpc_verify_program failed with %s\n", verifier_message) : 0,
         ebpf_free_string(verifier_message),
         verifier_message = nullptr,
         result == ERROR_SUCCESS));

    ebpf_free_string(verifier_message);
    clean_up_rpc_binding();
}

TEST_CASE("verify-program-droppacket_unsafe", "[verify-program-droppacket_unsafe]")
{
    uint32_t result;
    const char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("droppacket_unsafe.o", "xdp", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size);
    if (result != ERROR_SUCCESS) {
        if (verifier_message_size > 0) {
            printf("message from verifier:\n %s\n", verifier_message);
            ebpf_free_string(verifier_message);
            verifier_message = nullptr;
        }
    }
    REQUIRE((result == (int)EBPF_VERIFICATION_FAILED));
    REQUIRE(verifier_message_size > 0);

    ebpf_free_string(verifier_message);
    clean_up_rpc_binding();
}
