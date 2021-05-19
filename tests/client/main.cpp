// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_internal.h"
#include "catch2\catch.hpp"
#include "ebpf_api.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "header.h"
#include "rpc_client.h"
#include "rpc_interface_h.h"
#include "service_helper.h"

#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

int
ebpf_rpc_verify_program(ebpf_program_verify_info* info, unsigned char** logs, uint32_t* logs_size);

void
_get_program_byte_code_helper(const char* file_name, const char* section_name, ebpf_program_verify_info* info)
{
    uint8_t* instruction_array;
    uint32_t instruction_array_size;
    EbpfMapDescriptor* descriptors = nullptr;
    int descriptors_count;
    uint32_t result = ERROR_SUCCESS;
    ebpf_program_type_t program_type;
    const char* error_message = nullptr;

    // Get byte code and map descriptors from ELF file.
    REQUIRE(
        (result = ebpf_get_program_byte_code(
             file_name,
             section_name,
             &program_type,
             true, // mock map fd
             &instruction_array,
             &instruction_array_size,
             &descriptors,
             &descriptors_count,
             &error_message),
         error_message ? printf("ebpf_get_program_byte_code failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == ERROR_SUCCESS));

    REQUIRE(instruction_array_size != 0);

    info->program_type = program_type;
    info->byte_code = instruction_array;
    info->byte_code_size = instruction_array_size;
    info->map_descriptors_count = descriptors_count;
    if (descriptors != nullptr) {
        info->map_descriptors = reinterpret_cast<ebpf_map_descriptor*>(descriptors);
    }

    printf("instruction_array_size = %d\n", instruction_array_size);
    ebpf_api_free_string(error_message);
}

TEST_CASE("verify-program-droppacket", "[verify-program-droppacket]")
{
    uint32_t result;
    unsigned char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    service_install_helper service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME);
    REQUIRE(service_helper.initialize() == ERROR_SUCCESS);

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("droppacket.o", "xdp", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
         verifier_message ? printf("ebpf_rpc_verify_program failed with: %s\n", verifier_message) : 0,
         ebpf_api_free_string((const char*)verifier_message),
         verifier_message = nullptr,
         result == ERROR_SUCCESS));

    ebpf_api_free_string((const char*)verifier_message);
    clean_up_rpc_binding();
    service_helper.uninitialize();
}

TEST_CASE("verify-program-bindmonitor", "[verify-program-bindmonitor]")
{
    uint32_t result;
    unsigned char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = { 0 };

    service_install_helper service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME);
    REQUIRE(service_helper.initialize() == ERROR_SUCCESS);

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("bindmonitor.o", "bind", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
            verifier_message ? printf("ebpf_rpc_verify_program failed with %s\n", verifier_message) : 0,
            ebpf_api_free_string((const char*)verifier_message),
            verifier_message = nullptr,
            result == ERROR_SUCCESS));

    ebpf_api_free_string((const char*)verifier_message);
    clean_up_rpc_binding();
    service_helper.uninitialize();
}

TEST_CASE("verify-program-divide_by_zero", "[verify-program-divide_by_zero]")
{
    uint32_t result;
    unsigned char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    service_install_helper service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME);
    REQUIRE(service_helper.initialize() == ERROR_SUCCESS);

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("divide_by_zero.o", "xdp", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
         verifier_message ? printf("ebpf_get_program_byte_code failed with %s\n", verifier_message) : 0,
         ebpf_api_free_string((const char*)verifier_message),
         verifier_message = nullptr,
         result == ERROR_SUCCESS));

    ebpf_api_free_string((const char*)verifier_message);
    clean_up_rpc_binding();
    service_helper.uninitialize();
}

TEST_CASE("verify-program-droppacket_unsafe", "[verify-program-droppacket_unsafe]")
{
    uint32_t result;
    unsigned char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    service_install_helper service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME);
    REQUIRE(service_helper.initialize() == ERROR_SUCCESS);

    // Get byte code and map descriptors from ELF file.
    _get_program_byte_code_helper("droppacket_unsafe.o", "xdp", &info);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size);
    if (result != ERROR_SUCCESS) {
        if (verifier_message_size > 0) {
            printf("message from verifier:\n %s\n", verifier_message);
            ebpf_api_free_string((const char*)verifier_message);
            verifier_message = nullptr;
        }
    }
    REQUIRE((result == (int)EBPF_VALIDATION_FAILED));
    REQUIRE(verifier_message_size > 0);

    ebpf_api_free_string((const char*)verifier_message);
    clean_up_rpc_binding();
    service_helper.uninitialize();
}
