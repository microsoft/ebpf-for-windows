// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "header.h"
#include "catch2\catch.hpp"
#include "rpc_interface_h.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "ebpf_windows.h"
#include "ebpf_api.h"

// int test_verify_program();

RPC_STATUS
initialize_rpc_binding();
RPC_STATUS
cleanup_rpc_binding();
uint32_t
ebpf_get_program_byte_code(
    const char* file_name,
    const char* section_name,
    ebpf_program_type_t* program_type,
    bool mock_map_fd,
    uint8_t** instructions,
    uint32_t* instructions_size,
    EbpfMapDescriptor** map_descriptors,
    int* map_descriptors_count,
    const char** error_message);

int
ebpf_rpc_verify_program(ebpf_program_verify_info* info, unsigned char** logs, uint32_t* logs_size);

TEST_CASE("verify-program", "[verify-program]")
{
    uint8_t* instruction_array;
    uint32_t instruction_array_size;
    EbpfMapDescriptor* descriptors;
    int descriptors_count;
    uint32_t result = ERROR_SUCCESS;
    ebpf_program_type_t program_type;
    const char* error_message = nullptr;
    unsigned char* verifier_message = nullptr;
    uint32_t verifier_message_size;
    ebpf_program_verify_info info = {0};

    // Get byte code and map descriptors from ELF file.
    REQUIRE(
        (result = ebpf_get_program_byte_code(
             "droppacket.o",
             "xdp",
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

    info.program_type = program_type;
    info.byte_code = instruction_array;
    info.byte_code_size = instruction_array_size;
    info.map_count = descriptors_count;
    info.map_descriptors = reinterpret_cast<ebpf_map_descriptor*>(descriptors);

    printf("instruction_array_size = %d\n", instruction_array_size);

    REQUIRE(initialize_rpc_binding() == RPC_S_OK);

    REQUIRE(
        (result = ebpf_rpc_verify_program(&info, &verifier_message, &verifier_message_size),
         error_message ? printf("ebpf_get_program_byte_code failed with %s\n", error_message) : 0,
         ebpf_api_free_string(error_message),
         error_message = nullptr,
         result == ERROR_SUCCESS));

    cleanup_rpc_binding();
}

/*
int main(int argc, char** argv)
{
    char* file_name;
    char* section_name;
    uint32_t result = ERROR_SUCCESS;

    if (argc != 3)
    {
        printf("invalid args\n");
        return ERROR_INVALID_PARAMETER;
    }

    // argv[1] is the file name
    file_name = argv[1];

    // argv[1] is the section name
    section_name = argv[2];

    return test_verify_program(file_name, section_name);
}
*/