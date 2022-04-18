// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <vector>

#include "ebpf_api.h"
#include "encode_program_info.h"
#include "windows_program_type.h"

static ebpf_result_t
_emit_program_info_file(const char* file_name, const char* symbol_name, uint8_t* buffer, unsigned long buffer_size)
{
    unsigned long index;
    FILE* output;
    if (fopen_s(&output, file_name, "w") != 0)
        return EBPF_NO_MEMORY;

    fprintf(output, "#pragma once\n");
    fprintf(output, "#include <stdint.h>\n");
    fprintf(output, "static const uint8_t %s[] = {", symbol_name);
    for (index = 0; index < buffer_size; index++) {
        if (index % 16 == 0)
            fprintf(output, "\n");

        fprintf(output, "0x%.2X, ", buffer[index]);
    }
    fprintf(output, "};");
    fflush(output);
    fclose(output);
    return EBPF_SUCCESS;
}

static ebpf_result_t
_encode_program_info(const EbpfProgramType& input_program_type)
{
    ebpf_result_t return_value;
    std::string file_name = std::string("ebpf_") + input_program_type.name + std::string("_program_data.h");
    std::string type_name = std::string("_ebpf_encoded_") + input_program_type.name + std::string("_program_info_data");
    uint8_t* buffer = NULL;
    unsigned long buffer_size = 0;
    ebpf_context_descriptor_t context_descriptor = *input_program_type.context_descriptor;
    ebpf_program_type_descriptor_t program_type = {
        input_program_type.name.c_str(),
        &context_descriptor,
        *reinterpret_cast<GUID*>(input_program_type.platform_specific_data)};
    ebpf_program_info_t program_info = {program_type, 0, NULL};

    program_info.count_of_helpers = ebpf_core_helper_functions_count;
    program_info.helper_prototype = ebpf_core_helper_function_prototype;
    return_value = ebpf_program_info_encode(&program_info, &buffer, &buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = _emit_program_info_file(file_name.c_str(), type_name.c_str(), buffer, buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(buffer);
    return return_value;
}

int
main()
{
    for (const auto& program_type : windows_program_types) {
        if (program_type.platform_specific_data == 0) {
            continue;
        }
        _encode_program_info(program_type);
    }
    return 0;
}
