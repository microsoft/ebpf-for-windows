// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <vector>

#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "encode_program_info.h"
#include "net_ebpf_ext_program_info.h"

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
_encode_bind()
{
    ebpf_result_t return_value;
    uint8_t* buffer = NULL;
    unsigned long buffer_size = 0;
    ebpf_context_descriptor_t bind_context_descriptor = {
        sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
    ebpf_program_type_descriptor_t bind_program_type = {"bind", &bind_context_descriptor, EBPF_PROGRAM_TYPE_BIND};
    ebpf_program_info_t bind_program_info = {bind_program_type, 0, NULL};

    bind_program_info.count_of_helpers = ebpf_core_helper_functions_count;
    bind_program_info.helper_prototype = ebpf_core_helper_function_prototype;
    return_value = ebpf_program_info_encode(&bind_program_info, &buffer, &buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = _emit_program_info_file(
        "ebpf_bind_program_data.h", "_ebpf_encoded_bind_program_info_data", buffer, buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(buffer);

    return return_value;
}

static ebpf_result_t
_encode_xdp()
{
    ebpf_result_t return_value;
    uint8_t* buffer = NULL;
    unsigned long buffer_size = 0;
    ebpf_context_descriptor_t xdp_context_descriptor = {
        sizeof(xdp_md_t),
        EBPF_OFFSET_OF(xdp_md_t, data),
        EBPF_OFFSET_OF(xdp_md_t, data_end),
        EBPF_OFFSET_OF(xdp_md_t, data_meta)};
    ebpf_program_type_descriptor_t xdp_program_type = {"xdp", &xdp_context_descriptor, EBPF_PROGRAM_TYPE_XDP};
    ebpf_program_info_t xdp_program_info = {xdp_program_type, 0, NULL};
    xdp_program_info.count_of_helpers =
        ebpf_core_helper_functions_count + EBPF_COUNT_OF(_xdp_ebpf_extension_helper_function_prototype);
    std::vector<ebpf_helper_function_prototype_t> _helper_function_prototypes;
    _helper_function_prototypes.assign(
        ebpf_core_helper_function_prototype, ebpf_core_helper_function_prototype + ebpf_core_helper_functions_count);
    _helper_function_prototypes.insert(
        _helper_function_prototypes.end(),
        _xdp_ebpf_extension_helper_function_prototype,
        _xdp_ebpf_extension_helper_function_prototype + EBPF_COUNT_OF(_xdp_ebpf_extension_helper_function_prototype));
    xdp_program_info.helper_prototype = _helper_function_prototypes.data();
    return_value = ebpf_program_info_encode(&xdp_program_info, &buffer, &buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value =
        _emit_program_info_file("ebpf_xdp_program_data.h", "_ebpf_encoded_xdp_program_info_data", buffer, buffer_size);
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
    if (_encode_xdp() != EBPF_SUCCESS || _encode_bind() != EBPF_SUCCESS)
        return 1;
    return 0;
}
