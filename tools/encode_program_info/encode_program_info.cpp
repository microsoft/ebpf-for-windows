// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_windows.h"

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

static ebpf_helper_function_prototype_t _ebpf_helper_function_prototype[] = {
    {1,
     "ebpf_map_lookup_element",
     EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    {2,
     "ebpf_map_update_element",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
    {3,
     "ebpf_map_delete_element",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}}};

static ebpf_result_t
_encode_bind()
{
    ebpf_result_t return_value;
    uint8_t* buffer = NULL;
    unsigned long buffer_size = 0;
    ebpf_context_descriptor_t bind_context_descriptor = {
        sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
    ebpf_program_type_descriptor_t bind_program_type = {"bind", &bind_context_descriptor, EBPF_PROGRAM_TYPE_BIND};
    ebpf_program_info_t bind_program_info = {
        bind_program_type, EBPF_COUNT_OF(_ebpf_helper_function_prototype), _ebpf_helper_function_prototype};

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
    ebpf_context_descriptor_t xdp_context_descriptor = {sizeof(xdp_md_t),
                                                        EBPF_OFFSET_OF(xdp_md_t, data),
                                                        EBPF_OFFSET_OF(xdp_md_t, data_end),
                                                        EBPF_OFFSET_OF(xdp_md_t, data_meta)};
    ebpf_program_type_descriptor_t xdp_program_type = {"xdp", &xdp_context_descriptor, EBPF_PROGRAM_TYPE_XDP};
    ebpf_program_info_t xdp_program_info = {
        xdp_program_type, EBPF_COUNT_OF(_ebpf_helper_function_prototype), _ebpf_helper_function_prototype};

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

static ebpf_result_t
_encode_flow()
{
    ebpf_result_t return_value;
    uint8_t* buffer = NULL;
    unsigned long buffer_size = 0;
    ebpf_context_descriptor_t flow_context_descriptor = {
        sizeof(flow_md_t), 0, EBPF_OFFSET_OF(flow_md_t, app_id) + sizeof(uint64_t), -1};
    ebpf_program_type_descriptor_t flow_program_type = {"flow", &flow_context_descriptor, EBPF_PROGRAM_TYPE_FLOW};
    ebpf_program_info_t flow_program_info = {
        flow_program_type, EBPF_COUNT_OF(_ebpf_helper_function_prototype), _ebpf_helper_function_prototype};

    return_value = ebpf_program_info_encode(&flow_program_info, &buffer, &buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = _emit_program_info_file(
        "ebpf_flow_program_data.h", "_ebpf_encoded_flow_program_info_data", buffer, buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(buffer);

    return return_value;
}

static ebpf_result_t
_encode_mac()
{
    ebpf_result_t return_value;
    uint8_t* buffer = NULL;
    unsigned long buffer_size = 0;
    ebpf_context_descriptor_t mac_context_descriptor = {
        sizeof(mac_md_t), 0, EBPF_OFFSET_OF(mac_md_t, packet_length) + sizeof(uint64_t), -1};
    ebpf_program_type_descriptor_t mac_program_type = {"mac", &mac_context_descriptor, EBPF_PROGRAM_TYPE_MAC};
    ebpf_program_info_t mac_program_info = {
        mac_program_type, EBPF_COUNT_OF(_ebpf_helper_function_prototype), _ebpf_helper_function_prototype};

    return_value = ebpf_program_info_encode(&mac_program_info, &buffer, &buffer_size);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    return_value = _emit_program_info_file(
        "ebpf_mac_program_data.h", "_ebpf_encoded_mac_program_info_data", buffer, buffer_size);
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
    if (_encode_xdp() != EBPF_SUCCESS
    || _encode_bind() != EBPF_SUCCESS
    || _encode_flow() != EBPF_SUCCESS
    || _encode_mac()  != EBPF_SUCCESS)
        return 1;
    return 0;
}
