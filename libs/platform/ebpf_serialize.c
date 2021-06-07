// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file contains function implementations for serializing and de-serializing
// various eBPF structures to/from ebpf_operation*_request/response structures.
#include "ebpf_serialize.h"

void
ebpf_map_information_array_free(uint16_t map_count, _In_count_(map_count) const ebpf_map_information_t* map_info)
{
    uint16_t map_index;

    for (map_index = 0; map_index < map_count; map_index++) {
        ebpf_free(map_info[map_index].pin_path);
    }

    ebpf_free((void*)map_info);
}

ebpf_result_t
ebpf_serialize_core_map_information_array(
    uint16_t map_count,
    _In_count_(map_count) const ebpf_core_map_information_t* map_info,
    _Out_writes_bytes_to_(output_buffer_length, *serialized_data_length) uint8_t* output_buffer,
    size_t output_buffer_length,
    _Out_ size_t* serialized_data_length,
    _Out_ size_t* required_length)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint16_t map_index;
    uint8_t* current = NULL;

    *serialized_data_length = 0;

    // Compute required length for serialized array of map information objects.
    *required_length = 0;
    for (map_index = 0; map_index < map_count; map_index++) {
        // Increment required_length by EBPF_OFFSET_OF(ebpf_serialized_map_information_t, pin_path).
        result = ebpf_safe_size_t_add(
            *required_length, EBPF_OFFSET_OF(ebpf_serialized_map_information_t, pin_path), required_length);
        if (result != EBPF_SUCCESS)
            goto Exit;

        // Increment required_length by map_info[map_index].pin_path.length.
        result = ebpf_safe_size_t_add(*required_length, map_info[map_index].pin_path.length, required_length);
        if (result != EBPF_SUCCESS)
            goto Exit;
    }

    // Output buffer too small.
    if (output_buffer_length < *required_length) {
        result = EBPF_ERROR_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    *serialized_data_length = *required_length;
    current = output_buffer;

    for (map_index = 0; map_index < map_count; map_index++) {
        size_t serialized_map_information_length;
        const ebpf_core_map_information_t* source = &map_info[map_index];
        ebpf_serialized_map_information_t* destination = (ebpf_serialized_map_information_t*)current;

        // Compute required length for serialized map information.
        result = ebpf_safe_size_t_add(
            EBPF_OFFSET_OF(ebpf_serialized_map_information_t, pin_path),
            source->pin_path.length,
            &serialized_map_information_length);
        if (result != EBPF_SUCCESS)
            goto Exit;

        // Copy the map definition fields.
        destination->definition = source->definition;

        // Set the length of the pin path.
        destination->pin_path_length = (uint16_t)source->pin_path.length;

        // Copy the pin path buffer.
        memcpy(destination->pin_path, source->pin_path.value, source->pin_path.length);

        // Move the output buffer current pointer.
        current += serialized_map_information_length;
    }

Exit:
    return result;
}

ebpf_result_t
ebpf_deserialize_map_information_array(
    size_t input_buffer_length,
    _In_reads_bytes_(input_buffer_length) const uint8_t* input_buffer,
    uint16_t map_count,
    _Outptr_result_buffer_(map_count) ebpf_map_information_t** map_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint16_t map_index;
    size_t out_map_size;
    ebpf_map_information_t* out_map_info = NULL;
    uint8_t* current;
    size_t buffer_left;

    // Allocate the output maps.
    result = ebpf_safe_size_t_multiply(sizeof(ebpf_map_information_t), (size_t)map_count, &out_map_size);
    if (result != EBPF_SUCCESS)
        goto Exit;

    out_map_info = (ebpf_map_information_t*)ebpf_allocate(out_map_size, EBPF_MEMORY_NO_EXECUTE);
    if (out_map_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    current = (uint8_t*)input_buffer;
    buffer_left = input_buffer_length;
    for (map_index = 0; map_index < map_count; map_index++) {
        ebpf_serialized_map_information_t* source;
        ebpf_map_information_t* destination;
        size_t destination_pin_path_length;

        // Check if sufficient input buffer remaining.
        if (buffer_left < sizeof(ebpf_serialized_map_information_t)) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        source = (ebpf_serialized_map_information_t*)current;
        destination = &out_map_info[map_index];

        // Copy the map definition part.
        destination->definition = source->definition;

        // Advance the input buffer current pointer.
        current += EBPF_OFFSET_OF(ebpf_serialized_map_information_t, pin_path);

        // Adjust remaining input buffer length
        result = ebpf_safe_size_t_subtract(
            buffer_left, EBPF_OFFSET_OF(ebpf_serialized_map_information_t, pin_path), &buffer_left);
        if (result != EBPF_SUCCESS)
            goto Exit;

        // Check if sufficient input buffer remaining.
        if (buffer_left < source->pin_path_length) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (source->pin_path_length > 0) {
            // Allocate the buffer to hold the pin path in destination map information structure.
            destination_pin_path_length = source->pin_path_length + 1;
            if (result != EBPF_SUCCESS)
                goto Exit;
            destination->pin_path = ebpf_allocate(destination_pin_path_length, EBPF_MEMORY_NO_EXECUTE);
            if (destination->pin_path == NULL) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            // Copy the pin path.
            memcpy(destination->pin_path, source->pin_path, source->pin_path_length);

            // Advance the input buffer current pointer.
            current += source->pin_path_length;

            // Adjust remaining input buffer length
            result = ebpf_safe_size_t_subtract(buffer_left, source->pin_path_length, &buffer_left);
            if (result != EBPF_SUCCESS)
                goto Exit;
        }
    }

    *map_info = out_map_info;
    out_map_info = NULL;

Exit:
    if (out_map_info != NULL)
        ebpf_map_information_array_free(map_count, out_map_info);

    return result;
}