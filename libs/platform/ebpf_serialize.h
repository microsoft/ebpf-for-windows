// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Data structures and functions for serializing and de-serializing eBPF structs
// between API and Execution Context.

#pragma once

#include "ebpf_core_structs.h"
#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief eBPF Core Map Information
     */
    typedef struct _ebpf_map_information_internal
    {
        ebpf_map_definition_t definition;
        ebpf_utf8_string_t pin_path;
    } ebpf_map_information_internal_t;

    /**
     * @brief Serialized eBPF Map Information.
     */
    typedef struct _ebpf_serialized_map_information
    {
        ebpf_map_definition_t definition;
        uint16_t pin_path_length;
        uint8_t pin_path[1];
    } ebpf_serialized_map_information_t;

    /**
     * @brief Serialize array of ebpf_map_information_t onto output buffer.
     *
     * @param[in]  map_count Length of input array of ebpf_map_information_internal_t structs.
     * @param[in]  map_info Array of ebpf_map_information_t to serialize.
     * @param[out]  output_buffer Caller specified output buffer to write serialized data into.
     * @param[in]  output_buffer_length Output buffer length.
     * @param[out] serialized_data_length Length of successfully serialized data.
     * @param[out] required_length Length of buffer required to serialize input array.
     *
     * @retval EBPF_SUCCESS The serialization was successful.
     * @retval EBPF_ERROR_INSUFFICIENT_BUFFER The output buffer is insufficient to store serialized data.
     */
    ebpf_result_t
    ebpf_serialize_core_map_information_array(
        uint16_t map_count,
        _In_count_(map_count) const ebpf_map_information_internal_t* map_info,
        _Out_writes_bytes_to_(output_buffer_length, *serialized_data_length) uint8_t* output_buffer,
        size_t output_buffer_length,
        _Out_ size_t* serialized_data_length,
        _Out_ size_t* required_length);

    /**
     * @brief Deserialize input buffer to an array of ebpf_map_information_t.
     *
     * @param[in] input_buffer_length Input buffer length.
     * @param[in] input_buffer Input buffer that will be de-serialized.
     * @param[in] map_count Caller specified expected length of output array.
     * @param[out] map_info Array of ebpf_map_information_t deserialized from input buffer.
     *
     * @retval EBPF_SUCCESS The de-serialization was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more input parameters are incorrect.
     * @retval EBPF_NO_MEMORY Output array could not be allocated.
     */
    ebpf_result_t
    ebpf_deserialize_map_information_array(
        size_t input_buffer_length,
        _In_reads_bytes_(input_buffer_length) const uint8_t* input_buffer,
        uint16_t map_count,
        _Outptr_result_buffer_(map_count) ebpf_map_information_t** map_info);

    /**
     * @brief Helper Function to free array of ebpf_map_information_t allocated by
     * ebpf_deserialize_map_information_array function.
     *
     * @param[in] map_count Length of array to be freed.
     * @param[in] map_info Map to be freed.
     */
    void
    ebpf_map_information_array_free(uint16_t map_count, _In_count_(map_count) ebpf_map_information_t* map_info);

#ifdef __cplusplus
}
#endif
