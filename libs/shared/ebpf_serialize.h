// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Data structures and functions for serializing and de-serializing eBPF structs
// between API and Execution Context.

#pragma once

#include "cxplat.h"
#include "ebpf_core_structs.h"
// Everything in this file must be usable in both user mode and kernel mode,
// and not rely on ebpf_platform.h.

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief eBPF Internal Map Information
     */
    typedef struct _ebpf_map_info_internal
    {
        ebpf_map_definition_in_memory_t definition;
        cxplat_utf8_string_t pin_path;
    } ebpf_map_info_internal_t;

    /**
     * @brief Serialized eBPF Map Information.
     */
    typedef struct _ebpf_serialized_map_info
    {
        ebpf_map_definition_in_memory_t definition;
        uint16_t pin_path_length;
        uint8_t pin_path[1];
    } ebpf_serialized_map_info_t;

    /**
     * @brief Serialize array of ebpf_map_info_t onto output buffer.
     *
     * @param[in]  map_count Length of input array of ebpf_map_info_internal_t structs.
     * @param[in]  map_info Array of ebpf_map_info_t to serialize.
     * @param[out] output_buffer Caller specified output buffer to write serialized data into.
     * @param[in]  output_buffer_length Output buffer length.
     * @param[out] serialized_data_length Length of successfully serialized data.
     * @param[out] required_length Length of buffer required to serialize input array.
     *
     * @retval EBPF_SUCCESS The serialization was successful.
     * @retval EBPF_ERROR_INSUFFICIENT_BUFFER The output buffer is insufficient to store serialized data.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_serialize_internal_map_info_array(
        uint16_t map_count,
        _In_count_(map_count) const ebpf_map_info_internal_t* map_info,
        _Out_writes_bytes_to_(output_buffer_length, *serialized_data_length) uint8_t* output_buffer,
        size_t output_buffer_length,
        _Out_ size_t* serialized_data_length,
        _Out_ size_t* required_length);

    /**
     * @brief Deserialize input buffer to an array of \ref ebpf_map_info_t.
     *
     * @param[in] input_buffer_length Input buffer length.
     * @param[in] input_buffer Input buffer that will be de-serialized.
     * @param[in] map_count Caller specified expected length of output array.
     * @param[out] map_info Array of ebpf_map_info_t deserialized from input buffer.
     *
     * @retval EBPF_SUCCESS The de-serialization was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more input parameters are incorrect.
     * @retval EBPF_NO_MEMORY Output array could not be allocated.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_deserialize_map_info_array(
        size_t input_buffer_length,
        _In_reads_bytes_(input_buffer_length) const uint8_t* input_buffer,
        uint16_t map_count,
        _Outptr_result_buffer_maybenull_(map_count) ebpf_map_info_t** map_info);

    /**
     * @brief Helper Function to free array of ebpf_map_info_t allocated by
     * ebpf_deserialize_map_info_array function.
     *
     * @param[in] map_count Length of array to be freed.
     * @param[in] map_info Map to be freed.
     */
    void
    ebpf_map_info_array_free(
        uint16_t map_count, _In_opt_count_(map_count) _Post_ptr_invalid_ ebpf_map_info_t* map_info);

    /**
     * @brief Serialize ebpf_program_info_t onto output buffer.
     *
     * @param[in]  program_info Pointer to ebpf_program_info_t to serialize.
     * @param[out] output_buffer Caller specified output buffer to write serialized data into.
     * @param[in]  output_buffer_length Output buffer length.
     * @param[out] serialized_data_length Length of successfully serialized data.
     * @param[out] required_length Length of buffer required to serialize input array.
     *
     * @retval EBPF_SUCCESS The serialization was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more input parameters are incorrect.
     * @retval EBPF_ERROR_INSUFFICIENT_BUFFER The output buffer is insufficient to store serialized data.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_serialize_program_info(
        _In_ const ebpf_program_info_t* program_info,
        _Out_writes_bytes_to_(output_buffer_length, *serialized_data_length) uint8_t* output_buffer,
        size_t output_buffer_length,
        _Out_ size_t* serialized_data_length,
        _Out_ size_t* required_length);

    /**
     * @brief Deserialize input buffer to an array of ebpf_program_info_t.
     *
     * @param[in] input_buffer_length Input buffer length.
     * @param[in] input_buffer Input buffer that will be de-serialized.
     * @param[out] program_info Pointer to ebpf_program_info_t deserialized from input buffer.
     *
     * @retval EBPF_SUCCESS The de-serialization was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more input parameters are incorrect.
     * @retval EBPF_NO_MEMORY Output array could not be allocated.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_deserialize_program_info(
        size_t input_buffer_length,
        _In_reads_bytes_(input_buffer_length) const uint8_t* input_buffer,
        _Outptr_ ebpf_program_info_t** program_info);

#ifdef __cplusplus
}
#endif
