// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_perf_event_array_record.h"
#include "ebpf_shared_framework.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_perf_event_array ebpf_perf_event_array_t;
typedef struct _ebpf_perf_event_array_opts
{
    size_t sz; /* size of this struct, for forward/backward compatiblity */
    uint64_t flags;
} ebpf_perf_event_array_opts_t;
#define perf_event_array_opts__last_field sz

/**
 * @brief Allocate a perf_event_array with capacity.
 *
 * @param[out] perf_event_array Pointer to buffer that holds  buffer pointer on success.
 * @param[in] capacity Size in bytes of ring buffer.
 * @retval EBPF_SUCCESS Successfully allocated ring buffer.
 * @retval EBPF_NO_MEMORY Unable to allocate ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_create(
    _Outptr_ ebpf_perf_event_array_t** perf_event_array, size_t capacity, _In_ ebpf_perf_event_array_opts_t* opts);

/**
 * @brief Free a ring buffer.
 *
 * @param[in] perf_event_array Perf event array to free.
 */
void
ebpf_perf_event_array_destroy(_Frees_ptr_opt_ ebpf_perf_event_array_t* perf_event_array);

/**
 * @brief Write out a variable sized record to the ring buffer.
 *
 * @param[in] ctx Context to write to.
 * @param[in, out] perf_event_array Perf event array to write to.
 * @param[in] cpu CPU ID to write to.
 * @param[in] data Data to copy into record.
 * @param[in] length Length of data to copy.
 * @retval EBPF_SUCCESS Successfully wrote record ring buffer.
 * @retval EBPF_OUT_OF_SPACE Unable to output to ring buffer due to inadequate space.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _Inout_ void* ctx,
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint64_t flags,
    _In_reads_bytes_(length) uint8_t* data,
    size_t length);

/**
 * @brief Query the current ready and free offsets from the ring buffer.
 *
 * @param[in] perf_event_array Perf event array to query.
 * @param[in] cpu_id CPU ID to query.
 * @param[out] consumer Offset of the first buffer that can be consumed.
 * @param[out] producer Offset of the next buffer to be produced.
 */
void
ebpf_perf_event_array_query(
    _In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Out_ size_t* consumer, _Out_ size_t* producer);

/**
 * @brief Mark one or more records in the ring buffer as returned to the ring.
 *
 * @param[in, out] perf_event_array Perf event array to update.
 * @param[in] cpu_id CPU ID to query.
 * @param[in] length Length of bytes to return to the ring buffer.
 * @retval EBPF_SUCCESS Successfully returned records to the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to return records to the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_return(_Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t length);

/**
 * @brief Get pointer to the ring buffer shared data.
 *
 * @param[in] perf_event_array Perf event array to query.
 * @param[in] cpu_id CPU ID to query.
 * @param[out] buffer Pointer to ring buffer data.
 * @retval EBPF_SUCCESS Successfully mapped the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to map the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_buffer(
    _In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Outptr_ uint8_t** buffer);

CXPLAT_EXTERN_C_END