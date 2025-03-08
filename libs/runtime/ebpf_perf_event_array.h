// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_shared_framework.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_perf_event_array ebpf_perf_event_array_t;
typedef struct _ebpf_perf_event_array_opts
{
    size_t sz; /* size of this struct, for forward/backward compatiblity */
    uint64_t flags;
} ebpf_perf_event_array_opts_t;
#define perf_event_array_opts__last_field sz

typedef enum _perf_event_array_flags
{
    PERF_ARRAY_FLAG_AUTO_CALLBACK = (uint64_t)1 << 0 /* Automatically invoke callback for each record */
} perf_event_array_flags_t;

/**
 * @brief Allocate a perf_event_array with capacity.
 *
 * @param[out] perf_event_array Pointer to buffer that holds buffer pointer on success.
 * @param[in] capacity Size in bytes of ring buffer.
 * @param[in] opts Options for creating the perf event array.
 * @retval EBPF_SUCCESS Successfully allocated ring buffer.
 * @retval EBPF_NO_MEMORY Unable to allocate ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_create(
    _Outptr_ _On_failure_(_Maybenull_) ebpf_perf_event_array_t** perf_event_array,
    size_t capacity,
    _In_ ebpf_perf_event_array_opts_t* opts);

/**
 * @brief Free a ring buffer.
 *
 * @param[in] perf_event_array Perf event array to free.
 */
void
ebpf_perf_event_array_destroy(_In_opt_ _Frees_ptr_opt_ ebpf_perf_event_array_t* perf_event_array);

/**
 * @brief Write out a variable sized record to the perf event array.
 *
 * @param[in] ctx Context to write to.
 * @param[in, out] perf_event_array Perf event array to write to.
 * @param[in] target_cpu CPU ring to write to (or (uint32_t)-1 for auto).
 * @param[in] data Data to copy into record.
 * @param[in] length Length of data to copy.
 * @param[out] cpu_id CPU ring that was written to.
 * @retval EBPF_SUCCESS Successfully wrote record ring buffer.
 * @retval EBPF_INVALID_ARGUMENT The length is < 1, > 2^31 -1, or > ring capacity.
 * @retval EBPF_INVALID_ARGUMENT target_cpu invalid or explictly specified below dispatch.
 * @retval EBPF_NO_MEMORY Failed to reserve space for record (perf ring full).
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output_simple(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t target_cpu,
    _In_reads_(length) uint8_t* data,
    size_t length,
    _Out_opt_ uint32_t* cpu_id);

/**
 * @brief Write out a variable sized record to the perf event array.
 *
 * @param[in] ctx Context to write to.
 * @param[in, out] perf_event_array Perf event array to write to.
 * @param[in] flags perf event output flags.
 * @param[in] data Data to copy into record.
 * @param[in] length Length of data to copy.
 * @param[out] cpu_id CPU ring that was written to.
 * @retval EBPF_SUCCESS Successfully wrote record ring buffer.
 * @retval EBPF_INVALID_ARGUMENT The length is < 1, > 2^31 -1, or > ring capacity.
 * @retval EBPF_INVALID_ARGUMENT cpu id in flags is invalid or explictly specified below dispatch.
 * @retval EBPF_INVALID_ARGUMENT context length in flags is non-zero without context data.
 * @retval EBPF_NO_MEMORY Failed to reserve space for record (perf ring full).
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _In_ void* ctx,
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint64_t flags,
    _In_reads_(length) uint8_t* data,
    size_t length,
    _Out_opt_ uint32_t* cpu_id);

/**
 * @brief Get the number of rings in the perf event array.
 * @param[in] perf_event_array Perf event array to query.
 * @return Number of rings in the perf event array.
 */
uint32_t
ebpf_perf_event_array_get_ring_count(_In_ const ebpf_perf_event_array_t* perf_event_array);

/**
 * @brief Get the total number of dropped records for a ring.
 * @param[in] perf_event_array Perf event array to query.
 * @param[in] cpu_id CPU ring to query.
 * @return Number of dropped records in the ring.
 */
size_t
ebpf_perf_event_array_get_lost_count(_In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id);

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
 * @param[in] consumer_offset New consumer offset to advance to.
 * @retval EBPF_SUCCESS Successfully returned records to the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to return records to the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_return_buffer(
    _Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t consumer_offset);

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
