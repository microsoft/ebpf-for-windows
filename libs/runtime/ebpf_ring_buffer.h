// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_ring_buffer_record.h"
#include "ebpf_shared_framework.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_ring_buffer ebpf_ring_buffer_t;

/**
 * @brief Allocate a ring_buffer with capacity.
 *
 * @param[out] ring_buffer Pointer to buffer that holds ring buffer pointer on success.
 * @param[in] capacity Size in bytes of ring buffer.
 * @retval EBPF_SUCCESS Successfully allocated ring buffer.
 * @retval EBPF_NO_MEMORY Unable to allocate ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_create(_Outptr_ ebpf_ring_buffer_t** ring_buffer, size_t capacity);

/**
 * @brief Free a ring buffer.
 *
 * @param[in] ring_buffer Ring buffer to free.
 */
void
ebpf_ring_buffer_destroy(_Frees_ptr_opt_ ebpf_ring_buffer_t* ring_buffer);

/**
 * @brief Write out a variable sized record to the ring buffer.
 *
 * @param[in, out] ring_buffer Ring buffer to write to.
 * @param[in] data Data to copy into record.
 * @param[in] length Length of data to copy.
 * @retval EBPF_SUCCESS Successfully wrote record ring buffer.
 * @retval EBPF_INVALID_ARGUMENT The length is < 1, > 2^31 -1, or > ring capacity.
 * @retval EBPF_NO_MEMORY Failed to reserve space for record (ring buffer full).
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_output(_Inout_ ebpf_ring_buffer_t* ring_buffer, _In_reads_bytes_(length) uint8_t* data, size_t length);

/**
 * @brief Reserve a buffer in the ring buffer. Buffer is valid until either ebpf_ring_buffer_submit,
 * ebpf_ring_buffer_discard, or the end of the current epoch.
 *
 * @param[in, out] ring_buffer Ring buffer to update.
 * @param[out] data Pointer to start of reserved buffer on success.
 * @param[in] length Length of buffer to reserve.
 * @retval EBPF_SUCCESS Successfully reserved space in the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT The length is < 1, > 2^31 -1, or > ring capacity.
 * @retval EBPF_NO_MEMORY Failed to reserve space for record (ring buffer full).
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve(
    _Inout_ ebpf_ring_buffer_t* ring_buffer, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length);

/**
 * @brief Mark a previously reserved buffer as available for reading.
 *
 * Clears the lock bit in the record header.
 *
 * @param[in] data Pointer to buffer to submit.
 * @retval EBPF_SUCCESS Record successfully submitted.
 * @retval EBPF_INVALID_ARGUMENT Invalid record (data == NULL).
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_submit(_Frees_ptr_opt_ uint8_t* data);

/**
 * @brief Discard a previously reserved record.
 *
 * Tells the consumer to skip this record when reading and unlocks it.
 *
 * @param[in] data Pointer to buffer to submit.
 * @retval EBPF_SUCCESS Successfully discarded space in the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to discard space in the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_discard(_Frees_ptr_opt_ uint8_t* data);

/**
 * @brief Query the current producer and consumer offsets from the ring buffer.
 *
 * @param[in] ring_buffer Ring buffer to query.
 * @param[out] consumer Offset of the first buffer that can be consumed.
 * @param[out] producer Offset of the next buffer to be produced.
 */
void
ebpf_ring_buffer_query(_In_ ebpf_ring_buffer_t* ring_buffer, _Out_ size_t* consumer, _Out_ size_t* producer);

/**
 * @brief Advance the consumer offset and return space to the ring.
 *
 * @param[in, out] ring_buffer Ring buffer to update.
 * @param[in] consumer_offset New consumer offset to advance to.
 * @retval EBPF_SUCCESS Successfully returned records to the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to return records to the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_return_buffer(_Inout_ ebpf_ring_buffer_t* ring_buffer, size_t consumer_offset);

/**
 * @brief Get pointer to the ring buffer shared data.
 *
 * @param[in] ring_buffer Ring buffer to query.
 * @param[out] buffer Pointer to ring buffer data.
 * @retval EBPF_SUCCESS Successfully mapped the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to map the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_map_buffer(_In_ const ebpf_ring_buffer_t* ring_buffer, _Outptr_ uint8_t** buffer);

/**
 * @brief Get the next record in the ring buffer's data buffer, skipping any discarded records.
 *
 * The value returned in next_offset can be passed to ebpf_ring_buffer_return_buffer to return the space to the ring.
 *
 * @param[in] ring_buffer Pointer to the ring buffer.
 * @param[in] buffer Pointer to the ring buffer's data buffer.
 * @param[out] next_offset Pointer to the offset after the last byte of this record (if any).
 * @return Pointer to the next record or NULL if no more records.
 */
_Must_inspect_result_ _Ret_maybenull_ const ebpf_ring_buffer_record_t*
ebpf_ring_buffer_next_consumer_record(
    _Inout_ ebpf_ring_buffer_t* ring_buffer,
    _In_ const uint8_t* buffer,
    _When_(return != NULL, _Out_) size_t* next_offset);

CXPLAT_EXTERN_C_END
