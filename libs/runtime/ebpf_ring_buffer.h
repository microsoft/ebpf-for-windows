// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_ring_buffer_record.h"
#include "ebpf_shared_framework.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_ring_buffer
{
    size_t length;
    volatile size_t consumer_offset;         ///< Consumer has read up to this offset.
    volatile size_t producer_offset;         ///< Producer(s) have reserved up to this offset.
    volatile size_t producer_reserve_offset; ///< Next record to be reserved.
    uint8_t* shared_buffer;                  ///< Shared double-mapped buffer.
    ebpf_ring_descriptor_t* ring_descriptor; ///< Memory ring descriptor.
} ebpf_ring_buffer_t;
// ebpf_ring_buffer_t should be made opaque instead of being in ebpf_ring_buffer.h (#4144).

static_assert(sizeof(size_t) == 8, "size_t must be 8 bytes");

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
 * @brief Initialize a pre-allocated ring buffer struct by allocating the ring.
 *
 * @note This is used by perf event array to initialize the ring buffer in the perf ring.
 * Use ebpf_ring_buffer_create to create a new ring buffer.
 *
 * @param[out] ring Ring buffer to initialize.
 * @param[in] capacity Size in bytes of ring buffer.
 * @retval EBPF_SUCCESS Successfully initialized ring buffer.
 * @retval EBPF_NO_MEMORY Unable to allocate ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_allocate_ring(
    _Out_writes_bytes_(sizeof(ebpf_ring_buffer_t)) ebpf_ring_buffer_t* ring, size_t capacity);

/**
 * @brief Free the ring buffer memory.
 *
 * @note This is used by perf event array to free the ring buffer in the perf ring.
 *
 * @param[in] ring Ring buffer to free.
 */
void
ebpf_ring_buffer_free_ring_memory(_Inout_ ebpf_ring_buffer_t* ring);

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
 * @brief Reserve a record in the ring buffer. Data buffer is valid until either ebpf_ring_buffer_submit,
 * ebpf_ring_buffer_discard, or the end of the current epoch.
 *
 * @note This is safe for multiple producers to call at the same time.
 *
 * @param[in, out] ring_buffer Ring buffer to update.
 * @param[out] data Pointer to start of reserved record data on success.
 * @param[in] length Length of data buffer to reserve.
 * @retval EBPF_SUCCESS Successfully reserved space in the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT The length is < 1, > 2^31 -1, or > ring capacity.
 * @retval EBPF_NO_MEMORY Failed to reserve space for record (ring buffer full).
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve(
    _Inout_ ebpf_ring_buffer_t* ring_buffer, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length);

/**
 * @brief Reserve a record with exclusive access to a ring buffer. Data buffer is valid until either
 * ebpf_ring_buffer_submit, ebpf_ring_buffer_discard, or the end of the current epoch.
 *
 * @note This function must only be called by a single thread, or by a single CPU at dispatch.
 * It assumes the latest producer reserve offset was already seen on this CPU.
 *
 * @param[in, out] ring_buffer Ring buffer to update.
 * @param[out] data Pointer to start of reserved record data on success.
 * @param[in] length Length of data buffer to reserve.
 * @retval EBPF_SUCCESS Successfully reserved space in the ring buffer.
 * @retval EBPF_INVALID_ARGUMENT Unable to reserve space in the ring buffer.
 */
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve_exclusive(
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
