// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

inline static uint8_t*
_ring_record_get_buffer(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (uint8_t*)record - ((uintptr_t)record % PAGE_SIZE) - ((uintptr_t)record->header.page_offset * PAGE_SIZE) -
           (EBPF_RING_BUFFER_HEADER_PAGES * PAGE_SIZE);
}

inline static ebpf_ring_buffer_kernel_page_t*
_ring_buffer_kernel_page(_In_ const uint8_t* buffer)
{
    return (ebpf_ring_buffer_kernel_page_t*)(void*)buffer;
}

inline static ebpf_ring_buffer_consumer_page_t*
_ring_buffer_consumer_page(_In_ const uint8_t* buffer)
{
    return (ebpf_ring_buffer_consumer_page_t*)(buffer + PAGE_SIZE);
}

inline static ebpf_ring_buffer_producer_page_t*
_ring_buffer_producer_page(_In_ const uint8_t* buffer)
{
    return (ebpf_ring_buffer_producer_page_t*)(buffer + 2 * PAGE_SIZE);
}

inline static volatile size_t*
_ring_consumer_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return &(ring->consumer_page->consumer_offset);
}

inline static volatile size_t*
_ring_producer_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return &(ring->producer_page->producer_offset);
}

inline static volatile size_t*
_ring_producer_reserve_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return &(ring->kernel_page->producer_reserve_offset);
}

/**
 * @brief Read-acquire the record header.
 *
 * Used to check for the lock bit to ensure that all writes to the record are visible.
 *
 * @param[in] record Pointer to the record.
 * @return 32 bit record header with length and lock+discard bits.
 */
inline static uint32_t
_ring_record_read_header_acquire(_In_ const ebpf_ring_buffer_record_t* record)
{
    return ReadUInt32Acquire(&record->header.length);
}

/**
 * @brief Get the record header (with no ordering constraints).
 *
 * This should only be used when the current value of the header has been read/written.
 *
 * @param[in] record Pointer to the record.
 * @return 32 bit record header with length and lock+discard bits.
 */
inline static uint32_t
_ring_record_read_header_nofence(_In_ const ebpf_ring_buffer_record_t* record)
{
    return ReadUInt32NoFence(&record->header.length);
}

/**
 * @brief Write-release the record header.
 *
 * Used to unlock (submit or discard) a record and make it visible to consumers.
 *
 * @param[in] record Pointer to the record.
 * @param[in] header New header value.
 */
inline static void
_ring_record_write_header_release(_Inout_ ebpf_ring_buffer_record_t* record, uint32_t header)
{
    WriteUInt32Release(&record->header.length, header);
}

/**
 * @brief Write the record header (without ordering constraints).
 *
 * Used by the producer between reserving space for the record and write-releasing the producer offset.
 *
 * @param[in] record Pointer to the record.
 * @param[in] header New header value.
 */
inline static void
_ring_record_write_header_nofence(_Inout_ ebpf_ring_buffer_record_t* record, uint32_t header)
{
    WriteUInt32NoFence(&record->header.length, header);
}

/**
 * @brief Get the consumer offset.
 *
 * The producer can always safely no-fence read the consumer offset.
 *
 * With a single consumer thread we can always no-fence read and write the consumer offset.
 * - The consumer will always have the latest value to read and update.
 * - With the current async op design we don't have control over the calling context so need to acquire/release
 *   the consumer offset in the consumer code to ensure it is monotonically increasing.
 *
 * @param[in] ring Pointer to the ring.
 * @return Consumer offset.
 */
inline static size_t
_ring_read_consumer_offset_nofence(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64NoFence(_ring_consumer_offset(ring));
}

/**
 * @brief Get the consumer offset with read-acquire.
 *
 * The consumer should use this when it doesn't know it has the latest value.
 *
 * @param[in] ring Pointer to the ring.
 * @return Consumer offset.
 */
inline static size_t
_ring_read_consumer_offset_acquire(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64Acquire(_ring_consumer_offset(ring));
}

/**
 * @brief Set the consumer offset.
 *
 * There is only a single consumer so ordering is guaranteed so we should be able to no-fence write.
 * - With the async ops, we don't have control over the calling context so need to acquire/release
 *  the consumer offset in the consumer code to ensure it is monotonically increasing.
 *
 * @param[in] ring Pointer to the ring.
 * @param[in] offset Offset to set.
 */
inline static void
_ring_write_consumer_offset_release(_Inout_ ebpf_ring_buffer_t* ring, size_t offset)
{
    WriteULong64Release(_ring_consumer_offset(ring), offset);
}

/**
 * @brief Get the producer offset.
 *
 * Uses read-acquire to ensure producers see the latest value and consumers only see initialized records.
 *
 * @param[in] ring Pointer to the ring.
 * @return Producer offset.
 */
inline static size_t
_ring_read_producer_offset_acquire(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64Acquire(_ring_producer_offset(ring));
}

/**
 * @brief Set the producer offset.
 *
 * Write-release is used to ensure initialized record headers are visible to consumers before the offset update.
 *
 * @param[in] ring Pointer to the ring.
 * @param[in] offset Offset to set.
 */
inline static void
_ring_write_producer_offset_release(_Inout_ ebpf_ring_buffer_t* ring, size_t offset)
{
    WriteULong64Release(_ring_producer_offset(ring), offset);
}

/**
 * @brief Get the producer reserve offset.
 *
 * Uses read-acquire to ensure producers see the latest value before trying compare-exchange.
 *
 * @param[in] ring Pointer to the ring.
 * @return Producer reserve offset.
 */
inline static size_t
_ring_read_producer_reserve_offset_acquire(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64Acquire(_ring_producer_reserve_offset(ring));
}

/**
 * @brief Get the producer reserve offset with no-fence.
 *
 * Only use this when the latest offset is known (with exclusive access).
 *
 * @param[in] ring Pointer to the ring.
 * @return Producer reserve offset.
 */
inline static size_t
_ring_read_producer_reserve_offset_nofence(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64Acquire(_ring_producer_reserve_offset(ring));
}

/**
 * @brief Set the producer reserve offset with no-fence.
 *
 * This is unsafe to use with multiple producer threads/CPUs.
 * Exclusive reserve uses this before write-releasing the producer offset.
 *
 * @param[in] ring Pointer to the ring.
 * @return Producer reserve offset.
 */
inline static void
_ring_write_producer_reserve_offset_nofence(_Inout_ ebpf_ring_buffer_t* ring, size_t offset)
{
    WriteULong64NoFence(_ring_producer_reserve_offset(ring), offset);
}

/**
 * @brief Atomically advance the producer reserve offset to reserve space for a new record.
 *
 * Reserves space between expected_value and new_value if expected_value is returned.
 *
 * @param[in] ring Pointer to the ring.
 * @param[in] new_value New reserve offset to attempt to set.
 * @param[in] expected_value Expected current reserve offset.
 * @returns expected_value if the compare-exchange succeeded, otherwise the previous value.
 */
inline static size_t
_ring_exchange_producer_reserve_offset(_Inout_ ebpf_ring_buffer_t* ring, size_t new_value, size_t expected_value)
{
    return (uint64_t)ebpf_interlocked_compare_exchange_int64(
        (volatile int64_t*)_ring_producer_reserve_offset(ring), new_value, expected_value);
}

/**
 * @brief Get record size from data size (includes header).
 *
 * Adds 8 bytes for the header and pads to 8 byte alignment.
 *
 * @param[in] data_length Length of the data in the record.
 * @return Size of the record.
 */
inline static size_t
_ring_record_size(size_t data_length)
{
    return ((EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + data_length) + 7) & ~7;
}

/**
 * @brief Get the length of the record from the header.
 *
 * Excludes the lock and discard bits.
 *
 * @param[in] header_length Record header.length.
 * @return Length of the record.
 */
inline static uint32_t
_ring_header_length(_In_ uint32_t header_length)
{
    return header_length & ~(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT);
}

/**
 * @brief Check if the record is locked from the header.
 *
 * @param[in] header_length Record header.length.
 * @retval true The record is locked.
 * @retval false The record is not locked.
 */
inline static bool
_ring_header_locked(_In_ uint32_t header_length)
{
    return (header_length & EBPF_RINGBUF_LOCK_BIT) != 0;
}

/**
 * @brief Check if the record is discarded from the header.
 *
 * @param[in] header_length Record header.length.
 * @retval true The record is discarded.
 * @retval false The record is not discarded.
 */
inline static bool
_ring_header_discarded(_In_ uint32_t header_length)
{
    return (header_length & EBPF_RINGBUF_DISCARD_BIT) != 0;
}

/**
 * @brief Get the length of the ring.
 *
 * @param[in] ring Pointer to the ring.
 * @return Length of the ring.
 */
inline static size_t
_ring_get_length(_In_ const ebpf_ring_buffer_t* ring)
{
    return ring->length;
}

/**
 * @brief Get the record at the given offset.
 *
 * @param[in] ring Pointer to the ring.
 * @param[in] offset Offset of the record.
 * @return Pointer to the record.
 */
inline static _Ret_notnull_ ebpf_ring_buffer_record_t*
_ring_record_at_offset(_In_ const ebpf_ring_buffer_t* ring, size_t offset)
{
    return (ebpf_ring_buffer_record_t*)&(ring->data[offset % _ring_get_length(ring)]);
}

inline static void
_ring_buffer_notify_consumer(_In_ uint8_t* buffer, uint64_t flags)
{
    ebpf_ring_buffer_producer_page_t* producer_page = _ring_buffer_producer_page(buffer);
    ebpf_ring_buffer_kernel_page_t* kernel_page = _ring_buffer_kernel_page(buffer);
    PKEVENT wait_event = NULL;
    if (flags & EBPF_RINGBUF_FLAG_FORCE_WAKEUP) {
        wait_event = kernel_page->wait_event;
    } else if (!(flags & EBPF_RINGBUF_FLAG_NO_WAKEUP)) {
        // Notify only if ring might not be empty.
        if (kernel_page->wait_event != NULL) {
            ebpf_ring_buffer_consumer_page_t* consumer_page = _ring_buffer_consumer_page(buffer);
            // Notify the producer that a record is available.
            size_t consumer_offset = ReadULong64Acquire(&consumer_page->consumer_offset);
            size_t producer_offset = ReadULong64Acquire(&producer_page->producer_offset);
            if (producer_offset != consumer_offset) {
                wait_event = kernel_page->wait_event;
            }
        }
    }

    if (wait_event != NULL) {
        // Signal the event to notify the consumer that new data is available.
        KeSetEvent(wait_event, 0, FALSE);
    }
}

/**
 * @brief Get the next record in the ring buffer's data buffer, skipping any discarded records.
 *
 * @param[in] ring Pointer to the ring buffer.
 * @param[out] next_offset Pointer to the offset after the last byte of this record.
 * @return Pointer to the next record or NULL if no more records.
 */
_Must_inspect_result_ _Ret_maybenull_ ebpf_ring_buffer_record_t*
_ring_next_consumer_record(_In_ ebpf_ring_buffer_t* ring, _When_(return != NULL, _Out_) size_t* next_offset)
{
    size_t consumer_offset = _ring_read_consumer_offset_acquire(ring);
    // Read-acquire the producer offset to ensure we see newly initialized record headers.
    // - The producer write-releases the producer offset to ensure the header is initialized first.
    size_t producer_offset = _ring_read_producer_offset_acquire(ring);

    // Keep reading until we find a locked or submitted record (or the ring is empty).
    while (producer_offset > consumer_offset) {
        ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, consumer_offset);
        // Read-acquire the record header to ensure the final record data is visible.
        // - The producer write-releases the header to unlock to ensure any writes are completed first.
        uint32_t record_header = _ring_record_read_header_acquire(record);

        // If the record is locked, return NULL (records must be read in order).
        if (_ring_header_locked(record_header)) {
            return NULL;
        }

        size_t record_length = _ring_header_length(record_header);
        size_t total_record_size = _ring_record_size(record_length);
        if (!_ring_header_discarded(record_header)) {
            *next_offset = consumer_offset + total_record_size;
            return record;
        } else {
            consumer_offset += total_record_size;
            // Advance the consumer offset to return the discarded record space to the ring.
            _ring_write_consumer_offset_release(ring, consumer_offset);
        }
    }
    return NULL;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_allocate_ring(_Out_writes_bytes_(sizeof(ebpf_ring_buffer_t)) ebpf_ring_buffer_t* ring, size_t capacity)
{
    if ((capacity & ~(capacity - 1)) != capacity) {
        return EBPF_INVALID_ARGUMENT;
    }

    ring->ring_descriptor = ebpf_allocate_ring_buffer_memory(capacity);
    if (!ring->ring_descriptor) {
        return EBPF_NO_MEMORY;
    }

    void* base_address = ebpf_ring_descriptor_get_base_address(ring->ring_descriptor);
    ring->kernel_page = (ebpf_ring_buffer_kernel_page_t*)base_address;
    ring->consumer_page = (ebpf_ring_buffer_consumer_page_t*)((uint8_t*)base_address + PAGE_SIZE);
    ring->producer_page = (ebpf_ring_buffer_producer_page_t*)((uint8_t*)base_address + 2 * PAGE_SIZE);
    ring->data = (uint8_t*)base_address + (EBPF_RING_BUFFER_HEADER_PAGES * PAGE_SIZE);
    ring->length = capacity;
    ring->kernel_page->wait_event = NULL;

    return EBPF_SUCCESS;
}

void
ebpf_ring_buffer_free_ring_memory(_Inout_ ebpf_ring_buffer_t* ring)
{
    ebpf_ring_buffer_kernel_page_t* kernel_page = ring->kernel_page;
    if (kernel_page->wait_event != NULL) {
        ObDereferenceObject(kernel_page->wait_event);
        kernel_page->wait_event = NULL;
    }
    ebpf_free_ring_buffer_memory(ring->ring_descriptor);
    ring->ring_descriptor = NULL;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_create(_Outptr_ ebpf_ring_buffer_t** ring, size_t capacity)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_ring_buffer_t* local_ring_buffer =
        ebpf_epoch_allocate_with_tag(sizeof(ebpf_ring_buffer_t), EBPF_POOL_TAG_RING_BUFFER);
    if (!local_ring_buffer) {
        result = EBPF_NO_MEMORY;
        goto Error;
    }

    result = ebpf_ring_buffer_allocate_ring(local_ring_buffer, capacity);

    if (result != EBPF_SUCCESS) {
        goto Error;
    }

    *ring = local_ring_buffer;
    local_ring_buffer = NULL;
    return EBPF_SUCCESS;

Error:
    ebpf_ring_buffer_destroy(local_ring_buffer);
    local_ring_buffer = NULL;
    EBPF_RETURN_RESULT(result);
}

void
ebpf_ring_buffer_destroy(_Frees_ptr_opt_ ebpf_ring_buffer_t* ring)
{
    if (ring) {
        EBPF_LOG_ENTRY();

        ebpf_free_ring_buffer_memory(ring->ring_descriptor);
        ebpf_epoch_free(ring);

        EBPF_RETURN_VOID();
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_set_wait_handle(
    _Inout_ ebpf_ring_buffer_t* ring_buffer, _In_ ebpf_handle_t wait_handle, uint64_t flags)
{
    if (flags != 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_ring_buffer_kernel_page_t* kernel_page = ring_buffer->kernel_page;
    PKEVENT old_wait_event = kernel_page->wait_event;

    PKEVENT wait_event = NULL;
    NTSTATUS status = ObReferenceObjectByHandle(
        (HANDLE)wait_handle,
        EVENT_MODIFY_STATE,
        *ExEventObjectType,
        UserMode,
        (PVOID*)&wait_event,
        NULL);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ObReferenceObjectByHandle, status);
        return EBPF_INVALID_ARGUMENT;
    }

    kernel_page->wait_event = wait_event;

    // Dereference the old event if it exists.
    if (old_wait_event != NULL) {
        ObDereferenceObject(old_wait_event);
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_output(_Inout_ ebpf_ring_buffer_t* ring, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    uint8_t* record_data;
    ebpf_result_t result = ebpf_ring_buffer_reserve(ring, &record_data, length);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    memcpy(record_data, data, length);
    return ebpf_ring_buffer_submit(record_data, 0);
}

void
ebpf_ring_buffer_query(_In_ ebpf_ring_buffer_t* ring, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    *consumer = _ring_read_consumer_offset_acquire(ring);
    // Read-acquire the producer offset to ensure any newly reserved record headers are visible after query returns.
    *producer = _ring_read_producer_offset_acquire(ring);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_return_buffer(_Inout_ ebpf_ring_buffer_t* ring, size_t consumer_offset)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;

    size_t local_consumer_offset = _ring_read_consumer_offset_acquire(ring);
    // Read-acquire the producer offset to ensure we see newly initialized record headers.
    // - The consumer should only be returning previously unlocked records, but this is necessary
    //   to validate the return.
    size_t producer_offset = _ring_read_producer_offset_acquire(ring);

    if (consumer_offset > producer_offset) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_ring_buffer_return_buffer: Offset too large",
            *_ring_producer_offset(ring),
            *_ring_consumer_offset(ring));
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Verify new consumer offset is on a record boundary.
    while (local_consumer_offset < consumer_offset) {
        ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, local_consumer_offset);
        // Read-acquire record header to ensure we see the final record data.
        // - The producer write-releases the header to unlock to ensure any writes to the data are visible first.
        // - Even if the record is discarded, we need to make sure it's writes are visible before it can be re-used.
        uint32_t record_header = _ring_record_read_header_acquire(record);
        if (_ring_header_locked(record_header)) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "ebpf_ring_buffer_return_buffer: Record is locked",
                local_consumer_offset);
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        size_t record_length = _ring_header_length(record_header);
        size_t total_record_size = _ring_record_size(record_length);
        local_consumer_offset += total_record_size;
    }

    if (local_consumer_offset != consumer_offset) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_ring_buffer_return_buffer: Invalid return offset",
            local_consumer_offset);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Advanced the consumer offset to return the space to the ring.
    _ring_write_consumer_offset_release(ring, consumer_offset);
    result = EBPF_SUCCESS;
Done:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_map_user(
    _In_ const ebpf_ring_buffer_t* ring,
    _Outptr_ void** consumer,
    _Outptr_ void** producer,
    _Outptr_result_buffer_(*data_size) uint8_t** data,
    _Out_ size_t* data_size)
{
    *data_size = ring->length;
    return ebpf_ring_map_user(ring->ring_descriptor, consumer, producer, data);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_unmap_user(
    _In_ const ebpf_ring_buffer_t* ring, _In_ const void* consumer, _In_ const void* producer, _In_ const void* data)
{
    return ebpf_ring_unmap_user(ring->ring_descriptor, consumer, producer, data);
}

_Must_inspect_result_ _Ret_maybenull_ const ebpf_ring_buffer_record_t*
ebpf_ring_buffer_next_consumer_record(
    _Inout_ ebpf_ring_buffer_t* ring_buffer, _When_(return != NULL, _Out_) size_t* next_offset)
{
    return _ring_next_consumer_record(ring_buffer, next_offset);
}

#pragma warning(push)
#pragma warning( \
    disable : 28167) // warning C28167: Code analysis incorrectly reports that the function 'ebpf_ring_buffer_reserve'
                     // does not restore the IRQL to the value that was current at function entry.
_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve(
    _Inout_ ebpf_ring_buffer_t* ring, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length)
{
    uint32_t record_header = (uint32_t)length | EBPF_RINGBUF_LOCK_BIT;
    size_t ring_capacity = _ring_get_length(ring);
    size_t total_record_size = _ring_record_size(length);
    if (total_record_size > ring_capacity || length == 0 || length > EBPF_RINGBUF_MAX_RECORD_SIZE) {
        return EBPF_INVALID_ARGUMENT;
    }

    size_t consumer_offset = _ring_read_consumer_offset_nofence(ring);
    // Acquire producer_reserve_offset to ensure we see the latest value before checking for space.
    // - Avoids needing to raise irql to dispatch if there is no space.
    size_t reserve_offset = _ring_read_producer_reserve_offset_acquire(ring);
    size_t new_reserve_offset = reserve_offset + total_record_size;
    if (new_reserve_offset - consumer_offset > ring_capacity) {
        return EBPF_NO_MEMORY; // Not enough space for record.
    }

    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL irql_at_enter = ebpf_raise_irql_to_dispatch_if_needed();
    for (;;) {
        // Reserve loop synchronization:
        // - Compare-exchange serializes reservations (using producer_reserve_offset).
        //   - Checking for space before compare-exchange prevents producers from overflowing the ring.
        // - Spin loop serializes offset updates between producers (and ensures previous allocations are locked).
        // - producer_offset write-release serializes lock and offset update (lock before offset update).

        // Acquire producer_reserve_offset to ensure we see the latest value before compare exchange.
        // - An older value increases the chances of needing to retry the compare-exchange.
        reserve_offset = _ring_read_producer_reserve_offset_acquire(ring);
        new_reserve_offset = reserve_offset + total_record_size;
        if (new_reserve_offset - consumer_offset > ring_capacity) {
            result = EBPF_NO_MEMORY; // Not enough space for record.
            goto Done;
        }

        size_t old_reserve_offset = _ring_exchange_producer_reserve_offset(ring, new_reserve_offset, reserve_offset);
        if (old_reserve_offset == reserve_offset) {
            // We successfully allocated the space -- now we need to lock the record and *then* update producer offset.

            ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, reserve_offset);
            record->header.page_offset = (uint32_t)(((uint8_t *)record - ring->data) / PAGE_SIZE);

            // Initialize the record header.
            // - We can no-fence write here, the write-release below ensures the locked header is visible first.
            _ring_record_write_header_nofence(record, record_header);

            // There may be multiple producers that all advanced the producer reserve offset but haven't set the lock
            // bit yet. We need the following guarantees from this race between concurrent reservations:
            // 1. Any newly reserved record is locked by the time the consumer first sees it.
            //     - It could be written and unlocked before the consumer sees it, but it can't be uninitialized.
            //     - Guaranteed for the current record by the release write of the producer offset below.
            //       - Release ensures that the locked record header is visible no later than the producer offset
            //         update.
            //       - The consumer can only look at records between consumer and producer offsets,
            //         so the header will be locked by the time the consumer first sees it.
            //     - We also need to ensure any previous records are locked before we advance offset (explained below).
            // 2. The producer offset is monotonically increasing.
            //
            // To ensure both of the above we wait until the producer offset matches the offset of our record to advance
            // the producer offset.
            // - This guarantees (1) because if the producer offset update is visible for the previous record, then
            //   its locked header is visible.
            //   - by extension this guarantees that all newly reserved records allocated before us are already locked.
            // - This guarantees (2) because it ensures the producer offset updates happen in order.
            //     - We wait to update until all previous offset updates are visible, so the producer offset always
            //       steps forward 1 record at a time.
            while (reserve_offset != _ring_read_producer_offset_acquire(ring)) {
                // We shouldn't need to spin long - at dispatch the worst case is waiting for N-1 producers to update
                // the offset before us.
            }
            // Release producer offset to ensure lock bit is visible before offset update.
            _ring_write_producer_offset_release(ring, new_reserve_offset);
            *data = record->data;
            goto Done; // We have successfully reserved record, now can write+submit/discard.
        }
        // We lost the race and need to try again (but another process suceeded).
        // Get updated consumer_offset (lessens chance of failing on mostly full buffer).
        consumer_offset = _ring_read_consumer_offset_nofence(ring);
        // Try again from the reserve offset we got from the compare exchange.
        reserve_offset = old_reserve_offset;
    }
Done:
    ebpf_lower_irql_from_dispatch_if_needed(irql_at_enter);
    return result;
}
#pragma warning(pop)

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve_exclusive(
    _Inout_ ebpf_ring_buffer_t* ring, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length)
{
    //  Exclusive Reserve notes:
    //  - This function should only be called by a single thread/CPU currently.
    //    - A single consumer can be concurrently reading.
    //    - Assumes we already have seen the latest producer_reserve_offset and producer_offset.
    //  - Synchronization:
    //    - producer_offset write-release ensures record is locked before producer offset is updated.
    //    - With only a single producer we skip the loops and directly update the offsets.

    uint32_t record_header = (uint32_t)length | EBPF_RINGBUF_LOCK_BIT;
    size_t ring_capacity = _ring_get_length(ring);
    size_t total_record_size = _ring_record_size(length);
    if (total_record_size > ring_capacity || length == 0 || length >= EBPF_RINGBUF_MAX_RECORD_SIZE) {
        return EBPF_INVALID_ARGUMENT;
    }

    size_t consumer_offset = _ring_read_consumer_offset_nofence(ring);
    // Read producer_reserve_offset.
    // - We can use no-fence because exclusive reserve assumes we already have the latest value in this CPU.
    size_t reserve_offset = _ring_read_producer_reserve_offset_nofence(ring);
    size_t new_reserve_offset = reserve_offset + total_record_size;
    if (new_reserve_offset - consumer_offset > ring_capacity) {
        return EBPF_NO_MEMORY; // Not enough space for record.
    }

    // Update reserve offset.
    // - This is a no-fence write, the producer offset write-release below ensures this is visible first.
    _ring_write_producer_reserve_offset_nofence(ring, new_reserve_offset);

    ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, reserve_offset);
    record->header.page_offset = (uint32_t)(((uint8_t *)record - ring->data) / PAGE_SIZE);

    // Initialize the record header.
    // - We can no-fence write here, the write-release below ensures the locked header is visible first.
    _ring_record_write_header_nofence(record, record_header);

    // Release producer offset to ensure lock bit is visible before offset update.
    _ring_write_producer_offset_release(ring, new_reserve_offset);

    *data = record->data;
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_submit(_Frees_ptr_opt_ uint8_t* data, uint64_t flags)
{
    if (!data) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_ring_buffer_record_t* record =
        (ebpf_ring_buffer_record_t*)(data - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    // We can no-fence read the record header since we reserved this record so we already have the latest value.
    uint32_t header = _ring_record_read_header_nofence(record);
    // Clear the lock and discard bits from the header.
    header = _ring_header_length(header);
    // Write-release record header to ensure the record is unlocked AFTER any writes to the record data are visible.
    uint8_t* buffer = _ring_record_get_buffer(record);
    _ring_record_write_header_release(record, header);

    _ring_buffer_notify_consumer(buffer, flags);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_discard(_Frees_ptr_opt_ uint8_t* data, uint64_t flags)
{
    if (!data) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_ring_buffer_record_t* record =
        (ebpf_ring_buffer_record_t*)(data - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    // We can no-fence read the record header since we reserved this record so we already have the latest value.
    uint32_t header = _ring_record_read_header_nofence(record);
    // Clear the lock bit from the header and set the discard bit.
    header = (header & ~EBPF_RINGBUF_LOCK_BIT) | EBPF_RINGBUF_DISCARD_BIT;
    // Write-release the record header to ensure any writes to the discarded record are completed first.
    uint8_t* buffer = _ring_record_get_buffer(record); // Get buffer address before we unlock the record.
    _ring_record_write_header_release(record, header);

    _ring_buffer_notify_consumer(buffer, flags);
    return EBPF_SUCCESS;
}
