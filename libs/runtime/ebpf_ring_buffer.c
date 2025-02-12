// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_ring_buffer
{
    size_t length;
    volatile size_t consumer_offset;
    volatile size_t producer_offset;
    volatile size_t producer_reserve_offset;
    uint8_t* shared_buffer;
    ebpf_ring_descriptor_t* ring_descriptor;
} ebpf_ring_buffer_t;

/**
 * @brief Raise the CPU's IRQL to DISPATCH_LEVEL if it is below DISPATCH_LEVEL.
 * First check if the IRQL is below DISPATCH_LEVEL to avoid the overhead of
 * calling KeRaiseIrqlToDpcLevel() if it is not needed.
 *
 * @return The previous IRQL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_ _IRQL_raises_(DISPATCH_LEVEL) static inline KIRQL
    _ring_raise_to_dispatch_if_needed()
{
    KIRQL old_irql = KeGetCurrentIrql();
    if (old_irql < DISPATCH_LEVEL) {
        old_irql = KeRaiseIrqlToDpcLevel();
    }
    return old_irql;
}

/**
 * @brief Lower the CPU's IRQL to the previous IRQL if previous level was below DISPATCH_LEVEL.
 * First check if the IRQL is below DISPATCH_LEVEL to avoid the overhead of
 * calling KeLowerIrql() if it is not needed.
 *
 * @param[in] previous_irql The previous IRQL.
 */
_IRQL_requires_(DISPATCH_LEVEL) static inline void _ring_lower_to_previous_irql(
    _When_(previous_irql < DISPATCH_LEVEL, _IRQL_restores_) KIRQL previous_irql)
{
    if (previous_irql < DISPATCH_LEVEL) {
        KeLowerIrql(previous_irql);
    }
}

inline static size_t
_ring_record_size(size_t data_size)
{
    return EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + data_size;
}

inline static size_t
_ring_padded_size(size_t size)
{
    return (size + 7) & ~7;
}

inline static size_t
_ring_record_total_size(_In_ const ebpf_ring_buffer_record_t* record)
{
    return _ring_padded_size(_ring_record_size(ebpf_ring_buffer_record_length(record)));
}

inline static uint32_t
_ring_header_length(_In_ uint32_t header)
{
    return header & ~(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT);
}

inline static bool
_ring_header_locked(_In_ uint32_t header)
{
    return (header & EBPF_RINGBUF_LOCK_BIT) != 0;
}

inline static bool
_ring_header_discarded(_In_ uint32_t header)
{
    return (header & EBPF_RINGBUF_DISCARD_BIT) != 0;
}

inline static void
_ring_record_initialize(_Inout_ ebpf_ring_buffer_record_t* record, size_t length)
{
    record->header.page_offset = 0; // unused for now.
    WriteUInt32NoFence(&record->header.length, (uint32_t)length | EBPF_RINGBUF_LOCK_BIT);
}

inline static void
_ring_record_finalize(_Inout_ ebpf_ring_buffer_record_t* record)
{
    MemoryBarrier(); // Ensure all writes to the record are completed before unlocking it.
    uint32_t new_length = _ring_header_length(ReadUInt32Acquire(&record->header.length));
    WriteUInt32NoFence(&record->header.length, new_length);
}

inline static void
_ring_record_discard(_Inout_ ebpf_ring_buffer_record_t* record)
{
    uint32_t new_length = record->header.length & ~EBPF_RINGBUF_LOCK_BIT;
    new_length |= EBPF_RINGBUF_DISCARD_BIT;
    WriteUInt32NoFence(&record->header.length, new_length);
}

inline static size_t
_ring_get_length(_In_ const ebpf_ring_buffer_t* ring)
{
    return ring->length;
}

inline static size_t
_ring_get_producer_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64Acquire(&ring->producer_offset) % ring->length;
}

inline static size_t
_ring_get_consumer_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return ReadULong64Acquire(&ring->consumer_offset) % ring->length;
}

inline static size_t
_ring_get_used_capacity(_In_ const ebpf_ring_buffer_t* ring)
{
    size_t consumer_offset = ReadULong64Acquire(&ring->consumer_offset);
    size_t producer_offset = ReadULong64Acquire(&ring->producer_offset);
    return producer_offset - consumer_offset;
}

inline static void
_ring_advance_producer_offset(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    size_t new_producer_offset = ReadULong64Acquire(&ring->producer_offset) + length;
    WriteULong64Release(&ring->producer_offset, new_producer_offset);
}

inline static void
_ring_advance_consumer_offset(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    size_t new_consumer_offset = ReadULong64Acquire(&ring->consumer_offset) + length;
    WriteULong64NoFence(&ring->consumer_offset, new_consumer_offset);
}

inline static _Ret_notnull_ ebpf_ring_buffer_record_t*
_ring_record_at_offset(_In_ const ebpf_ring_buffer_t* ring, size_t offset)
{
    return (ebpf_ring_buffer_record_t*)&ring->shared_buffer[offset % ring->length];
}

inline static _Ret_maybenull_ ebpf_ring_buffer_record_t*
_ring_next_consumer_record(_In_ ebpf_ring_buffer_t* ring)
{
    size_t consumer_offset = ReadULong64Acquire(&ring->consumer_offset);
    if (consumer_offset == ReadULong64Acquire(&ring->producer_offset)) {
        return NULL;
    }
    ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, consumer_offset);
    uint32_t record_header = ReadUInt32Acquire(&record->header.length);
    while (!_ring_header_locked(record_header)) {
        if (!_ring_header_discarded(record_header)) {
            return record;
        }
        size_t record_length = _ring_header_length(record_header);
        size_t total_record_size = _ring_padded_size(_ring_record_size(record_length));
        consumer_offset += total_record_size;
        size_t producer_offset = ReadULong64Acquire(&ring->producer_offset);
        WriteULong64NoFence(&ring->consumer_offset, consumer_offset);
        if (consumer_offset >= producer_offset) {
            return NULL;
        }
        record = _ring_record_at_offset(ring, consumer_offset);
        record_header = ReadUInt32Acquire(&record->header.length);
    }
    return NULL;
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

    if ((capacity & ~(capacity - 1)) != capacity) {
        result = EBPF_INVALID_ARGUMENT;
        goto Error;
    }

    local_ring_buffer->length = capacity;

    local_ring_buffer->ring_descriptor = ebpf_allocate_ring_buffer_memory(capacity);
    if (!local_ring_buffer->ring_descriptor) {
        result = EBPF_NO_MEMORY;
        goto Error;
    }
    local_ring_buffer->shared_buffer = ebpf_ring_descriptor_get_base_address(local_ring_buffer->ring_descriptor);

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
ebpf_ring_buffer_output(_Inout_ ebpf_ring_buffer_t* ring, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    uint8_t* record_data;
    ebpf_result_t result = ebpf_ring_buffer_reserve(ring, &record_data, length);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    memcpy(record_data, data, length);
    return ebpf_ring_buffer_submit(record_data);
}

void
ebpf_ring_buffer_query(_In_ ebpf_ring_buffer_t* ring, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    *consumer = ReadULong64Acquire(&ring->consumer_offset);
    *producer = ReadULong64Acquire(&ring->producer_offset);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_return(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    size_t local_length = length;
    size_t consumer_offset = ring->consumer_offset;

    if ((length > _ring_get_length(ring)) || length > _ring_get_used_capacity(ring)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_ring_buffer_return: Buffer too large",
            ring->producer_offset,
            ring->consumer_offset);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Verify count.
    while (local_length != 0) {
        ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, consumer_offset);
        uint32_t record_header = ReadUInt32Acquire(&record->header.length);
        size_t record_length = _ring_header_length(record_header);
        size_t total_record_size = _ring_padded_size(_ring_record_size(record_length));
        if (local_length < record_length) {
            break;
        }
        consumer_offset += total_record_size;
        local_length -= record_length;
    }
    // Did it end on a record boundary?
    if (local_length != 0) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_ring_buffer_return: Invalid buffer length",
            local_length);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    WriteULong64NoFence(&ring->consumer_offset, consumer_offset);
    result = EBPF_SUCCESS;

Done:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_map_buffer(_In_ const ebpf_ring_buffer_t* ring, _Outptr_ uint8_t** buffer)
{
    *buffer = ebpf_ring_map_readonly_user(ring->ring_descriptor);
    if (!*buffer) {
        return EBPF_INVALID_ARGUMENT;
    } else {
        return EBPF_SUCCESS;
    }
}

const ebpf_ring_buffer_record_t*
ebpf_ring_buffer_next_consumer_record(_Inout_ ebpf_ring_buffer_t* ring_buffer, _In_ const uint8_t* buffer)
{
    ebpf_ring_buffer_record_t* record = _ring_next_consumer_record(ring_buffer);
    if (record) {
        return (ebpf_ring_buffer_record_t*)(buffer + ((uint8_t*)record - ring_buffer->shared_buffer));
    } else {
        return NULL;
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve(
    _Inout_ ebpf_ring_buffer_t* ring, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length)
{

    //  Reservation loop:
    //  - No fairness guarantee, but does guarantee progress on each race/collision
    //  - Still needs to run at dispatch (or if all threads were passive you could yield in the spin loop)
    //  - All but one of the Read/Write ops could be NoFence
    //    - with NoFence possible extra spinning or failing when nearly full (and maybe worse fairness?)
    //  - Synchronization:
    //    - CompareExchange serializes allocation (using producer_reserve_offset)
    //    - spin loop serializes offset updates between producers (ensure previous allocations are locked)
    //    - producer_offset WriteRelease serializes lock and offset update (lock before offset update)
    if (length > ring->length || length == 0 || length > UINT32_MAX) {
        return EBPF_INVALID_ARGUMENT;
    } else if (_ring_get_used_capacity(ring) + length > ring->length) {
        return EBPF_NO_MEMORY;
    }
    ebpf_result_t result = EBPF_SUCCESS;
    size_t record_size = _ring_record_size(length);
    size_t padded_record_size = _ring_padded_size(record_size);

    KIRQL irql_at_enter = _ring_raise_to_dispatch_if_needed();
    for (;;) {
        size_t consumer_offset =
            ReadULong64Acquire(&ring->consumer_offset); // could be NoFence (possible fail on nearly-full ringbuf)
        size_t _prod = ReadULong64Acquire(&ring->producer_reserve_offset); // could be NoFence (possible extra looping)
        size_t _new_prod = _prod + padded_record_size;
        if (_new_prod - consumer_offset >= ring->length) {
            result = EBPF_NO_MEMORY; // Not enough space for record
            goto Done;
        } else if (
            _prod == (uint64_t)ebpf_interlocked_compare_exchange_int64(
                         (volatile int64_t*)&ring->producer_reserve_offset, _new_prod, _prod)) {
            // We successfully allocated the space -- now we need to lock the record and (then) update producer offset

            ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, _prod);
            _ring_record_initialize(record, (uint32_t)length);

            // There may be multiple producers that all advanced the producer reserve offset but haven't set the locked
            // flag yet.
            // - Need to guarantee that any reserved record behind producer_offset is locked before consumer sees it
            // - Only advances producer offset once the producer_offset matches the producer_reserve_offset we
            // originally got
            //   - Guarantees any records allocated before us are locked before we update offset
            while (_prod != ReadULong64Acquire(&ring->producer_offset)) { // could be NoFence (possible extra spins)
                // we shouldn't have to spin long
            }
            WriteULong64Release(
                &ring->producer_offset, _new_prod); // Must be Release to ensure ordering with setting the lock bit.
            *data = record->data;
            goto Done; // we have successfully reserved record, now can write+submit/discard
        } // else we lost the race and try again (but another process suceeded)
    }
Done:
    _ring_lower_to_previous_irql(irql_at_enter);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_submit(_Frees_ptr_opt_ uint8_t* data)
{
    if (!data) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_ring_buffer_record_t* record =
        (ebpf_ring_buffer_record_t*)(data - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    _ring_record_finalize(record);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_discard(_Frees_ptr_opt_ uint8_t* data)
{
    if (!data) {
        return EBPF_INVALID_ARGUMENT;
    }
    ebpf_ring_buffer_record_t* record =
        (ebpf_ring_buffer_record_t*)(data - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    _ring_record_discard(record);
    return EBPF_SUCCESS;
}
