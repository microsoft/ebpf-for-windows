// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_ring_buffer
{
    ebpf_lock_t lock;
    size_t length;
    size_t consumer_offset;
    size_t producer_offset;
    uint8_t* shared_buffer;
    ebpf_ring_descriptor_t* ring_descriptor;
} ebpf_ring_buffer_t;

inline static size_t
_ring_get_length(_In_ const ebpf_ring_buffer_t* ring)
{
    return ring->length;
}

inline static size_t
_ring_get_producer_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return ring->producer_offset % ring->length;
}

inline static size_t
_ring_get_consumer_offset(_In_ const ebpf_ring_buffer_t* ring)
{
    return ring->consumer_offset % ring->length;
}

inline static void
_ring_advance_producer_offset(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    ring->producer_offset += length;
}

inline static void
_ring_advance_consumer_offset(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    ring->consumer_offset += length;
}

inline static _Ret_notnull_ ebpf_ring_buffer_record_t*
_ring_record_at_offset(_In_ const ebpf_ring_buffer_t* ring, size_t offset)
{
    return (ebpf_ring_buffer_record_t*)&ring->shared_buffer[offset % ring->length];
}

inline static _Ret_notnull_ ebpf_ring_buffer_record_t*
_ring_next_consumer_record(_In_ const ebpf_ring_buffer_t* ring)
{
    return _ring_record_at_offset(ring, _ring_get_consumer_offset(ring));
}

inline static _Ret_maybenull_ ebpf_ring_buffer_record_t*
_ring_buffer_acquire_record(_Inout_ ebpf_ring_buffer_t* ring, size_t requested_length)
{
    ebpf_ring_buffer_record_t* record = NULL;
    requested_length += EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data);
    size_t remaining_space = ring->length - (ring->producer_offset - ring->consumer_offset);

    if (remaining_space > requested_length) {
        record = _ring_record_at_offset(ring, _ring_get_producer_offset(ring));
        _ring_advance_producer_offset(ring, requested_length);
        record->header.length = (uint32_t)requested_length;
        record->header.locked = 1;
        record->header.discarded = 0;
    }
    return record;
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
    ebpf_result_t result;
    ebpf_lock_state_t state = ebpf_lock_lock(&ring->lock);
    ebpf_ring_buffer_record_t* record = _ring_buffer_acquire_record(ring, length);

    if (record == NULL) {
        result = EBPF_OUT_OF_SPACE;
        goto Done;
    }

    record->header.discarded = 0;
    record->header.locked = 0;
    memcpy(record->data, data, length);
    result = EBPF_SUCCESS;
Done:
    ebpf_lock_unlock(&ring->lock, state);
    return result;
}

void
ebpf_ring_buffer_query(_In_ const ebpf_ring_buffer_t* ring, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    *consumer = ring->consumer_offset;
    *producer = ring->producer_offset;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_return(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    ebpf_result_t result;
    ebpf_lock_state_t state = ebpf_lock_lock(&ring->lock);
    size_t local_length = length;
    size_t offset = _ring_get_consumer_offset(ring);

    // Check if length is valid.
    if ((length > _ring_get_length(ring)) ||
        (length + _ring_get_consumer_offset(ring) > _ring_get_producer_offset(ring))) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Verify count.
    while (local_length != 0) {
        ebpf_ring_buffer_record_t* record = _ring_record_at_offset(ring, offset);
        if (local_length < record->header.length) {
            break;
        }
        offset += record->header.length;
        local_length -= record->header.length;
    }
    // Did it end on a record boundary?
    if (local_length != 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    _ring_advance_consumer_offset(ring, length);
    result = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&ring->lock, state);
    return result;
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

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_reserve(
    _Inout_ ebpf_ring_buffer_t* ring, _Outptr_result_bytebuffer_(length) uint8_t** data, size_t length)
{
    ebpf_result_t result;
    ebpf_lock_state_t state = ebpf_lock_lock(&ring->lock);
    ebpf_ring_buffer_record_t* record = _ring_buffer_acquire_record(ring, length);
    if (record == NULL) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    record->header.locked = 1;
    MemoryBarrier();

    *data = record->data;
    result = EBPF_SUCCESS;
Done:
    ebpf_lock_unlock(&ring->lock, state);
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

    record->header.discarded = 0;
    // Place a memory barrier here so that all prior writes to the record are completed before the record
    // is unlocked. Caller needs to ensure a MemoryBarrier between reading the record->header.locked and
    // the data in the record.
    MemoryBarrier();
    record->header.locked = 0;
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

    record->header.discarded = 1;
    // Place a memory barrier here so that all prior writes to the record are completed before the record
    // is unlocked. Caller needs to ensure a MemoryBarrier between reading the record->header.locked and
    // the data in the record.
    MemoryBarrier();
    record->header.locked = 0;
    return EBPF_SUCCESS;
}

const ebpf_ring_buffer_record_t*
ebpf_ring_buffer_next_record(_In_ const uint8_t* buffer, size_t buffer_length, size_t consumer, size_t producer)
{
    if (producer == consumer) {
        return NULL;
    }
    return (ebpf_ring_buffer_record_t*)(buffer + consumer % buffer_length);
}
