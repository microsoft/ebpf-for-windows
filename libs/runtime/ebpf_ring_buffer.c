// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_ring_buffer
{
    int64_t length;
    int64_t mask;
    cxplat_spin_lock_t producer_lock;
    cxplat_spin_lock_t consumer_lock;
    volatile int64_t consumer_offset;
    volatile int64_t producer_offset;
    uint8_t* shared_buffer;
    ebpf_ring_descriptor_t* ring_descriptor;
} ebpf_ring_buffer_t;

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
    local_ring_buffer->mask = capacity - 1;

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
    uint8_t* buffer;

    result = ebpf_ring_buffer_reserve(ring, &buffer, length);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    memcpy(buffer, data, length);

    return ebpf_ring_buffer_submit(buffer);
}

void
ebpf_ring_buffer_query(_In_ ebpf_ring_buffer_t* ring, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    *consumer = (size_t)ReadAcquire64(&ring->consumer_offset);
    *producer = (size_t)ReadAcquire64(&ring->producer_offset);
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_return(_Inout_ ebpf_ring_buffer_t* ring, size_t length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    KIRQL old_irql = KeGetCurrentIrql();
    if (old_irql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    cxplat_acquire_spin_lock_at_dpc_level(&ring->consumer_lock);

    int64_t consumer_offset = ReadNoFence64(&ring->consumer_offset);
    int64_t producer_offset = ReadNoFence64(&ring->producer_offset);
    int64_t effective_length = EBPF_PAD_8(length + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));

    if (consumer_offset == producer_offset) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    int64_t remaining_space = producer_offset - consumer_offset;

    if (remaining_space > effective_length) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    remaining_space = effective_length;

    while (remaining_space > 0) {
        ebpf_ring_buffer_record_t* record =
            (ebpf_ring_buffer_record_t*)(ring->shared_buffer + (consumer_offset & ring->mask));

        long size = ReadNoFence(&record->size);
        size += EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data);
        size = EBPF_PAD_8(size);

        consumer_offset += size;
        remaining_space -= size;

        record->size = 0;
    }

    WriteNoFence64(&ring->consumer_offset, consumer_offset);

    result = EBPF_SUCCESS;

Exit:
    cxplat_release_spin_lock_from_dpc_level(&ring->consumer_lock);

    if (old_irql < DISPATCH_LEVEL) {
        KeLowerIrql(old_irql);
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
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
    KIRQL old_irql;
    int64_t producer_offset = ReadNoFence64(&ring->producer_offset);
    int64_t consumer_offset = ReadNoFence64(&ring->consumer_offset);
    int64_t remaining_space = ring->length - (producer_offset - consumer_offset);
    size_t effective_length = EBPF_PAD_8(length + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));

    if (remaining_space < (int64_t)effective_length) {
        return EBPF_NO_MEMORY;
    }

    old_irql = KeGetCurrentIrql();
    if (old_irql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    cxplat_acquire_spin_lock_at_dpc_level(&ring->producer_lock);

    producer_offset = ReadNoFence64(&ring->producer_offset);
    consumer_offset = ReadNoFence64(&ring->consumer_offset);

    remaining_space = ring->length - (producer_offset - consumer_offset);

    if (remaining_space < (int64_t)effective_length) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    ebpf_ring_buffer_record_t* record =
        (ebpf_ring_buffer_record_t*)(ring->shared_buffer + (producer_offset & ring->mask));

    WriteNoFence(&record->size, (long)length | EBPF_RING_BUFFER_RECORD_FLAG_LOCKED);
    *data = record->data;

    WriteNoFence64(&ring->producer_offset, producer_offset + effective_length);

    result = EBPF_SUCCESS;

Exit:
    cxplat_release_spin_lock_from_dpc_level(&ring->producer_lock);

    if (old_irql < DISPATCH_LEVEL) {
        KeLowerIrql(old_irql);
    }

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_submit(_Frees_ptr_opt_ uint8_t* data)
{
    ebpf_ring_buffer_record_t* record = CONTAINING_RECORD(data, ebpf_ring_buffer_record_t, data);
    long size = ReadAcquire(&record->size);

    if (!(size & EBPF_RING_BUFFER_RECORD_FLAG_LOCKED)) {
        return EBPF_INVALID_ARGUMENT;
    }

    size &= ~EBPF_RING_BUFFER_RECORD_FLAG_LOCKED;

    WriteRelease(&record->size, size);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_ring_buffer_discard(_Frees_ptr_opt_ uint8_t* data)
{
    ebpf_ring_buffer_record_t* record = CONTAINING_RECORD(data, ebpf_ring_buffer_record_t, data);
    long size = ReadAcquire(&record->size);

    if (!(size & EBPF_RING_BUFFER_RECORD_FLAG_LOCKED)) {
        return EBPF_INVALID_ARGUMENT;
    }

    size &= ~EBPF_RING_BUFFER_RECORD_FLAG_LOCKED;
    size |= EBPF_RING_BUFFER_RECORD_FLAG_DISCARDED;

    WriteRelease(&record->size, size);
    return EBPF_SUCCESS;
}
