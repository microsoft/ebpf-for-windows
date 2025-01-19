// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_perf_event_array.h"
#include "ebpf_perf_event_array_record.h"
#include "ebpf_platform.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_perf_ring
{
    ebpf_lock_t lock;
    size_t length;
    size_t consumer_offset;
    size_t producer_offset;
    uint8_t* shared_buffer;
    ebpf_ring_descriptor_t* ring_descriptor;
} ebpf_perf_ring_t;
typedef struct _ebpf_perf_event_array
{
    ebpf_perf_ring_t rings[];
} ebpf_perf_event_array_t;

inline static size_t
_perf_array_get_length(_In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    return perf_event_array->rings[cpu_id].length;
}

inline static size_t
_perf_array_get_producer_offset(_In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    const ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    return ring->producer_offset % ring->length;
}

inline static size_t
_perf_array_get_consumer_offset(_In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    const ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    return ring->consumer_offset % ring->length;
}

inline static size_t
_perf_array_get_used_capacity(_In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    const ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    ebpf_assert(ring->producer_offset >= ring->consumer_offset);
    return ring->producer_offset - ring->consumer_offset;
}

inline static void
_perf_array_advance_producer_offset(_Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t length)
{
    perf_event_array->rings[cpu_id].producer_offset += length;
}

inline static void
_perf_array_advance_consumer_offset(_Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t length)
{
    perf_event_array->rings[cpu_id].consumer_offset += length;
}

inline static _Ret_notnull_ ebpf_perf_event_array_record_t*
_perf_array_record_at_offset(_In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t offset)
{
    ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    return (ebpf_perf_event_array_record_t*)&ring->shared_buffer[offset % ring->length];
}

inline static _Ret_notnull_ ebpf_perf_event_array_record_t*
_perf_array_next_consumer_record(_In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    return _perf_array_record_at_offset(
        perf_event_array, cpu_id, _perf_array_get_consumer_offset(perf_event_array, cpu_id));
}

inline static _Ret_maybenull_ ebpf_perf_event_array_record_t*
_perf_event_array_acquire_record(
    _Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t requested_length)
{
    ebpf_perf_event_array_record_t* record = NULL;
    requested_length += EBPF_OFFSET_OF(ebpf_perf_event_array_record_t, data);
    ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    size_t remaining_space = ring->length - (ring->producer_offset - ring->consumer_offset);

    if (remaining_space > requested_length) {
        record = _perf_array_record_at_offset(
            perf_event_array, cpu_id, _perf_array_get_producer_offset(perf_event_array, cpu_id));
        _perf_array_advance_producer_offset(perf_event_array, cpu_id, requested_length);
        record->header.length = (uint32_t)requested_length;
        record->header.locked = 1;
        record->header.discarded = 0;
    }
    return record;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_create(
    _Outptr_ ebpf_perf_event_array_t** perf_event_array, size_t capacity, _In_ ebpf_perf_event_array_opts_t* opts)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(opts);
    ebpf_result_t result;
    ebpf_perf_event_array_t* local_perf_event_array = NULL;
    uint32_t cpu_count = ebpf_get_cpu_count();
    size_t total_size = sizeof(ebpf_perf_event_array_t) + sizeof(ebpf_perf_ring_t) * cpu_count;

    local_perf_event_array = ebpf_epoch_allocate_with_tag(total_size, EBPF_POOL_TAG_RING_BUFFER);
    if (!local_perf_event_array) {
        result = EBPF_NO_MEMORY;
        goto Error;
    }

    for (uint32_t i = 0; i < cpu_count; i++) {
        ebpf_perf_ring_t* ring = &local_perf_event_array->rings[i];
        ring->length = capacity;

        ring->ring_descriptor = ebpf_allocate_ring_buffer_memory(capacity);
        if (!ring->ring_descriptor) {
            result = EBPF_NO_MEMORY;
            goto Error;
        }
        ring->shared_buffer = ebpf_ring_descriptor_get_base_address(ring->ring_descriptor);
    }

    *perf_event_array = local_perf_event_array;
    local_perf_event_array = NULL;
    return EBPF_SUCCESS;

Error:
    if (local_perf_event_array) {
        for (uint32_t i = 0; i < cpu_count; i++) {
            if (local_perf_event_array->rings[i].ring_descriptor) {
                ebpf_free_ring_buffer_memory(local_perf_event_array->rings[i].ring_descriptor);
            }
        }
        ebpf_epoch_free(local_perf_event_array);
    }
    EBPF_RETURN_RESULT(result);
}

void
ebpf_perf_event_array_destroy(_Frees_ptr_opt_ ebpf_perf_event_array_t* perf_event_array)
{
    if (perf_event_array) {
        EBPF_LOG_ENTRY();
        uint32_t cpu_count = ebpf_get_cpu_count();
        for (uint32_t i = 0; i < cpu_count; i++) {
            ebpf_free_ring_buffer_memory(perf_event_array->rings[i].ring_descriptor);
        }
        ebpf_epoch_free(perf_event_array);
        EBPF_RETURN_VOID();
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _Inout_ void* ctx,
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint64_t flags,
    _In_reads_bytes_(length) uint8_t* data,
    size_t length)
{
    UNREFERENCED_PARAMETER(ctx);
    ebpf_result_t result;
    uint32_t cpu_id = flags & EBPF_MAP_FLAG_INDEX_MASK;
    // size_t capture_length = (flags & EBPF_MAP_FLAG_CTXLEN_MASK) >> 32;

    uint32_t current_cpu = ebpf_get_current_cpu();
    if (cpu_id == EBPF_MAP_FLAG_CURRENT_CPU) {
        cpu_id = current_cpu;
        //} else if (cpu_id != current_cpu) { // Disabled for initial testing
        //    return EBPF_INVALID_ARGUMENT;
    }

    ebpf_lock_state_t state = ebpf_lock_lock(&perf_event_array->rings[cpu_id].lock);
    ebpf_perf_event_array_record_t* record = _perf_event_array_acquire_record(perf_event_array, cpu_id, length);

    if (record == NULL) {
        result = EBPF_OUT_OF_SPACE;
        goto Done;
    }

    record->header.discarded = 0;
    record->header.locked = 0;
    memcpy(record->data, data, length);
    result = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&perf_event_array->rings[cpu_id].lock, state);
    return result;
}

void
ebpf_perf_event_array_query(
    _In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    ebpf_lock_state_t state = ebpf_lock_lock(&ring->lock);
    *consumer = ring->consumer_offset;
    *producer = ring->producer_offset;
    ebpf_lock_unlock(&ring->lock, state);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_return(_Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    ebpf_lock_state_t state = ebpf_lock_lock(&ring->lock);
    size_t local_length = length;
    size_t offset = _perf_array_get_consumer_offset(perf_event_array, cpu_id);

    if ((length > _perf_array_get_length(perf_event_array, cpu_id)) ||
        length > _perf_array_get_used_capacity(perf_event_array, cpu_id)) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_perf_event_array_return: Buffer too large",
            ring->producer_offset,
            ring->consumer_offset);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Verify count.
    while (local_length != 0) {
        ebpf_perf_event_array_record_t* record = _perf_array_record_at_offset(perf_event_array, cpu_id, offset);
        if (local_length < record->header.length) {
            break;
        }
        offset += record->header.length;
        local_length -= record->header.length;
    }
    // Did it end on a record boundary?
    if (local_length != 0) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_MAP,
            "ebpf_perf_event_array_return: Invalid buffer length",
            local_length);
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    _perf_array_advance_consumer_offset(perf_event_array, cpu_id, length);
    result = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&ring->lock, state);
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_buffer(
    _In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Outptr_ uint8_t** buffer)
{
    const ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    *buffer = ebpf_ring_map_readonly_user(ring->ring_descriptor);
    if (!*buffer) {
        return EBPF_INVALID_ARGUMENT;
    } else {
        return EBPF_SUCCESS;
    }
}