// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_perf_event_array.h"
#include "ebpf_perf_event_array_record.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"
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
    size_t lost_records;
    uint64_t pad;
} ebpf_perf_ring_t;
typedef struct _ebpf_perf_event_array
{
    uint32_t ring_count;
    uint32_t pad1;
    uint64_t pad2[7];
    ebpf_perf_ring_t rings[1];
} ebpf_perf_event_array_t;

static_assert(sizeof(ebpf_perf_ring_t) % EBPF_CACHE_LINE_SIZE == 0, "ebpf_perf_ring_t is not cache aligned.");
static_assert(
    sizeof(ebpf_perf_event_array_t) % EBPF_CACHE_LINE_SIZE == 0, "ebpf_perf_event_array_t is not cache aligned.");

inline static size_t
_perf_array_record_size(size_t data_size)
{
    return EBPF_OFFSET_OF(ebpf_perf_event_array_record_t, data) + data_size;
}

inline static size_t
_perf_array_padded_size(size_t size)
{
    return (size + 7) & ~7;
}

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
    requested_length = _perf_array_record_size(requested_length);
    size_t padded_length = _perf_array_padded_size(requested_length);
    ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    size_t remaining_space = ring->length - (ring->producer_offset - ring->consumer_offset);

    if (remaining_space > padded_length) {
        record = _perf_array_record_at_offset(
            perf_event_array, cpu_id, _perf_array_get_producer_offset(perf_event_array, cpu_id));
        _perf_array_advance_producer_offset(perf_event_array, cpu_id, padded_length);
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
    uint32_t ring_count = ebpf_get_cpu_count();
    size_t total_size = sizeof(ebpf_perf_event_array_t) + sizeof(ebpf_perf_ring_t) * (ring_count - 1);

    local_perf_event_array = ebpf_epoch_allocate_with_tag(total_size, EBPF_POOL_TAG_RING_BUFFER);
    if (!local_perf_event_array) {
        result = EBPF_NO_MEMORY;
        goto Error;
    }
    local_perf_event_array->ring_count = ring_count;

    for (uint32_t i = 0; i < ring_count; i++) {
        ebpf_perf_ring_t* ring = &local_perf_event_array->rings[i];
        ring->length = capacity;
        ring->lost_records = 0;

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
        for (uint32_t i = 0; i < ring_count; i++) {
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
        uint32_t ring_count = perf_event_array->ring_count;
        for (uint32_t i = 0; i < ring_count; i++) {
            ebpf_free_ring_buffer_memory(perf_event_array->rings[i].ring_descriptor);
        }
        ebpf_epoch_free(perf_event_array);
        EBPF_RETURN_VOID();
    }
}

_Must_inspect_result_ ebpf_result_t
_ebpf_perf_event_array_output(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t cpu_id,
    _In_reads_bytes_(length) const uint8_t* data,
    size_t length,
    _In_reads_bytes_(extra_length) const uint8_t* extra_data,
    size_t extra_length)
{
    ebpf_assert(cpu_id < perf_event_array->ring_count);

    ebpf_lock_state_t state = ebpf_lock_lock(&perf_event_array->rings[cpu_id].lock);
    ebpf_perf_event_array_record_t* record =
        _perf_event_array_acquire_record(perf_event_array, cpu_id, length + extra_length);
    ebpf_result_t result = EBPF_SUCCESS;

    if (record == NULL) {
        result = EBPF_OUT_OF_SPACE;
        perf_event_array->rings[cpu_id].lost_records++;
        goto Done;
    }

    record->header.discarded = 0;
    record->header.locked = 0;
    memcpy(record->data, data, length);
    if (extra_data != NULL) {
        memcpy(record->data + length, extra_data, extra_length);
    }
    result = EBPF_SUCCESS;

Done:
    ebpf_lock_unlock(&perf_event_array->rings[cpu_id].lock, state);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output_simple(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t cpu_id,
    _In_reads_bytes_(length) uint8_t* data,
    size_t length)
{
    if (cpu_id == (uint32_t)EBPF_MAP_FLAG_CURRENT_CPU) {
        cpu_id = ebpf_get_current_cpu();
    }
    return _ebpf_perf_event_array_output(perf_event_array, cpu_id, data, length, NULL, 0);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _In_ void* ctx,
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint64_t flags,
    _In_reads_bytes_(length) uint8_t* data,
    size_t length,
    _Out_opt_ uint32_t* cpu_id)
{
    // UNREFERENCED_PARAMETER(ctx);
    // ebpf_result_t result;
    uint32_t _cpu_id = (flags & EBPF_MAP_FLAG_INDEX_MASK) >> EBPF_MAP_FLAG_INDEX_SHIFT;
    uint32_t capture_length = (uint32_t)((flags & EBPF_MAP_FLAG_CTXLEN_MASK) >> EBPF_MAP_FLAG_CTXLEN_SHIFT);
    uint32_t current_cpu = ebpf_get_current_cpu();
    const void* extra_data = NULL;
    size_t extra_length = 0;

    if (_cpu_id == EBPF_MAP_FLAG_CURRENT_CPU) {
        _cpu_id = current_cpu;
        if (cpu_id != NULL) {
            *cpu_id = _cpu_id;
        }
    } else if (_cpu_id != current_cpu) {
        // We only support writes to the current CPU.
        return EBPF_INVALID_ARGUMENT;
    } else if (cpu_id != NULL) {
        *cpu_id = _cpu_id;
    }

    if (capture_length != 0) {
        // Caller requested data capture.
        ebpf_assert(ctx != NULL);

        uint8_t *ctx_data_start, *ctx_data_end;
        ebpf_program_get_context_data(ctx, &ctx_data_start, &ctx_data_end);

        if (ctx_data_start == NULL || ctx_data_end == NULL) {
            // No context data pointer.
            return EBPF_OPERATION_NOT_SUPPORTED;
        } else if ((uint64_t)(ctx_data_end - ctx_data_start) < (uint64_t)capture_length) {
            // Requested capture length larger than data.
            return EBPF_INVALID_ARGUMENT;
        }

        extra_data = ctx_data_start;
        extra_length = capture_length;
    }

    return _ebpf_perf_event_array_output(perf_event_array, _cpu_id, data, length, extra_data, extra_length);
}

uint32_t
ebpf_perf_event_array_get_ring_count(_In_ const ebpf_perf_event_array_t* perf_event_array)
{
    return perf_event_array->ring_count;
}

size_t
ebpf_perf_event_array_get_reset_lost_count(_In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    ebpf_lock_state_t state = ebpf_lock_lock(&ring->lock);
    size_t lost_count = ring->lost_records;
    ring->lost_records = 0;
    ebpf_lock_unlock(&ring->lock, state);
    return lost_count;
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
    length = _perf_array_padded_size(length);

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
        size_t padded_record_length = _perf_array_padded_size(record->header.length);
        if (local_length < padded_record_length) {
            break;
        }
        offset += padded_record_length;
        local_length -= padded_record_length;
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