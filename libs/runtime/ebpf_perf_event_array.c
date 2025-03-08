// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_perf_event_array.h"
#include "ebpf_platform.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

typedef struct _ebpf_perf_ring
{
    ebpf_ring_buffer_t ring;
    volatile size_t lost_records;
    uint64_t flags;
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

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_create(
    _Outptr_ _On_failure_(_Maybenull_) ebpf_perf_event_array_t** perf_event_array,
    size_t capacity,
    _In_ ebpf_perf_event_array_opts_t* opts)
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
        goto Done;
    }
    local_perf_event_array->ring_count = ring_count;

    uint32_t cpu_i;
    for (cpu_i = 0; cpu_i < ring_count; cpu_i++) {
        ebpf_perf_ring_t* ring = &local_perf_event_array->rings[cpu_i];
        result = ebpf_ring_buffer_initialize_ring(&ring->ring, capacity);
        if (result != EBPF_SUCCESS) {
            // Failed to allocate ring, update ring count to ensure correct cleanup.
            local_perf_event_array->ring_count = cpu_i;
            goto Done;
        }
    }

    *perf_event_array = local_perf_event_array;
    local_perf_event_array = NULL;
    result = EBPF_SUCCESS;

Done:
    if (result != EBPF_SUCCESS) {
        ebpf_perf_event_array_destroy(local_perf_event_array);
    }
    EBPF_RETURN_RESULT(result);
}

void
ebpf_perf_event_array_destroy(_In_opt_ _Frees_ptr_opt_ ebpf_perf_event_array_t* perf_event_array)
{
    if (perf_event_array) {
        EBPF_LOG_ENTRY();
        uint32_t ring_count = perf_event_array->ring_count;
        for (uint32_t i = 0; i < ring_count; i++) {
            ebpf_ring_buffer_free_ring_memory(&perf_event_array->rings[i].ring);
        }
        ebpf_epoch_free(perf_event_array);
        EBPF_RETURN_VOID();
    }
}

_Must_inspect_result_ ebpf_result_t
_ebpf_perf_event_array_output(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t target_cpu,
    _In_reads_(length) const uint8_t* data,
    size_t length,
    _In_reads_(extra_length) const uint8_t* extra_data,
    size_t extra_length,
    _Out_opt_ uint32_t* cpu_id)
{

    KIRQL irql_at_enter = KeGetCurrentIrql();
    if (irql_at_enter < DISPATCH_LEVEL) {
        if (target_cpu != (uint32_t)EBPF_MAP_FLAG_CURRENT_CPU) {
            return EBPF_INVALID_ARGUMENT;
        }
        irql_at_enter = ebpf_raise_irql(DISPATCH_LEVEL);
    }

    ebpf_result_t result;
    uint32_t current_cpu = ebpf_get_current_cpu();

    uint32_t _cpu_id = target_cpu;
    if (target_cpu == (uint32_t)EBPF_MAP_FLAG_CURRENT_CPU) {
        _cpu_id = current_cpu;
    } else if (_cpu_id != current_cpu) {
        // We only support writes to the current CPU.
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (cpu_id != NULL) {
        *cpu_id = _cpu_id; // return the cpu we are writing to.
    }

    uint8_t* record;
    ebpf_perf_ring_t* ring = &perf_event_array->rings[_cpu_id];

    // We write to a per-cpu ring at dispatch, so can use the faster exclusive reserve function.
    result = ebpf_ring_buffer_reserve_exclusive(&ring->ring, &record, length + extra_length);
    if (result != EBPF_SUCCESS) {
        ring->lost_records++;
        goto Done;
    }
    memcpy(record, data, length);
    if (extra_data != NULL) {
        memcpy(record + length, extra_data, extra_length);
    }
    result = ebpf_ring_buffer_submit(record);

Done:
    ebpf_lower_irql_from_dispatch_if_needed(irql_at_enter);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output_simple(
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint32_t target_cpu,
    _In_reads_(length) uint8_t* data,
    size_t length,
    _Out_opt_ uint32_t* cpu_id)
{
    return _ebpf_perf_event_array_output(perf_event_array, target_cpu, data, length, NULL, 0, cpu_id);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _In_ void* ctx,
    _Inout_ ebpf_perf_event_array_t* perf_event_array,
    uint64_t flags,
    _In_reads_(length) uint8_t* data,
    size_t length,
    _Out_opt_ uint32_t* cpu_id)
{
    uint32_t _cpu_id = (flags & EBPF_MAP_FLAG_INDEX_MASK) >> EBPF_MAP_FLAG_INDEX_SHIFT;
    uint32_t capture_length = (uint32_t)((flags & EBPF_MAP_FLAG_CTXLEN_MASK) >> EBPF_MAP_FLAG_CTXLEN_SHIFT);

    const void* extra_data = NULL;
    size_t extra_length = 0;
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
    return _ebpf_perf_event_array_output(perf_event_array, _cpu_id, data, length, extra_data, extra_length, cpu_id);
}

uint32_t
ebpf_perf_event_array_get_ring_count(_In_ const ebpf_perf_event_array_t* perf_event_array)
{
    return perf_event_array->ring_count;
}

size_t
ebpf_perf_event_array_get_lost_count(_In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id)
{
    return perf_event_array->rings[cpu_id].lost_records;
}

void
ebpf_perf_event_array_query(
    _In_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    ebpf_ring_buffer_query(&perf_event_array->rings[cpu_id].ring, consumer, producer);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_return_buffer(
    _Inout_ ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, size_t consumer_offset)
{
    return ebpf_ring_buffer_return_buffer(&perf_event_array->rings[cpu_id].ring, consumer_offset);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_buffer(
    _In_ const ebpf_perf_event_array_t* perf_event_array, uint32_t cpu_id, _Outptr_ uint8_t** buffer)
{
    const ebpf_perf_ring_t* ring = &perf_event_array->rings[cpu_id];
    return ebpf_ring_buffer_map_buffer(&ring->ring, buffer);
}