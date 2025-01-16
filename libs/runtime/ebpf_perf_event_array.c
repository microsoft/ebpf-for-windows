// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_epoch.h"
#include "ebpf_perf_event_array.h"
#include "ebpf_perf_event_array_record.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_ring_buffer_record.h"
#include "ebpf_tracelog.h"

// TODO: we need an array of rings (and the associated fields)
typedef struct _ebpf_perf_event_array
{
    ebpf_lock_t lock;
    size_t length;
    size_t consumer_offset;
    size_t producer_offset;
    uint8_t* shared_buffer;
    ebpf_ring_descriptor_t* ring_descriptor;
} ebpf_perf_event_array_t;

inline static size_t
_perfbuf_get_length(_In_ const ebpf_perf_event_array_t* perfbuf)
{
    return perfbuf->length;
}

inline static size_t
_perfbuf_get_producer_offset(_In_ const ebpf_perf_event_array_t* perfbuf)
{
    return perfbuf->producer_offset % perfbuf->length;
}

inline static size_t
_perfbuf_get_consumer_offset(_In_ const ebpf_perf_event_array_t* perfbuf)
{
    return perfbuf->consumer_offset % perfbuf->length;
}

inline static size_t
_perfbuf_get_used_capacity(_In_ const ebpf_perf_event_array_t* perfbuf)
{
    ebpf_assert(perfbuf->producer_offset >= perfbuf->consumer_offset);
    return perfbuf->producer_offset - perfbuf->consumer_offset;
}

inline static void
_perfbuf_advance_producer_offset(_Inout_ ebpf_perf_event_array_t* perfbuf, size_t length)
{
    perfbuf->producer_offset += length;
}

inline static void
_perfbuf_advance_consumer_offset(_Inout_ ebpf_perf_event_array_t* perfbuf, size_t length)
{
    perfbuf->consumer_offset += length;
}

inline static _Ret_notnull_ ebpf_perf_event_array_record_t*
_perfbuf_record_at_offset(_In_ const ebpf_perf_event_array_t* perfbuf, size_t offset)
{
    return (ebpf_perf_event_array_record_t*)&perfbuf->shared_buffer[offset % perfbuf->length];
}

inline static _Ret_notnull_ ebpf_perf_event_array_record_t*
_perfbuf_next_consumer_record(_In_ const ebpf_perf_event_array_t* perfbuf)
{
    return _perfbuf_record_at_offset(perfbuf, _perfbuf_get_consumer_offset(perfbuf));
}

inline static _Ret_maybenull_ ebpf_perf_event_array_record_t*
_perf_event_array_acquire_record(_Inout_ ebpf_perf_event_array_t* perfbuf, uint32_t cpu, size_t requested_length)
{
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(requested_length);
    ebpf_perf_event_array_record_t* record = NULL;
    return record;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_create(_Outptr_ ebpf_perf_event_array_t** perfbuf, size_t capacity)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(capacity);
    EBPF_RETURN_RESULT(EBPF_OPERATION_NOT_SUPPORTED);
}

void
ebpf_perf_event_array_destroy(_Frees_ptr_opt_ ebpf_perf_event_array_t* perfbuf)
{
    if (perfbuf) {
        EBPF_LOG_ENTRY();
        EBPF_RETURN_VOID();
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_output(
    _Inout_ ebpf_perf_event_array_t* perfbuf, uint32_t cpu, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(length);
    return EBPF_OPERATION_NOT_SUPPORTED;
}

void
ebpf_perf_event_array_query(
    _In_ ebpf_perf_event_array_t* perfbuf, uint32_t cpu, _Out_ size_t* consumer, _Out_ size_t* producer)
{
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(consumer);
    UNREFERENCED_PARAMETER(producer);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_return(_Inout_ ebpf_perf_event_array_t* perfbuf, uint32_t cpu, size_t length)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(length);
    EBPF_RETURN_RESULT(EBPF_OPERATION_NOT_SUPPORTED);
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_map_buffer(_In_ const ebpf_perf_event_array_t* perfbuf, uint32_t cpu, _Outptr_ uint8_t** buffer)
{
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(buffer);
    return EBPF_OPERATION_NOT_SUPPORTED;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_reserve(
    _Inout_ ebpf_perf_event_array_t* perfbuf,
    uint32_t cpu,
    _Outptr_result_bytebuffer_(length) uint8_t** data,
    size_t length)
{
    UNREFERENCED_PARAMETER(perfbuf);
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(buffer);
    return EBPF_OPERATION_NOT_SUPPORTED;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_submit(_Frees_ptr_opt_ uint8_t* data)
{
    if (!data) {
        return EBPF_INVALID_ARGUMENT;
    }
    return EBPF_OPERATION_NOT_SUPPORTED;
}

_Must_inspect_result_ ebpf_result_t
ebpf_perf_event_array_discard(_Frees_ptr_opt_ uint8_t* data)
{
    if (!data) {
        return EBPF_INVALID_ARGUMENT;
    }
    return EBPF_OPERATION_NOT_SUPPORTED;
}
