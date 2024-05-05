// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once
#include "cxplat.h"

CXPLAT_EXTERN_C_BEGIN

typedef struct _ebpf_ring_buffer_record
{
    struct
    {
        uint8_t locked : 1;
        uint8_t discarded : 1;
        uint32_t length : 30;
    } header;
    uint8_t data[1];
} ebpf_ring_buffer_record_t;

/**
 * @brief Locate the next record in the ring buffer's data buffer and
 * advance consumer offset.
 *
 * @param[in] buffer Pointer to the start of the ring buffer's data buffer.
 * @param[in] buffer_length Length of the ring buffer's data buffer.
 * @param[in] consumer Consumer offset.
 * @param[in] producer Producer offset.
 * @return Pointer to the next record or NULL if no more records.
 */
inline const ebpf_ring_buffer_record_t*
ebpf_ring_buffer_next_record(_In_ const uint8_t* buffer, size_t buffer_length, size_t consumer, size_t producer)
{
    ebpf_assert(producer >= consumer);
    if (producer == consumer) {
        return NULL;
    }
    return (ebpf_ring_buffer_record_t*)(buffer + consumer % buffer_length);
}

CXPLAT_EXTERN_C_END
