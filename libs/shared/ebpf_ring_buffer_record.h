// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once
#include "cxplat.h"

CXPLAT_EXTERN_C_BEGIN

#define EBPF_RINGBUF_LOCK_BIT (1U << 31)
#define EBPF_RINGBUF_DISCARD_BIT (1U << 30)

typedef struct _ebpf_ring_buffer_record
{
    struct
    {
        uint32_t length;
        uint32_t page_offset;
    } header;
    uint8_t data[1];
} ebpf_ring_buffer_record_t;

/**
 * @brief Determine if the record is locked.
 *
 * If the record is not locked then the discard bit and length can be read.
 *
 * @param[in] record Pointer to the record.
 * @return True if the record is locked.
 */
inline const bool
ebpf_ring_buffer_record_is_locked(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (ReadUInt32Acquire(&record->header.length) & EBPF_RINGBUF_LOCK_BIT) != 0;
}

/**
 * @brief Determine if the record is discarded (only valid if unlocked).
 *
 * If the record is discarded then length+header bytes are returned.
 * If the record is not discarded then length bytes are available for reading.
 *
 * @param[in] record Pointer to the record.
 * @return True if the record is discarded.
 */
inline const bool
ebpf_ring_buffer_record_is_discarded(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (ReadUInt32NoFence(&record->header.length) & EBPF_RINGBUF_DISCARD_BIT) != 0;
}

/**
 * @brief Get the length of the record.
 *
 * Excludes the lock and discard bits.
 *
 * @param[in] record Pointer to the record.
 * @return Length of the record.
 */
inline const uint32_t
ebpf_ring_buffer_record_length(_In_ const ebpf_ring_buffer_record_t* record)
{
    return ReadUInt32NoFence(&record->header.length) & ~(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT);
}

inline const uint32_t
ebpf_ring_buffer_record_total_size(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (ebpf_ring_buffer_record_length(record) + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + 7) & ~7;
}

/**
 * @brief Locate the next record in the ring buffer's data buffer.
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
