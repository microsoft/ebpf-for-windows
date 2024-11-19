// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once
#include "cxplat.h"

CXPLAT_EXTERN_C_BEGIN

#define EBPF_RING_BUFFER_RECORD_FLAG_LOCKED_OFFSET 31
#define EBPF_RING_BUFFER_RECORD_FLAG_DISCARDED_OFFSET 30
#define EBPF_RING_BUFFER_RECORD_FLAG_LOCKED (long)(0x1ul << EBPF_RING_BUFFER_RECORD_FLAG_LOCKED_OFFSET)
#define EBPF_RING_BUFFER_RECORD_FLAG_DISCARDED (long)(0x1ul << EBPF_RING_BUFFER_RECORD_FLAG_DISCARDED_OFFSET)

typedef struct _ebpf_ring_buffer_record
{
    long size; ///< Size of the record in bytes. The lower 30 bits are the size, the 31st bit is the locked flag, and
               ///< the 32nd bit is the discarded flag. Next record starts at this + size + sizeof(size) + padding (to
               ///< 8).

    uint8_t data[1]; ///< Data of the record.
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

inline const bool
ebpf_ring_buffer_record_is_discarded(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (ReadNoFence(&record->size) & EBPF_RING_BUFFER_RECORD_FLAG_DISCARDED) != 0;
}

inline const bool
ebpf_ring_buffer_record_is_locked(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (ReadNoFence(&record->size) & EBPF_RING_BUFFER_RECORD_FLAG_LOCKED) != 0;
}

inline const size_t
ebpf_ring_buffer_record_size(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (size_t)(ReadNoFence(&record->size) &
                    ~(EBPF_RING_BUFFER_RECORD_FLAG_LOCKED | EBPF_RING_BUFFER_RECORD_FLAG_DISCARDED));
}

CXPLAT_EXTERN_C_END
