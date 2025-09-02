// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "cxplat.h"
#include "ebpf_shared_framework.h"

CXPLAT_EXTERN_C_BEGIN

#define EBPF_RINGBUF_LOCK_BIT (1U << 31)
#define EBPF_RINGBUF_DISCARD_BIT (1U << 30)
// Max record size is 32 bit length - 2 bits for lock+discard.
#define EBPF_RINGBUF_MAX_RECORD_SIZE ((1ULL << 30) - 1)
#define EBPF_RINGBUF_HEADER_SIZE (EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data))

typedef struct _ebpf_ring_buffer_record
{
    // This struct should match the linux ring buffer record structure for future mmap compatibility (see #4163).
    struct
    {
        uint32_t length;      ///< High 2 bits are lock,discard.
        uint32_t page_offset; ///< Offset of the record from the start of the data buffer, in pages.
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
    // Uses read-acquire to ensure that if the record is unlocked and not discarded that the data is visible.
    return (ReadUInt32Acquire(&record->header.length) & EBPF_RINGBUF_LOCK_BIT) != 0;
}

/**
 * @brief Determine if the record is discarded (only valid if unlocked).
 *
 * If the record is discarded then the consumer should skip the record.
 * If the record is not discarded then the data is valid and can be read.
 *
 * @param[in] record Pointer to the record.
 * @return True if the record is discarded.
 */
inline const bool
ebpf_ring_buffer_record_is_discarded(_In_ const ebpf_ring_buffer_record_t* record)
{
    // We check the lock bit using read-acquire before checking for discard, so we can use no-fence here.
    return (ReadUInt32NoFence(&record->header.length) & EBPF_RINGBUF_DISCARD_BIT) != 0;
}

/**
 * @brief Get the length of the record (only valid if unlocked).
 *
 * @param[in] record Pointer to the record.
 * @return Length of the record.
 */
inline const uint32_t
ebpf_ring_buffer_record_length(_In_ const ebpf_ring_buffer_record_t* record)
{
    return ReadUInt32NoFence(&record->header.length) & ~(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT);
}

/**
 * @brief Get the total size of the record (including header and padding).
 *
 * Record includes 8 byte header and is padded to 8 byte alignment.
 *
 * @param[in] record Pointer to the record.
 * @return Total size of the record.
 */
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

    ebpf_assert(producer - consumer >= EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
    return (ebpf_ring_buffer_record_t*)(buffer + consumer % buffer_length);
}

CXPLAT_EXTERN_C_END
