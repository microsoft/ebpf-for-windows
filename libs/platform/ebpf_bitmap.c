// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_bitmap.h"

typedef struct _ebpf_bitmap
{
    size_t bit_count;
    size_t data[1];
} ebpf_bitmap_t;

typedef struct _ebpf_bitmap_cursor_internal
{
    const ebpf_bitmap_t* bitmap;
    size_t index;         // Current block being searched.
    size_t current_block; // Copy of the current block.
} ebpf_bitmap_cursor_internal_t;

C_ASSERT(sizeof(ebpf_bitmap_cursor_internal_t) == sizeof(ebpf_bitmap_cursor_t));

#define BITS_IN_SIZE_T (sizeof(size_t) * 8)
#define BIT_COUNT_TO_BLOCK_COUNT(X) (((X) + BITS_IN_SIZE_T - 1) / BITS_IN_SIZE_T)

size_t
ebpf_bitmap_size(size_t bit_count)
{
    return EBPF_OFFSET_OF(ebpf_bitmap_t, data) + BIT_COUNT_TO_BLOCK_COUNT(bit_count) * sizeof(size_t);
}

void
ebpf_bitmap_initialize(_Out_ ebpf_bitmap_t* bitmap, size_t bit_count)
{
    bitmap->bit_count = bit_count;
    memset(bitmap->data, 0, BIT_COUNT_TO_BLOCK_COUNT(bit_count) * sizeof(size_t));
}

bool
ebpf_bitmap_set_bit(_Inout_ ebpf_bitmap_t* bitmap, size_t index, bool interlocked)
{
    volatile int64_t* block = (volatile int64_t*)(bitmap->data + index / BITS_IN_SIZE_T);
    uint8_t position_within_block = index % BITS_IN_SIZE_T;

    if (interlocked) {
        return _interlockedbittestandset64(block, position_within_block);
    } else {
        return _bittestandset64((int64_t*)block, position_within_block);
    }
}

bool
ebpf_bitmap_reset_bit(_Inout_ ebpf_bitmap_t* bitmap, size_t index, bool interlocked)
{
    volatile int64_t* block = (volatile int64_t*)(bitmap->data + index / BITS_IN_SIZE_T);
    uint8_t position_within_block = index % BITS_IN_SIZE_T;

    if (interlocked) {
        return _interlockedbittestandreset64(block, position_within_block);
    } else {
        return _bittestandreset64((int64_t*)block, position_within_block);
    }
}

bool
ebpf_bitmap_test_bit(_In_ const ebpf_bitmap_t* bitmap, size_t index)
{
    return _bittest64((const int64_t*)&(bitmap->data[index / BITS_IN_SIZE_T]), index % BITS_IN_SIZE_T);
}

void
ebpf_bitmap_start_forward_search(_In_ const ebpf_bitmap_t* bitmap, _Out_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    internal_cursor->bitmap = bitmap;
    internal_cursor->index = 0;
    internal_cursor->current_block = bitmap->data[internal_cursor->index / BITS_IN_SIZE_T];
}

void
ebpf_bitmap_start_reverse_search(_In_ const ebpf_bitmap_t* bitmap, _Out_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    internal_cursor->bitmap = bitmap;
    internal_cursor->index = bitmap->bit_count - 1;
    internal_cursor->current_block = bitmap->data[internal_cursor->index / BITS_IN_SIZE_T];
}

size_t
ebpf_bitmap_forward_search_next_bit(_Inout_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    while (internal_cursor->index < internal_cursor->bitmap->bit_count) {
        unsigned long next_bit = 0;
        if (_BitScanForward64(&next_bit, internal_cursor->current_block)) {
            internal_cursor->index = next_bit + (internal_cursor->index / BITS_IN_SIZE_T) * BITS_IN_SIZE_T;
            // Clear the bit.
            internal_cursor->current_block &= ~((size_t)1 << next_bit);
            return internal_cursor->index;
        } else {
            // Move to next block.
            internal_cursor->index /= BITS_IN_SIZE_T;
            internal_cursor->index++;
            internal_cursor->index *= BITS_IN_SIZE_T;
            internal_cursor->current_block = internal_cursor->bitmap->data[internal_cursor->index / BITS_IN_SIZE_T];
        }
    }

    return MAXSIZE_T;
}

size_t
ebpf_bitmap_reverse_search_next_bit(_Inout_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    while (internal_cursor->index < internal_cursor->bitmap->bit_count) {
        unsigned long next_bit = 0;
        if (_BitScanReverse64(&next_bit, internal_cursor->current_block)) {
            internal_cursor->index = next_bit + (internal_cursor->index / BITS_IN_SIZE_T) * BITS_IN_SIZE_T;
            // Clear the bit.
            internal_cursor->current_block &= ~((size_t)1 << next_bit);
            return internal_cursor->index;
        } else {
            // Move to previous block.
            internal_cursor->index /= BITS_IN_SIZE_T;
            if (internal_cursor->index == 0) {
                break;
            }
            internal_cursor->index--;
            internal_cursor->index *= BITS_IN_SIZE_T;
            internal_cursor->current_block = internal_cursor->bitmap->data[internal_cursor->index / BITS_IN_SIZE_T];
        }
    }

    return MAXSIZE_T;
}
