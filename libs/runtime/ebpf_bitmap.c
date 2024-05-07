// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This module exposes ebpf_bitmap_t, which maintains a set of N bits. It provides the following operations:
// 1) Test the bit at position X of N.
// 2) Set or reset the bit at position X of N, with both interlocked and non-interlocked versions.
// 3) Iterate over the bits that are set in the bitmap, either in the forward or reverse direction, returning the
// position of the bit that is set.
//
// Iteration over bits:
// The BitScanForward/BitScanReverse instructions find the least significant bit or most significant bit that is set in
// a mask (a block of bits) and return the offset of that bit. To permit iterating over a set of bits, this module
// provides a cursor, which maintains the last offset where a bit was found as well as a copy of the current mask
// (block) being searched.  At the start of the search, the first block of 64-bits is copied from the bitmap into the
// cursor's current block. As each bit in the current block is found and returned, that bit is cleared so that the
// BitScanForward/BitScanReverse instruction will find the next bit in the current block. Once all the bits in the
// current block are found, the next block of 64-bits is copied from the bitmap into the cursor's current block and the
// search is resumed on the new block. Once the cursor's index reaches either 0 (reverse) or bitmap's bit_count
// (forward), the search ends.

#include "ebpf_bitmap.h"

typedef struct _ebpf_bitmap
{
    size_t bit_count;
    uint64_t data[1];
} ebpf_bitmap_t;

typedef struct _ebpf_bitmap_cursor_internal
{
    const ebpf_bitmap_t* bitmap;
    size_t next_bit_offset;      // Last bit found.
    uint64_t current_block_copy; // Copy of the current block being searched.
} ebpf_bitmap_cursor_internal_t;

C_ASSERT(sizeof(ebpf_bitmap_cursor_internal_t) == sizeof(ebpf_bitmap_cursor_t));

// The number of bits within a block.
#define BITS_IN_BLOCK (sizeof(uint64_t) * 8)

// Calculate the number of blocks required to hold X number of bits.
#define BIT_COUNT_TO_BLOCK_COUNT(X) (((X) + BITS_IN_BLOCK - 1) / BITS_IN_BLOCK)

// Give the index of the block containing bit X.
#define BIT_TO_BLOCK(X) ((X) / BITS_IN_BLOCK)

// Give the offset of bit X from the start of the containing block.
#define OFFSET_IN_BLOCK(X) ((X) % BITS_IN_BLOCK)

// Give the bit offset of the start of the block containing X.
#define START_OF_BLOCK(X) ((X)-OFFSET_IN_BLOCK(X))

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
    volatile int64_t* block = (volatile int64_t*)(&bitmap->data[BIT_TO_BLOCK(index)]);
    if (interlocked) {
        return _interlockedbittestandset64(block, OFFSET_IN_BLOCK(index));
    } else {
        return _bittestandset64((int64_t*)block, OFFSET_IN_BLOCK(index));
    }
}

bool
ebpf_bitmap_reset_bit(_Inout_ ebpf_bitmap_t* bitmap, size_t index, bool interlocked)
{
    volatile int64_t* block = (volatile int64_t*)(&bitmap->data[BIT_TO_BLOCK(index)]);
    if (interlocked) {
        return _interlockedbittestandreset64(block, OFFSET_IN_BLOCK(index));
    } else {
        return _bittestandreset64((int64_t*)block, OFFSET_IN_BLOCK(index));
    }
}

bool
ebpf_bitmap_test_bit(_In_ const ebpf_bitmap_t* bitmap, size_t index)
{
    return _bittest64((const int64_t*)(&bitmap->data[BIT_TO_BLOCK(index)]), OFFSET_IN_BLOCK(index));
}

void
ebpf_bitmap_start_forward_search(_In_ const ebpf_bitmap_t* bitmap, _Out_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    internal_cursor->bitmap = bitmap;
    internal_cursor->next_bit_offset = 0;
    internal_cursor->current_block_copy = bitmap->data[BIT_TO_BLOCK(internal_cursor->next_bit_offset)];
}

void
ebpf_bitmap_start_reverse_search(_In_ const ebpf_bitmap_t* bitmap, _Out_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    internal_cursor->bitmap = bitmap;
    internal_cursor->next_bit_offset = bitmap->bit_count - 1;
    internal_cursor->current_block_copy = bitmap->data[BIT_TO_BLOCK(internal_cursor->next_bit_offset)];
}

size_t
ebpf_bitmap_forward_search_next_bit(_Inout_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    // Search until we find a bit or run out of blocks.
    for (;;) {
        unsigned long next_bit = 0;
        if (_BitScanForward64(&next_bit, internal_cursor->current_block_copy)) {
            // Clear the bit.
            _bittestandreset64((int64_t*)&internal_cursor->current_block_copy, next_bit);
            internal_cursor->next_bit_offset = next_bit + START_OF_BLOCK(internal_cursor->next_bit_offset);
            return internal_cursor->next_bit_offset;
        } else {
            // Set index to the start of the current block.
            internal_cursor->next_bit_offset = START_OF_BLOCK(internal_cursor->next_bit_offset);

            // Move the index to the start of the next block to be searched.
            internal_cursor->next_bit_offset += BITS_IN_BLOCK;

            // Are there any more blocks to search?
            if (internal_cursor->next_bit_offset > internal_cursor->bitmap->bit_count) {
                return MAXSIZE_T;
            }

            internal_cursor->current_block_copy =
                internal_cursor->bitmap->data[BIT_TO_BLOCK(internal_cursor->next_bit_offset)];
        }
    }
}

size_t
ebpf_bitmap_reverse_search_next_bit(_Inout_ ebpf_bitmap_cursor_t* cursor)
{
    ebpf_bitmap_cursor_internal_t* internal_cursor = (ebpf_bitmap_cursor_internal_t*)cursor;
    // Search until we find a bit or run out of blocks.
    for (;;) {
        unsigned long next_bit = 0;
        if (_BitScanReverse64(&next_bit, internal_cursor->current_block_copy)) {
            internal_cursor->next_bit_offset =
                next_bit + (internal_cursor->next_bit_offset / BITS_IN_BLOCK) * BITS_IN_BLOCK;
            // Clear the bit.
            _bittestandreset64((int64_t*)&internal_cursor->current_block_copy, next_bit);
            return internal_cursor->next_bit_offset;
        } else {
            // Set index to the start of the current block.
            internal_cursor->next_bit_offset = START_OF_BLOCK(internal_cursor->next_bit_offset);

            // Are there any more blocks to search?
            if (internal_cursor->next_bit_offset == 0) {
                return MAXSIZE_T;
            }

            // Move index to the end of the next block to be searched.
            internal_cursor->next_bit_offset--;
            internal_cursor->current_block_copy =
                internal_cursor->bitmap->data[BIT_TO_BLOCK(internal_cursor->next_bit_offset)];
        }
    }
}
