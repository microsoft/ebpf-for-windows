// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_bitmap.h"

uint32_t
ebpf_find_next_bit_and_reset(_Inout_ uint32_t* data)
{
    uint32_t index;
    if (!_BitScanForward((DWORD*)&index, *data)) {
        return MAXUINT32;
    }

    _bittestandreset((LONG*)data, index);
    return index;
}

bool
ebpf_interlocked_set_bit(_In_ volatile uint8_t* data, uint32_t bit)
{
    volatile long* destination = (volatile long*)(data) + (bit / 32);
    ebpf_assert((uintptr_t)(destination) % 4 == 0);

    return _interlockedbittestandset(destination, bit % 32);
}

bool
ebpf_interlocked_clear_bit(_In_ volatile uint8_t* data, uint32_t bit)
{
    volatile long* destination = (volatile long*)(data + (bit / 32));
    ebpf_assert((uintptr_t)(destination) % 4 == 0);
    return _interlockedbittestandreset(destination, bit % 32);
}