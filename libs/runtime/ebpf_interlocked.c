// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

int32_t
ebpf_interlocked_or_int32(_Inout_ volatile int32_t* target, int32_t mask)
{
    return InterlockedOr((volatile long*)target, mask);
}

int32_t
ebpf_interlocked_and_int32(_Inout_ volatile int32_t* target, int32_t mask)
{
    return InterlockedAnd((volatile long*)target, mask);
}

int32_t
ebpf_interlocked_xor_int32(_Inout_ volatile int32_t* target, int32_t mask)
{
    return InterlockedXor((volatile long*)target, mask);
}

int64_t
ebpf_interlocked_or_int64(_Inout_ volatile int64_t* target, int64_t mask)
{
    return InterlockedOr64(target, mask);
}

int64_t
ebpf_interlocked_and_int64(_Inout_ volatile int64_t* target, int64_t mask)
{
    return InterlockedAnd64(target, mask);
}

int64_t
ebpf_interlocked_xor_int64(_Inout_ volatile int64_t* target, int64_t mask)
{
    return InterlockedXor64(target, mask);
}

int32_t
ebpf_interlocked_increment_int32(_Inout_ volatile int32_t* addend)
{
    return InterlockedIncrement((volatile long*)addend);
}

int32_t
ebpf_interlocked_decrement_int32(_Inout_ volatile int32_t* addend)
{
    return InterlockedDecrement((volatile long*)addend);
}

int64_t
ebpf_interlocked_increment_int64(_Inout_ volatile int64_t* addend)
{
    return InterlockedIncrement64(addend);
}

int64_t
ebpf_interlocked_decrement_int64(_Inout_ volatile int64_t* addend)
{
    return InterlockedDecrement64(addend);
}

int32_t
ebpf_interlocked_compare_exchange_int32(_Inout_ volatile int32_t* destination, int32_t exchange, int32_t comparand)
{
    return InterlockedCompareExchange((long volatile*)destination, exchange, comparand);
}

int64_t
ebpf_interlocked_compare_exchange_int64(_Inout_ volatile int64_t* destination, int64_t exchange, int64_t comparand)
{
    return InterlockedCompareExchange64(destination, exchange, comparand);
}

void*
ebpf_interlocked_compare_exchange_pointer(
    _Inout_ void* volatile* destination, _In_opt_ const void* exchange, _In_opt_ const void* comparand)
{
    return InterlockedCompareExchangePointer((void* volatile*)destination, (void*)exchange, (void*)comparand);
}
