// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_shared_framework.h"

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size)
{
    return ebpf_allocate_with_tag(size, EBPF_POOL_TAG_DEFAULT);
}

_Must_inspect_result_ _Ret_maybenull_z_ char*
ebpf_strdup(_In_z_ const char* source)
{
    size_t size = strlen(source) + 1;
    char* destination = (char*)ebpf_allocate(size);
    if (destination) {
        memcpy(destination, source, size);
    }
    return destination;
}

void
ebpf_free(_Frees_ptr_opt_ void* memory)
{
    if (memory) {
        ExFreePool(memory);
    }
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate(
    _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size)
{
    void* p = ebpf_allocate(new_size);
    if (p) {
        memcpy(p, memory, min(old_size, new_size));
        if (new_size > old_size) {
            memset(((char*)p) + old_size, 0, new_size - old_size);
        }
        ebpf_free(memory);
    }
    return p;
}