// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "cxplat.h"
#include "ebpf_shared_framework.h"
#define min(x, y) (((x) < (y)) ? (x) : (y))

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size)
{
    return cxplat_allocate(size);
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

// TODO: get rid of this extra level of indirection?
void
ebpf_free(_Frees_ptr_opt_ void* memory)
{
    cxplat_free(memory);
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate(
    _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size)
{
    return cxplat_reallocate(memory, old_size, new_size);
}