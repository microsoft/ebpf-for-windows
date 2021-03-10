/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <ntddk.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum _ubpd_pool_tag
{
    EBPF_POOL_TAG = 'fpbu'
} ubpd_pool_tag_t;

void*
ubpf_alloc(size_t size, size_t count)
{
    void* memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, EBPF_POOL_TAG);

    if (memory) {
        memset(memory, 0, size * count);
    }
    return memory;
}

void
ubpf_free(void* memory)
{
    if (memory)
        ExFreePool(memory);
}

int
vasprintf(char** target, const char* format, va_list argptr)
{
    int length = 1024;
    *target = ubpf_alloc(length, sizeof(const char));
    return vsprintf_s(*target, length, format, argptr);
}
