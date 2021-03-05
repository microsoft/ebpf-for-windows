/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include <ntddk.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>


void* ubpf_alloc(size_t size, size_t count)
{
    return ExAllocatePool(POOL_FLAG_NON_PAGED, size * count);
}

void ubpf_free(void* memory)
{
    ExFreePool(memory);
}

int vasprintf(char** target, const char* format, va_list argptr)
{
    int length = 1024;
    *target = ubpf_alloc(length, sizeof(const char));
    return vsprintf_s(*target, length, format, argptr);
}
