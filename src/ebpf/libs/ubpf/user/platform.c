/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void*
ubpf_alloc(size_t size, size_t count);

void
ubpf_free(void* memory);

int
vasprintf(char** target, const char* format, va_list argptr)
{
    int length = 1024;
    *target = ubpf_alloc(length, sizeof(const char));
    return vsprintf_s(*target, length, format, argptr);
}
