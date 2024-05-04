/*
 *  Copyright (c) eBPF for Windows contributors
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdarg.h>
#include <stdio.h>

int
rand_r(unsigned int* seedp)
{
    return rand();
}

int
vasprintf(char** target, const char* format, va_list argptr)
{
    int length = 1024;
    if (target == NULL) {
        return -1;
    }
    *target = calloc(length, sizeof(const char));
    if (*target == NULL) {
        return -1;
    }
    return vsprintf_s(*target, length, format, argptr);
}
