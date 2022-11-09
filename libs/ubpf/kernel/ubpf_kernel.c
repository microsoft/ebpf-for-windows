// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _CRT_SECURE_NO_WARNINGS 1

#include "ebpf_platform.h"

#pragma warning(disable : 4100)
#pragma warning(disable : 4018)
#pragma warning(disable : 4146)
#pragma warning(disable : 4214)
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#pragma warning(disable : 4245)
#pragma warning(disable : 4267)

#include <stdlib.h>

#define malloc(X) ebpf_allocate((X))
#define calloc(X, Y) ebpf_allocate((X) * (Y))
#define free(X) ebpf_free(X)

#include <endian.h>
#include <unistd.h>

#if !defined(_countof)
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#undef stderr
#define stderr 0
#define fprintf place_holder_fprintf
#define strerror place_holder_strerror
#define errno (place_holder_errno())

inline int
fprintf(void* stream, const char* format, ...)
{
    return -1;
}

inline char* __cdecl place_holder_strerror(_In_ int error) { return NULL; }

inline int
place_holder_errno()
{
    return -1;
}

#define UBPF_STACK_SIZE 512

static enum Registers
map_register(int r)
{
    return 0;
}

#include "ubpf_vm.c"
#pragma warning(push)
#pragma warning(disable : 6387) // ubpf_jit.c(70): error C6387: 'buffer' could be '0'
#include "ubpf_jit.c"
#pragma warning(pop)
