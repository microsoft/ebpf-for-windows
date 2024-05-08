// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define _CRT_SECURE_NO_WARNINGS 1

#include "ebpf_shared_framework.h"

#pragma warning(disable : 4013)
#pragma warning(disable : 4018)
#pragma warning(disable : 4090)
#pragma warning(disable : 4146)
#pragma warning(disable : 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable : 4214)
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#pragma warning(disable : 4245)
#pragma warning(disable : 4267)

#include <endian.h>
#define UBPF_STACK_SIZE 512

#include <stdlib.h>

#define malloc(X) ebpf_allocate((X))
#define calloc(X, Y) ebpf_allocate((X) * (Y))
#define free(X) ebpf_free(X)

#pragma warning(push)
#pragma warning(disable : 4100)  // unreferenced formal parameter
#pragma warning(disable : 4211)  // nonstandard extension used: redefined extern to static
#pragma warning(disable : 6387)  // ubpf_jit.c(70): error C6387: 'buffer' could be '0'
#pragma warning(disable : 26451) // Arithmetic overflow: Using operator '*' on a 4 byte value and then casting the
                                 // result to a 8 byte value.
#include "ubpf_jit.c"
#include "ubpf_jit_support.c"
#include "ubpf_jit_x86_64.c"
#include "ubpf_vm.c"
#pragma warning(pop)
