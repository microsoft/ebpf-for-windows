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
#include <stdlib.h>

static void*
_ebpf_ubpf_calloc(size_t count, size_t size)
{
    size_t allocation_length = 0;
    if (cxplat_safe_size_t_multiply(count, size, &allocation_length) != CXPLAT_STATUS_SUCCESS) {
        return NULL;
    }
    return ebpf_allocate_with_tag(allocation_length, EBPF_POOL_TAG_DEFAULT);
}

#define malloc(X) ebpf_allocate_with_tag((X), EBPF_POOL_TAG_DEFAULT)
#define calloc(X, Y) _ebpf_ubpf_calloc((X), (Y))
#define free(X) ebpf_free(X)

#pragma warning(push)
#pragma warning(disable : 4100)  // unreferenced formal parameter
#pragma warning(disable : 4211)  // nonstandard extension used: redefined extern to static
#pragma warning(disable : 6387)  // ubpf_jit.c(70): error C6387: 'buffer' could be '0'
#pragma warning(disable : 26451) // Arithmetic overflow: Using operator '*' on a 4 byte value and then casting the
                                 // result to a 8 byte value.

// Windows headers define near and far which conflict with the ubpf headers.
#undef near
#undef far
#include "ubpf_instruction_valid.c"
#include "ubpf_jit.c"
#include "ubpf_jit_support.c"
#include "ubpf_jit_x86_64.c"
#include "ubpf_vm.c"
#pragma warning(pop)

// eBPF for Windows uses only the default (legacy) ubpf execution profile; it does not use
// ubpf's opt-in "safe" execution profile. ubpf_vm.c references these safe-profile entry points
// unconditionally, so stub them out rather than compiling vm/ubpf_safe.c (which duplicates
// ubpf_vm.c's file-static interpreter helpers and so cannot be amalgamated into this translation
// unit).
#pragma warning(push)
#pragma warning(disable : 4100) // unreferenced formal parameter
int
ubpf_set_execution_profile_impl(struct ubpf_vm* vm, enum ubpf_execution_profile profile)
{
    return (profile == UBPF_EXECUTION_PROFILE_LEGACY) ? 0 : -1;
}

int
ubpf_register_safe_helper_impl(struct ubpf_vm* vm, const struct ubpf_safe_helper_descriptor* descriptor)
{
    return -1;
}

int
ubpf_register_safe_region_impl(struct ubpf_vm* vm, const struct ubpf_safe_region* region)
{
    return -1;
}

int
ubpf_exec_ex_safe(
    const struct ubpf_vm* vm,
    void* mem,
    size_t mem_len,
    uint64_t* bpf_return_value,
    uint8_t* stack_start,
    size_t stack_length)
{
    // Unreachable: the safe profile is never selected (ubpf_set_execution_profile_impl rejects it).
    return -1;
}
#pragma warning(pop)
