// Copyright (c) eBPF for Windows contributors
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

#include <endian.h>
#include <unistd.h>

#if !defined(_countof)
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#undef stderr
#undef errno
#define stderr 0
#define fprintf place_holder_fprintf
#define strerror place_holder_strerror
#define errno (place_holder_errno())

#if !defined(NDEBUG)
void
ubpf_assert(const char* message, const char* file, unsigned line)
{
    UNREFERENCED_PARAMETER(message);
    UNREFERENCED_PARAMETER(file);
    UNREFERENCED_PARAMETER(line);
    __fastfail(0);
}
#undef _assert
#define _assert ubpf_assert
#endif

inline int
fprintf(void* stream, const char* format, ...)
{
    return -1;
}

inline char* __cdecl place_holder_strerror(int error) { return NULL; }

inline int
place_holder_errno()
{
    return -1;
}

#define UBPF_STACK_SIZE 512

// UINTPTR_MAX is not defined in Windows kernel headers, so define it here.
#ifndef UINTPTR_MAX
#ifdef _WIN64
#define UINTPTR_MAX 0xffffffffffffffffULL
#else
#define UINTPTR_MAX 0xffffffffU
#endif
#endif

static enum Registers
map_register(int r)
{
    return 0;
}

#include "ubpf_int.h"

// Thunk out JIT related calls.
// Workaround until https://github.com/iovisor/ubpf/issues/185 is fixed.
struct ubpf_jit_result
ubpf_translate_x86_64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode)
{
    __fastfail(0);
    struct ubpf_jit_result result = {0};
    return result;
}

bool
ubpf_jit_update_dispatcher_x86_64(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset)
{
    __fastfail(0);
    return false;
}

bool
ubpf_jit_update_helper_x86_64(
    struct ubpf_vm* vm,
    extended_external_helper_t new_helper,
    unsigned int idx,
    uint8_t* buffer,
    size_t size,
    uint32_t offset)
{
    __fastfail(0);
    return false;
}

// Thunk out JIT related calls.
// Workaround until https://github.com/iovisor/ubpf/issues/185 is fixed.
struct ubpf_jit_result
ubpf_translate_arm64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, enum JitMode jit_mode)
{
    __fastfail(0);
    struct ubpf_jit_result result = {0};
    return result;
}

bool
ubpf_jit_update_dispatcher_arm64(
    struct ubpf_vm* vm, external_function_dispatcher_t new_dispatcher, uint8_t* buffer, size_t size, uint32_t offset)
{
    __fastfail(0);
    return false;
}

bool
ubpf_jit_update_helper_arm64(
    struct ubpf_vm* vm,
    extended_external_helper_t new_helper,
    unsigned int idx,
    uint8_t* buffer,
    size_t size,
    uint32_t offset)
{
    __fastfail(0);
    return false;
}

#pragma warning(push)
#pragma warning(disable : 28159) // Don't use KeBugCheck
void __cdecl abort(void) { KeBugCheck(PAGE_FAULT_IN_NONPAGED_AREA); }
#pragma warning(pop)

#include "ubpf_vm.c"
#pragma warning(push)
#pragma warning(disable : 6387) // ubpf_jit.c(70): error C6387: 'buffer' could be '0'
#include "ubpf_instruction_valid.c"
#include "ubpf_jit.c"
#pragma warning(pop)

// eBPF for Windows uses only the default (legacy) ubpf execution profile; it does not use
// ubpf's opt-in "safe" execution profile. ubpf_vm.c references these safe-profile entry points
// unconditionally, so stub them out rather than compiling vm/ubpf_safe.c (which duplicates
// ubpf_vm.c's file-static interpreter helpers and so cannot be amalgamated into this translation
// unit). This mirrors how the unused ubpf JIT is thunked out above.
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
