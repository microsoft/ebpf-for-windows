// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_fault_injection.h"
#include "ebpf_global_new_delete.hpp"
#include "ebpf_platform.h"

// Only enable leak detection and fault injection if iterator debugging is disabled.
// The MSVC STL libraries trigger noexcept violations on out of memory failure when
// iterator debugging is enabled.
#if (_ITERATOR_DEBUG_LEVEL == 0)
// Define global new and delete over ebpf_allocate and ebpf_free

void* __cdecl
operator new(size_t size)
{
    if (ebpf_platform_new_delete_state_t::is_enabled() && ebpf_fault_injection_inject_fault()) {
        throw std::bad_alloc();
    }

    void* return_value = malloc(size);
    if (return_value == nullptr) {
        throw std::bad_alloc();
    }
    return return_value;
}

void __cdecl
operator delete(void* memory) noexcept
{
    free(memory);
}

void* __cdecl
operator new[](size_t size)
{
    if (ebpf_platform_new_delete_state_t::is_enabled() && ebpf_fault_injection_inject_fault()) {
        throw std::bad_alloc();
    }

    void* return_value = malloc(size);
    if (return_value == nullptr) {
        throw std::bad_alloc();
    }
    return return_value;
}

void __cdecl
operator delete[](void* memory) noexcept
{
    free(memory);
}
#endif