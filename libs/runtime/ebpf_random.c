// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_random.h"

// Pointer to cache aligned array of random number generator state.

typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_random_state
{
    uint64_t state;
    uint8_t _padding[EBPF_CACHE_LINE_SIZE - sizeof(uint64_t)];
} ebpf_random_state_t;

static volatile ebpf_random_state_t* _ebpf_random_number_generator_state = NULL;

_Must_inspect_result_ ebpf_result_t
ebpf_random_initiate()
{
    LARGE_INTEGER p = KeQueryPerformanceCounter(NULL);
    unsigned long seed = p.LowPart ^ (unsigned long)p.HighPart;

    uint32_t cpu_count = ebpf_get_cpu_count();
    size_t state_size = cpu_count * sizeof(ebpf_random_state_t);
    _ebpf_random_number_generator_state = ebpf_allocate_cache_aligned(state_size);
    if (_ebpf_random_number_generator_state == NULL) {
        return EBPF_NO_MEMORY;
    }
    for (uint32_t i = 0; i < cpu_count; i++) {
        _ebpf_random_number_generator_state[i].state = RtlRandomEx(&seed);
    }
    return EBPF_SUCCESS;
}

void
ebpf_random_terminate()
{
    ebpf_free_cache_aligned((void*)_ebpf_random_number_generator_state);
    _ebpf_random_number_generator_state = NULL;
}

#define LCG_MULTIPLIER ((uint64_t)1664525)
#define LCG_OFFSET ((uint64_t)1013904223)
#define LCG_MODULUS ((uint64_t)4294967296)

// Implement a linear congruential random number generator.
// x(n+1) = (a * x(n) + c) % m
// where a = 1664525, c = 1013904223, and m = 4294967296
// See: https://www.researchgate.net/publication/220420979_Random_Number_Generators_Good_Ones_Are_Hard_to_Find
// for more details.
// Note the linear congruential random number generator is not cryptographically secure.
// The values for a, c, and m are chosen to be fast to compute on 32-bit processors and to also have a long period.
uint32_t
ebpf_random_uint32()
{
    uint32_t cpu_index = ebpf_get_current_cpu();
    volatile ebpf_random_state_t* state = &_ebpf_random_number_generator_state[cpu_index];
    uint64_t state64 = state->state;
    uint64_t next_state64 = (state64 * LCG_MULTIPLIER + LCG_OFFSET) % LCG_MODULUS;
    state->state = next_state64;
    return (uint32_t)next_state64;
}