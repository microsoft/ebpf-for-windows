// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_random.h"

// Pointer to cache aligned array of random number generator state.

// Standard MT19937 implementation from https://en.wikipedia.org/wiki/Mersenne_Twister

// Define MT19937 constants with names used in the reference implementation.
#define N 624
#define M 397
#define MATRIX_A 0x9908b0df
#define UPPER_MASK 0x80000000
#define LOWER_MASK 0x7fffffff

typedef __declspec(align(EBPF_CACHE_LINE_SIZE)) struct _ebpf_random_state
{
    // MT19937 state with names used in the reference implementation.
    uint32_t mt[N];
    uint32_t mti;
    uint32_t padding[15];
} ebpf_random_state_t;

static ebpf_random_state_t* _ebpf_random_number_generator_state = NULL;

inline void
init_mt19937_genrand(ebpf_random_state_t* state, uint32_t seed)
{
    state->mt[0] = seed;
    for (state->mti = 1; state->mti < N; state->mti++) {
        // Values from reference implementation.
        state->mt[state->mti] =
            (1812433253ul * (state->mt[state->mti - 1] ^ (state->mt[state->mti - 1] >> 30)) + state->mti);
    }
}

inline uint32_t
genrand_mt19937_int32(ebpf_random_state_t* state)
{
    uint32_t y;
    static uint32_t mag01[2] = {0x0UL, MATRIX_A};

    // Generate the next N values from the series.
    if (state->mti >= N) {
        int kk;

        if (state->mti == N + 1) {
            init_mt19937_genrand(state, 5489UL);
        }

        for (kk = 0; kk < N - M; kk++) {
            y = (state->mt[kk] & UPPER_MASK) | (state->mt[kk + 1] & LOWER_MASK);
            state->mt[kk] = state->mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }

        for (; kk < N - 1; kk++) {
            y = (state->mt[kk] & UPPER_MASK) | (state->mt[kk + 1] & LOWER_MASK);
            state->mt[kk] = state->mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }

        y = (state->mt[N - 1] & UPPER_MASK) | (state->mt[0] & LOWER_MASK);
        state->mt[N - 1] = state->mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
        state->mti = 0;
    }

    y = state->mt[state->mti++];

    // Values from reference implementation.
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}

_Must_inspect_result_ ebpf_result_t
ebpf_random_initiate()
{

    uint32_t cpu_count = ebpf_get_cpu_count();
    size_t state_size = cpu_count * sizeof(ebpf_random_state_t);
    _ebpf_random_number_generator_state = (ebpf_random_state_t*)cxplat_allocate(
        CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED, state_size, EBPF_POOL_TAG_RANDOM);
    if (_ebpf_random_number_generator_state == NULL) {
        return EBPF_NO_MEMORY;
    }
    for (uint32_t i = 0; i < cpu_count; i++) {
        uint32_t seed = (uint32_t)__rdtsc();
        ebpf_random_state_t* state = &_ebpf_random_number_generator_state[i];
        init_mt19937_genrand(state, seed);
    }
    return EBPF_SUCCESS;
}

void
ebpf_random_terminate()
{
    cxplat_free(
        (void*)_ebpf_random_number_generator_state,
        CXPLAT_POOL_FLAG_NON_PAGED | CXPLAT_POOL_FLAG_CACHE_ALIGNED,
        EBPF_POOL_TAG_RANDOM);
    _ebpf_random_number_generator_state = NULL;
}

uint32_t
ebpf_random_uint32()
{
    KIRQL old_irql = KeGetCurrentIrql();
    if (old_irql < DISPATCH_LEVEL) {
        old_irql = KeRaiseIrqlToDpcLevel();
    }

    uint32_t cpu_index = ebpf_get_current_cpu();
    ebpf_random_state_t* state = &_ebpf_random_number_generator_state[cpu_index];
    uint32_t random = genrand_mt19937_int32(state);

    if (old_irql < DISPATCH_LEVEL) {
        KeLowerIrql(old_irql);
    }
    return random;
}
