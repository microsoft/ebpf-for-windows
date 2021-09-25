// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <ebpf_platform.h>

/**
 * @brief Find the next bit in data that is set.
 *
 * @param[in] data 32 bit aligned block of memory containing bits to check.
 * @param[in] bit_count Size of data in bits.
 * @param[in] start_bit Position to start search at, use MAXUINT32 to restart.
 * @return Next bit that is set or MAXUINT32 if none are set.
 */
uint32_t
ebpf_find_next_set_bit(_In_reads_((bit_count + 31) / 32) uint8_t* data, uint32_t bit_count, uint32_t start_bit);

/**
 * @brief Set a bit in data in a thread safe manner.
 *
 * @param[in] data 32 bit aligned block of memory containing bits.
 * @param[in] bit Offset of bit to set.
 */
bool
ebpf_interlocked_set_bit(_In_ volatile uint8_t* data, uint32_t bit);

/**
 * @brief Reset a bit in data in a thread safe manner.
 *
 * @param[in] data 32 bit aligned block of memory containing bits.
 * @param[in] bit Offset of bit to reset.
 */
bool
ebpf_interlocked_clear_bit(_In_ volatile uint8_t* data, uint32_t bit);

uint32_t
ebpf_find_next_bit_and_reset(_Inout_ uint32_t* data);
