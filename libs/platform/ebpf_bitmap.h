// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <ebpf_platform.h>

/**
 * @brief Set a bit in data in a thread safe manner.
 * Assumes data is in network byte order.
 *
 * @param[in] data 32 bit aligned block of memory containing bits.
 * @param[in] bit Offset of bit to set.
 * @returns The previous value of this bit.
 */
bool
ebpf_interlocked_set_bit(_In_ volatile uint8_t* data, uint32_t bit);

/**
 * @brief Reset a bit in data in a thread safe manner.
 * Assumes data is in network byte order.
 *
 * @param[in] data 32 bit aligned block of memory containing bits.
 * @param[in] bit Offset of bit to reset.
 * @returns The previous value of this bit.
 */
bool
ebpf_interlocked_clear_bit(_In_ volatile uint8_t* data, uint32_t bit);

/**
 * @brief Find the first bit set in data, clear it and return the offset.
 * Assumes data is in network byte order.
 *
 * @param data Block of 32 bits.
 * @returns uint32_t Offset of the bit that was cleared.
 */
uint32_t
ebpf_find_next_bit_and_reset(_Inout_ uint32_t* data);
