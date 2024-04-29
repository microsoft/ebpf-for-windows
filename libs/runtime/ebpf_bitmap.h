// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <ebpf_platform.h>

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct _ebpf_bitmap ebpf_bitmap_t;
    typedef uintptr_t ebpf_bitmap_cursor_t[3];

    /**
     * @brief Compute the size in bytes required to hold a ebpf_bitmap_t.
     *
     * @param[in] bit_count Count of bits the bitmap will hold.
     * @return Size in bytes required.
     */
    size_t
    ebpf_bitmap_size(size_t bit_count);

    /**
     * @brief Initialize an already allocated bitmap.
     *
     * @param[out] bitmap Pointer to the bitmap.
     * @param[in] bit_count Count of bits to be stored.
     */
    void
    ebpf_bitmap_initialize(_Out_ ebpf_bitmap_t* bitmap, size_t bit_count);

    /**
     * @brief Set bit at index to true.
     *
     * @param[in, out] bitmap Pointer to the bitmap.
     * @param[in] index Index to modify.
     * @param[in] interlocked Perform the operation using interlocked.
     * @retval true The bit was modified.
     * @retval false The bit was already set.
     */
    bool
    ebpf_bitmap_set_bit(_Inout_ ebpf_bitmap_t* bitmap, size_t index, bool interlocked);

    /**
     * @brief Set bit at index to false.
     *
     * @param[in, out] bitmap Pointer to the bitmap.
     * @param[in] index Index to modify.
     * @param[in] interlocked Perform the operation using interlocked.
     * @retval true The bit was modified.
     * @retval false The bit was already reset.
     */
    bool
    ebpf_bitmap_reset_bit(_Inout_ ebpf_bitmap_t* bitmap, size_t index, bool interlocked);

    /**
     * @brief Get the value of the bit at index.
     *
     * @param[in] bitmap Pointer to the bitmap.
     * @param[in] index Index to modify.
     * @retval true The bit was set.
     * @retval false The bit was not set.
     */
    bool
    ebpf_bitmap_test_bit(_In_ const ebpf_bitmap_t* bitmap, size_t index);

    /**
     * @brief Initialize a cursor to perform a forward scan of bits.
     *
     * @param[in] bitmap Pointer to the bitmap.
     * @param[out] cursor Pointer to cursor.
     */
    void
    ebpf_bitmap_start_forward_search(_In_ const ebpf_bitmap_t* bitmap, _Out_ ebpf_bitmap_cursor_t* cursor);

    /**
     * @brief Initialize a cursor to perform a reverse scan of bits.
     *
     * @param[in] bitmap Pointer to the bitmap.
     * @param[out] cursor Pointer to cursor.
     */
    void
    ebpf_bitmap_start_reverse_search(_In_ const ebpf_bitmap_t* bitmap, _Out_ ebpf_bitmap_cursor_t* cursor);

    /**
     * @brief Find the next set bit in the bitmap via forward search.
     *
     * @param[in, out] cursor Pointer to cursor.
     * @return Offset of the next set bit.
     */
    size_t
    ebpf_bitmap_forward_search_next_bit(_Inout_ ebpf_bitmap_cursor_t* cursor);

    /**
     * @brief Find the next set bit in the bitmap via reverse search.
     *
     * @param[in, out] cursor Pointer to cursor.
     * @return Offset of the next set bit.
     */
    size_t
    ebpf_bitmap_reverse_search_next_bit(_Inout_ ebpf_bitmap_cursor_t* cursor);

#ifdef __cplusplus
}
#endif
