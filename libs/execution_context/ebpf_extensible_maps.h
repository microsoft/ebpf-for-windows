// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core.h"
#include "ebpf_extension.h"
#include "ebpf_maps.h"
#include "ebpf_platform.h"
#include "ebpf_structs.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Create an extensible map.
     *
     * This function creates a new extensible map based on the provided map definition.
     * Extensible maps are maps with type IDs greater than BPF_MAP_TYPE_MAX (4096).
     *
     * @param[in] map_definition Pointer to the map definition structure containing
     *                           map type, key size, value size, and maximum entries.
     * @param[in] inner_map_handle Handle to an inner map for map-in-map types, or 0 for regular maps.
     * @param[out] map Pointer to receive the created map object.
     *
     * @retval EBPF_SUCCESS The map was created successfully.
     * @retval EBPF_INVALID_ARGUMENT Invalid map definition or output pointer.
     * @retval EBPF_NO_MEMORY Insufficient memory to create the map.
     * @retval EBPF_NOT_SUPPORTED Unsupported map type.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_create(
        _In_ const ebpf_map_definition_in_memory_t* map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_map_t** map);

    /**
     * @brief Delete an extensible map and free its resources.
     *
     * This function destroys an extensible map that was previously created with
     * ebpf_extensible_map_create(). All entries in the map are deleted and the
     * map structure itself is freed.
     *
     * @param[in] map Pointer to the extensible map to delete. The pointer will be
     *                invalid after this function returns.
     */
    void
    ebpf_extensible_map_delete(_In_ _Post_ptr_invalid_ ebpf_core_map_t* map);

    /**
     * @brief Check if a map type is extensible.
     *
     * This function determines whether a given map type ID represents an extensible
     * map. Extensible maps have type IDs greater than BPF_MAP_TYPE_MAX, which allows
     * for custom map implementations beyond the standard BPF map types.
     *
     * @param[in] map_type The map type ID to check.
     *
     * @return true if the map type is extensible (> BPF_MAP_TYPE_MAX), false otherwise.
     */
    static inline bool
    ebpf_map_type_is_extensible(uint32_t map_type)
    {
        return map_type > BPF_MAP_TYPE_MAX;
    }

    /**
     * @brief Find an element in an extensible map.
     *
     * This function searches for an entry with the specified key in the extensible map
     * and returns a pointer to the associated value if found.
     *
     * @param[in,out] map Pointer to the extensible map to search in.
     * @param[in] key_size Size of the key in bytes.
     * @param[in] key Pointer to the key data to search for.
     * @param[out] value Pointer to receive the address of the value associated with the key.
     * @param[in] flags Additional flags for the lookup operation (currently unused).
     *
     * @retval EBPF_SUCCESS The key was found and value pointer is set.
     * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
     * @retval EBPF_INVALID_ARGUMENT Invalid map, key, or output pointer.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_find_entry(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        _Outptr_ uint8_t** value,
        int flags);

    /**
     * @brief Update an element in an extensible map.
     *
     * This function inserts or updates an entry in the extensible map with the
     * specified key-value pair. The behavior depends on the option parameter.
     *
     * @param[in,out] map Pointer to the extensible map to update.
     * @param[in] key_size Size of the key in bytes.
     * @param[in] key Pointer to the key data.
     * @param[in] value_size Size of the value in bytes.
     * @param[in] value Pointer to the value data to store.
     * @param[in] option Update option specifying the behavior:
     *                   - EBPF_ANY: Insert or update
     *                   - EBPF_NOEXIST: Insert only if key doesn't exist
     *                   - EBPF_EXIST: Update only if key exists
     * @param[in] flags Additional flags for the update operation.
     *
     * @retval EBPF_SUCCESS The entry was successfully updated or inserted.
     * @retval EBPF_KEY_EXISTS Key already exists (when option is EBPF_NOEXIST).
     * @retval EBPF_KEY_NOT_FOUND Key not found (when option is EBPF_EXIST).
     * @retval EBPF_NO_MEMORY Insufficient memory to create new entry.
     * @retval EBPF_INVALID_ARGUMENT Invalid parameters.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_update_entry(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_(key_size) const uint8_t* key,
        size_t value_size,
        _In_reads_(value_size) const uint8_t* value,
        ebpf_map_option_t option,
        int flags);

    /**
     * @brief Delete an element from an extensible map.
     *
     * This function removes the entry with the specified key from the extensible map.
     * The associated value is freed and the entry is removed from the map's data structure.
     *
     * @param[in] map Pointer to the extensible map to delete from.
     * @param[in] key_size Size of the key in bytes.
     * @param[in] key Pointer to the key data of the entry to delete.
     * @param[in] flags Additional flags for the delete operation (currently unused).
     *
     * @retval EBPF_SUCCESS The entry was successfully deleted.
     * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
     * @retval EBPF_INVALID_ARGUMENT Invalid map or key pointer.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_delete_entry(
        _In_ ebpf_map_t* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, int flags);

    /**
     * @brief Get the next key and optionally its value from an extensible map.
     *
     * This function is used to iterate over all entries in the extensible map.
     * It returns the next key in the iteration order after the given previous key,
     * and optionally the associated value.
     *
     * @param[in,out] map Pointer to the extensible map to iterate over.
     * @param[in] key_size Size of the key in bytes.
     * @param[in] previous_key Pointer to the previous key, or NULL to get the first key.
     * @param[out] next_key Buffer to receive the next key data.
     * @param[out] next_value Optional pointer to receive the address of the value
     *                        associated with the next key. Can be NULL if value is not needed.
     *
     * @retval EBPF_SUCCESS The next key was found and returned.
     * @retval EBPF_NO_MORE_KEYS No more keys available (end of iteration).
     * @retval EBPF_KEY_NOT_FOUND The previous key was not found in the map.
     * @retval EBPF_INVALID_ARGUMENT Invalid parameters.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_get_next_key_and_value(
        _Inout_ ebpf_map_t* map,
        size_t key_size,
        _In_reads_opt_(key_size) const uint8_t* previous_key,
        _Out_writes_(key_size) uint8_t* next_key,
        _Outptr_opt_ uint8_t** next_value);

    /**
     * @brief Associate a program with an extensible map.
     *
     * This function creates an association between an eBPF program and an extensible map.
     * This association is typically used for maps that hold program file descriptors,
     * such as program array maps used for tail calls.
     *
     * @param[in,out] map Pointer to the extensible map to associate with the program.
     * @param[in] program Pointer to the eBPF program to associate with the map.
     *
     * @retval EBPF_SUCCESS The program was successfully associated with the map.
     * @retval EBPF_INVALID_ARGUMENT Invalid map or program pointer.
     * @retval EBPF_NOT_SUPPORTED Map type does not support program association.
     */
    _Must_inspect_result_ ebpf_result_t
    ebpf_extensible_map_associate_program(_Inout_ ebpf_map_t* map, _In_ const struct _ebpf_program* program);

#ifdef __cplusplus
}
#endif