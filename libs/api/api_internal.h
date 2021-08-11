// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "api_common.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_windows.h"
#include "spec_type_descriptors.hpp"

struct bpf_object;

typedef struct bpf_program
{
    struct bpf_object* object;
    char* section_name;
    char* program_name;
    uint8_t* byte_code;
    uint32_t byte_code_size;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    ebpf_handle_t handle;
    fd_t fd;
    bool pinned;
} ebpf_program_t;

typedef struct bpf_map
{
    const struct bpf_object* object;
    char* name;
    ebpf_handle_t map_handle;
    fd_t map_fd;
    fd_t mock_map_fd;
    ebpf_map_definition_t map_definition;
    char* pin_path;
    bool pinned;
} ebpf_map_t;

typedef struct bpf_link
{
    char* pin_path;
    ebpf_handle_t link_handle;
    fd_t link_fd;
    bool disconnected;
} ebpf_link_t;

typedef struct bpf_object
{
    char* file_name = nullptr;
    std::vector<ebpf_program_t*> programs;
    std::vector<ebpf_map_t*> maps;
} ebpf_object_t;

ebpf_result_t
ebpf_get_program_byte_code(
    _In_z_ const char* file_name,
    _In_z_ const char* section_name,
    bool mock_map_fd,
    std::vector<ebpf_program_t*>& programs,
    _Outptr_result_maybenull_ EbpfMapDescriptor** map_descriptors,
    _Out_ int* map_descriptors_count,
    _Outptr_result_maybenull_ const char** error_message);

ebpf_result_t
get_program_info_data(ebpf_program_type_t program_type, _Outptr_ ebpf_program_info_t** program_info);

void
clean_up_ebpf_program(_In_ _Post_invalid_ ebpf_program_t* program);

void
clean_up_ebpf_programs(_Inout_ std::vector<ebpf_program_t*>& programs);

void
clean_up_ebpf_map(_In_ _Post_invalid_ ebpf_map_t* map);

void
clean_up_ebpf_maps(_Inout_ std::vector<ebpf_map_t*>& maps);

/**
 * @brief Get next program in ebpf_object object.
 *
 * @param[in] previous Pointer to previous eBPF program, or NULL to get the first one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the next program, or NULL if none.
 */
_Ret_maybenull_ struct bpf_program*
ebpf_program_next(_In_opt_ const struct bpf_program* previous, _In_ const struct bpf_object* object);

/**
 * @brief Get previous program in ebpf_object object.
 *
 * @param[in] next Pointer to next eBPF program, or NULL to get the last one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the previous program, or NULL if none.
 */
_Ret_maybenull_ struct bpf_program*
ebpf_program_previous(_In_opt_ const struct bpf_program* next, _In_ const struct bpf_object* object);

/**
 * @brief Get next map in ebpf_object object.
 *
 * @param[in] previous Pointer to previous eBPF map, or NULL to get the first one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the next map, or NULL if none.
 */
_Ret_maybenull_ struct bpf_map*
ebpf_map_next(_In_opt_ const struct bpf_map* previous, _In_ const struct bpf_object* object);

/**
 * @brief Get previous map in ebpf_object object.
 *
 * @param[in] next Pointer to next eBPF map, or NULL to get the last one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the previous map, or NULL if none.
 */
_Ret_maybenull_ struct bpf_map*
ebpf_map_previous(_In_opt_ const struct bpf_map* next, _In_ const struct bpf_object* object);

/**
 * @brief Fetch fd for a program object.
 *
 * @param[in] program Pointer to eBPF program.
 * @return fd for the program on success, ebpf_fd_invalid on failure.
 */
fd_t
ebpf_program_get_fd(_In_ const struct bpf_program* program);

/**
 * @brief Fetch fd for a map object.
 *
 * @param[in] map Pointer to eBPF map.
 * @return fd for the map on success, ebpf_fd_invalid on failure.
 */
fd_t
ebpf_map_get_fd(_In_ const struct bpf_map* map);

/**
 * @brief Clean up ebpf_object. Also delete all the sub objects
 * (maps, programs) and close the related file descriptors.
 *
 * @param[in] object Pointer to ebpf_object.
 */
void
ebpf_object_close(_In_ _Post_invalid_ struct bpf_object* object);

void
initialize_map(_Out_ ebpf_map_t* map, _In_ const map_cache_t& map_cache);

/**
 * @brief Pin an eBPF map to specified path.
 * @param[in] program Pointer to eBPF map.
 * @param[in] path Pin path for the map.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_pin(_In_ struct bpf_map* map, _In_opt_z_ const char* path);

/**
 * @brief Unpin an eBPF map from the specified path.
 * @param[in] map Pointer to eBPF map.
 * @param[in] path Pin path for the map.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_unpin(_In_ struct bpf_map* map, _In_opt_z_ const char* path);

/**
 * @brief Set pin path for an eBPF map.
 * @param[in] map Pointer to eBPF map.
 * @param[in] path Pin path for the map.
 *
 * @retval EBPF_SUCCESS The API suceeded.
 * @retval EBPF_NO_MEMORY Out of memory.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 */
ebpf_result_t
ebpf_map_set_pin_path(_In_ struct bpf_map* map, _In_ const char* path);
