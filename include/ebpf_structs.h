// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file contains eBPF definitions common to eBPF programs, core execution engine
// as well as eBPF API library.

#pragma once

#include <stdint.h>
#include "../external/ebpf-verifier/src/ebpf_base.h"

typedef enum bpf_map_type
{
    BPF_MAP_TYPE_UNSPECIFIED = 0, ///< Unspecified map type.
    BPF_MAP_TYPE_HASH = 1,        ///< Hash table.
    BPF_MAP_TYPE_ARRAY = 2,       ///< Array, where the map key is the array index.
    BPF_MAP_TYPE_PROG_ARRAY =
        3, ///< Array of program fds usable with bpf_tail_call, where the map key is the array index.
    BPF_MAP_TYPE_PERCPU_HASH = 4,
    BPF_MAP_TYPE_PERCPU_ARRAY = 5,
    BPF_MAP_TYPE_HASH_OF_MAPS = 6,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 7,
} ebpf_map_type_t;

typedef enum ebpf_map_option
{
    // Create a new element or update an existing element.
    EBPF_ANY,
    // Create a new element only when it does not exist.
    EBPF_NOEXIST,
    // Update an existing element.
    EBPF_EXIST
} ebpf_map_option_t;

typedef uint32_t ebpf_id_t;
#define EBPF_ID_NONE UINT32_MAX

/**
 * @brief eBPF Map Definition as it is stored in memory.
 */
typedef struct _ebpf_map_definition_in_memory
{
    uint32_t size;        ///< Size in bytes of the ebpf_map_definition_t structure.
    ebpf_map_type_t type; ///< Type of map.
    uint32_t key_size;    ///< Size in bytes of a map key.
    uint32_t value_size;  ///< Size in bytes of a map value.
    uint32_t max_entries; ///< Maximum number of entries allowed in the map.
    ebpf_id_t inner_map_id;
} ebpf_map_definition_in_memory_t;

/**
 * @brief eBPF Map Definition as it appears in the maps section of an ELF file.
 */
typedef struct _ebpf_map_definition_in_file
{
    uint32_t size;        ///< Size in bytes of the ebpf_map_definition_t structure.
    ebpf_map_type_t type; ///< Type of map.
    uint32_t key_size;    ///< Size in bytes of a map key.
    uint32_t value_size;  ///< Size in bytes of a map value.
    uint32_t max_entries; ///< Maximum number of entries allowed in the map.

    /** When a map definition is hard coded in an eBPF program, inner_map_idx
     * indicates the 0-based index of which map in the maps section of the ELF
     * file is the inner map template.
     */
    uint32_t inner_map_idx;
} ebpf_map_definition_in_file_t;

typedef enum
{
    BPF_FUNC_map_lookup_elem = 1,
    BPF_FUNC_map_update_elem = 2,
    BPF_FUNC_map_delete_elem = 3,
    BPF_FUNC_tail_call = 4,
    BPF_FUNC_get_prandom_u32 = 5,
    BPF_FUNC_ktime_get_boot_ns = 6,
    BPF_FUNC_get_smp_processor_id = 7,
    BPF_FUNC_ktime_get_ns = 8,
} ebpf_helper_id_t;

// Libbpf itself requires the following structs to be defined, but doesn't
// care what fields they have.  Applications such as bpftool on the other
// hand depend on fields of specific names and types.

struct bpf_link_info
{
    ebpf_id_t id;      ///< Link ID.
    ebpf_id_t prog_id; ///< Program ID.
};

struct bpf_map_info
{
    ebpf_id_t id;         ///< Map ID.
    ebpf_map_type_t type; ///< Type of map.
    uint32_t key_size;    ///< Size in bytes of a map key.
    uint32_t value_size;  ///< Size in bytes of a map value.
    uint32_t max_entries; ///< Maximum number of entries allowed in the map.
};

#define BPF_OBJ_NAME_LEN 16

struct bpf_prog_info
{
    ebpf_id_t id;                ///< Program ID.
    uint32_t nr_map_ids;         ///< Number of maps associated with this program.
    char name[BPF_OBJ_NAME_LEN]; ///< Null-terminated program name.
};
