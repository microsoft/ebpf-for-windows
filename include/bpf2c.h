// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_structs.h"

#if defined(NO_CRT)
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define bool _Bool
#define false 0
#define true 1
#define UINT32_MAX ((uint32_t)0xFFFFFFFF)

#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define UBPF_STACK_SIZE 512

#define IMMEDIATE(X) (int32_t) X
#define OFFSET(X) (int16_t) X
#define POINTER(X) (uint64_t)(X)

#if !defined(htobe16)
#define htobe16(X) swap16(X)
#define htobe32(X) swap32(X)
#define htobe64(X) swap64(X)

#define htole16(X) (X)
#define htole32(X) (X)
#define htole64(X) (X)
#endif

#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FIELD_SIZE(s, m) (sizeof(((s*)0)->m))
#define EBPF_SIZE_INCLUDING_FIELD(s, m) (EBPF_OFFSET_OF(s, m) + EBPF_FIELD_SIZE(s, m))

#define NATIVE_MODULE_HELPER_ENTRY_VERSION_1 1
#define NATIVE_MODULE_HELPER_ENTRY_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(helper_function_entry_t, tail_call)

#define NATIVE_MODULE_MAP_ENTRY_VERSION_1 1
#define NATIVE_MODULE_MAP_ENTRY_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(map_entry_t, name)

#define NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_1 1
#define NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(map_initial_values_t, values)

#define NATIVE_MODULE_PROGRAM_ENTRY_VERSION_1 1
#define NATIVE_MODULE_PROGRAM_ENTRY_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(program_entry_t, program_info_hash_type)

#define NATIVE_MODULE_METADATA_TABLE_VERSION_1 1
#define NATIVE_MODULE_METADATA_TABLE_VERSION_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(metadata_table_t, map_initial_values)

#define NATIVE_MODULE_HELPER_ENTRY_CURRENT_VERSION NATIVE_MODULE_HELPER_ENTRY_VERSION_1
#define NATIVE_MODULE_HELPER_ENTRY_CURRENT_VERSION_SIZE NATIVE_MODULE_HELPER_ENTRY_VERSION_SIZE_1

#define NATIVE_MODULE_MAP_ENTRY_CURRENT_VERSION NATIVE_MODULE_MAP_ENTRY_VERSION_1
#define NATIVE_MODULE_MAP_ENTRY_CURRENT_VERSION_SIZE NATIVE_MODULE_MAP_ENTRY_VERSION_SIZE_1

#define NATIVE_MODULE_MAP_INITIAL_VALUES_CURRENT_VERSION NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_1
#define NATIVE_MODULE_MAP_INITIAL_VALUES_CURRENT_VERSION_SIZE NATIVE_MODULE_MAP_INITIAL_VALUES_VERSION_SIZE_1

#define NATIVE_MODULE_PROGRAM_ENTRY_CURRENT_VERSION NATIVE_MODULE_PROGRAM_ENTRY_VERSION_1
#define NATIVE_MODULE_PROGRAM_ENTRY_CURRENT_VERSION_SIZE NATIVE_MODULE_PROGRAM_ENTRY_VERSION_SIZE_1

#define NATIVE_MODULE_METADATA_TABLE_CURRENT_VERSION NATIVE_MODULE_METADATA_TABLE_VERSION_1
#define NATIVE_MODULE_METADATA_TABLE_CURRENT_VERSION_SIZE NATIVE_MODULE_METADATA_TABLE_VERSION_SIZE_1

    typedef struct _ebpf_extension_header
    {
        uint16_t version; ///< Version of the extension data structure.
        size_t size;      ///< Size of the extension data structure.
    } ebpf_extension_header_t;

    /**
     * @brief Helper function entry.
     * This structure defines a helper function entry in the metadata table. The address of the helper function is
     * written into the entry during load time. The helper_id and name are used to identify the helper function
     * to bind to when the program is loaded.
     */
    typedef struct _helper_function_entry
    {
        ebpf_extension_header_t header;
        uint64_t (*address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
        uint32_t helper_id;
        const char* name;
        bool tail_call;
    } helper_function_entry_t;

    /**
     * @brief Map entry.
     * This structure contains the address of the map and the map definition. The address is written into the entry
     * during load time. The map definition is used to initialize the map when the program is loaded.
     */
    typedef struct _map_entry
    {
        ebpf_extension_header_t header;
        void* address;
        ebpf_map_definition_in_file_t definition;
        const char* name;
    } map_entry_t;

    /**
     * @brief Map initial values.
     * This structure contains the initial values for a map. The values are used to initialize the map when the
     * program is loaded. Values are specified as strings and are converted to the appropriate type based on the
     * map definition. Only BPF_MAP_TYPE_ARRAY_OF_MAPS and BPF_MAP_TYPE_PROG_ARRAY map types are supported.
     */
    typedef struct _map_initial_values
    {
        ebpf_extension_header_t header;
        const char* name;    // Name of the map.
        size_t count;        // Number of values in the map.
        const char** values; // Array of strings containing the initial values.
    } map_initial_values_t;

    /**
     * @brief Program entry.
     * This structure contains the address of the program and additional information about the program.
     */
    typedef struct _program_entry
    {
        // DLLs put the strings into the same section, so add a marker
        // at the start of a program entry to make it easy to find
        // entries in the programs section.
        uint64_t zero;

        ebpf_extension_header_t header;           ///< Header for the program entry.
        uint64_t (*function)(void*);              ///< Address of the program.
        const char* pe_section_name;              ///< Name of the PE section containing the program.
        const char* section_name;                 ///< Name of the section containing the program.
        const char* program_name;                 ///< Name of the program.
        uint16_t* referenced_map_indices;         ///< List of map indices referenced by the program.
        uint16_t referenced_map_count;            ///< Number of maps referenced by the program.
        helper_function_entry_t* helpers;         ///< List of helper functions used by the program.
        uint16_t helper_count;                    ///< Number of helper functions used by the program.
        size_t bpf_instruction_count;             ///< Number of BPF instructions in the program.
        ebpf_program_type_t* program_type;        ///< Type of the program.
        ebpf_attach_type_t* expected_attach_type; ///< Expected attach type of the program.
        const uint8_t* program_info_hash;         ///< Hash of the program info.
        size_t program_info_hash_length;          ///< Length of the program info hash.
        const char* program_info_hash_type;       ///< Type of the program info hash
    } program_entry_t;

    /**
     * @brief Version information for the bpf2c compiler.
     * This structure contains the version information for the bpf2c compiler that generated the module. It can be
     * used to determine if the module is compatible with the current version of the eBPF for Windows runtime.
     */
    typedef struct _bpf2c_version
    {
        uint32_t major;
        uint32_t minor;
        uint32_t revision;
    } bpf2c_version_t;

    /**
     * @brief Metadata table for a module.
     * This structure is returned by the module's metadata function, get_metadata_table and contains
     * information about the module including the list of programs and maps.
     */
    typedef struct _metadata_table
    {
        ebpf_extension_header_t header;
        // TODO: "size" needs to be removed.
        size_t size;
        void (*programs)(
            _Outptr_result_buffer_maybenull_(*count) program_entry_t** programs,
            _Out_ size_t* count); ///< Returns the list of programs in this module.
        void (*maps)(
            _Outptr_result_buffer_maybenull_(*count) map_entry_t** maps,
            _Out_ size_t* count); ///< Returns the list of maps in this module.
        void (*hash)(
            _Outptr_result_buffer_maybenull_(*size) const uint8_t** hash,
            _Out_ size_t* size); ///< Returns the hash of the ELF file used to generate this module.
        void (*version)(_Out_ bpf2c_version_t* version);
        void (*map_initial_values)(
            _Outptr_result_buffer_maybenull_(*count) map_initial_values_t** map_initial_values,
            _Out_ size_t* count); ///< Returns the list of initial values for maps in this module.
    } metadata_table_t;

    /**
     * @brief Inline function used to implement the 16 bit EBPF_OP_LE/EBPF_OP_BE instruction.
     *
     * @param[in] value The value to swap.
     * @return The swapped value.
     */
    inline uint16_t
    swap16(uint16_t value)
    {
        return value << 8 | value >> 8;
    }

    /**
     * @brief Inline function used to implement the 32 bit EBPF_OP_LE/EBPF_OP_BE instruction.
     *
     * @param[in] value The value to swap.
     * @return The swapped value.
     */
    inline uint32_t
    swap32(uint32_t value)
    {
        return swap16(value >> 16) | ((uint32_t)swap16(value & ((1 << 16) - 1))) << 16;
    }

    /**
     * @brief Inline function used to implement the 64 bit EBPF_OP_LE/EBPF_OP_BE instruction.
     *
     * @param[in] value The value to swap.
     * @return The swapped value.
     */
    inline uint64_t
    swap64(uint64_t value)
    {
        return swap32(value >> 32) | ((uint64_t)swap32(value & ((1ull << 32ull) - 1))) << 32;
    }

#ifdef __cplusplus
}
#endif
