// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FIELD_SIZE(s, m) (sizeof(((s*)0)->m))
#define EBPF_SIZE_INCLUDING_FIELD(s, m) (EBPF_OFFSET_OF(s, m) + EBPF_FIELD_SIZE(s, m))

#ifdef _MSC_VER
#include <guiddef.h>
#else
typedef uint8_t GUID[16];
#endif

#if !defined(NO_CRT) && !defined(_NO_CRT_STDIO_INLINE)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned short wchar_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long long size_t;
#define bool _Bool
#endif

// This file contains eBPF definitions needed by eBPF programs as well as
// the verifier, execution context and extension drivers.

#define EBPF_ROOT_REGISTRY_PATH L"\\Registry\\Machine\\Software\\eBPF"
#define EBPF_ROOT_RELATIVE_PATH L"Software\\eBPF"
#define EBPF_STORE_REGISTRY_PATH L"Software\\eBPF\\Providers"

#define EBPF_PROVIDERS_REGISTRY_KEY L"Providers"
#define EBPF_SECTIONS_REGISTRY_KEY L"SectionData"
#define EBPF_PROGRAM_DATA_REGISTRY_KEY L"ProgramData"
#define EBPF_PROGRAM_TYPE_DESCRIPTOR_REGISTRY_KEY L"TypeDescriptor"
#define EBPF_PROGRAM_DATA_HELPERS_REGISTRY_KEY L"Helpers"
#define EBPF_GLOBAL_HELPERS_REGISTRY_KEY L"GlobalHelpers"

#define EBPF_EXTENSION_HEADER_VERSION L"Version"
#define EBPF_EXTENSION_HEADER_SIZE L"Size"

#define EBPF_SECTION_DATA_PROGRAM_TYPE L"ProgramType"
#define EBPF_SECTION_DATA_ATTACH_TYPE L"AttachType"

#define EBPF_PROGRAM_DATA_NAME L"Name"
#define EBPF_PROGRAM_DATA_CONTEXT_DESCRIPTOR L"ContextDescriptor"
#define EBPF_PROGRAM_DATA_PLATFORM_SPECIFIC_DATA L"PlatformSpecificData"
#define EBPF_PROGRAM_DATA_PRIVILEGED L"IsPrivileged"
#define EBPF_PROGRAM_DATA_HELPER_COUNT L"HelperCount"

#define EBPF_HELPER_DATA_PROTOTYPE L"Prototype"
#define EBPF_HELPER_DATA_REALLOCATE_PACKET L"ReallocatePacket"

#define EBPF_DATA_BPF_PROG_TYPE L"BpfProgType"
#define EBPF_DATA_BPF_ATTACH_TYPE L"BpfAttachType"

typedef GUID ebpf_program_type_t;
typedef GUID ebpf_attach_type_t;

typedef enum _ebpf_helper_function
{
    EBPF_LOOKUP_ELEMENT = 1, ///< Look up a map element.
    EBPF_UPDATE_ELEMENT = 2, ///< Update map element.
    EBPF_DELETE_ELEMENT = 3, ///< Delete a map element.
} ebpf_helper_function_t;

#define EBPF_MAX_GENERAL_HELPER_FUNCTION 0xFFFF

#define EBPF_ATTACH_CLIENT_DATA_CURRENT_VERSION 1

#define EBPF_ATTACH_CLIENT_DATA_VERSION_SIZE EBPF_SIZE_INCLUDING_FIELD(ebpf_extension_data_t, prog_attach_flags)
#define EBPF_ATTACH_CLIENT_DATA_VERSION_TOTAL_SIZE sizeof(ebpf_extension_data_t)
#define EBPF_ATTACH_CLIENT_DATA_HEADER_VERSION \
    {EBPF_ATTACH_CLIENT_DATA_CURRENT_VERSION,  \
     EBPF_ATTACH_CLIENT_DATA_VERSION_SIZE,     \
     EBPF_ATTACH_CLIENT_DATA_VERSION_TOTAL_SIZE}

// Version 1 of the eBPF extension data structures and their lengths.
#define EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION 1
#define EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE EBPF_SIZE_INCLUDING_FIELD(ebpf_attach_provider_data_t, link_type)
#define EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_attach_provider_data_t)
#define EBPF_ATTACH_PROVIDER_DATA_HEADER             \
    {EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION,      \
     EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE, \
     EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION 1
#define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_program_type_descriptor_t, is_privileged)
#define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_program_type_descriptor_t)
#define EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER             \
    {EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION,      \
     EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE, \
     EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION 1
#define EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_prototype_t, implicit_context)
#define EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_helper_function_prototype_t)
#define EBPF_HELPER_FUNCTION_PROTOTYPE_HEADER             \
    {EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION,      \
     EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE, \
     EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_PROGRAM_INFORMATION_CURRENT_VERSION 1
#define EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_program_info_t, global_helper_prototype)
#define EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_program_info_t)
#define EBPF_PROGRAM_INFORMATION_HEADER             \
    {EBPF_PROGRAM_INFORMATION_CURRENT_VERSION,      \
     EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE, \
     EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION 1
#define EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_helper_function_addresses_t, helper_function_address)
#define EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_helper_function_addresses_t)
#define EBPF_HELPER_FUNCTION_ADDRESSES_HEADER             \
    {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION,      \
     EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE, \
     EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_PROGRAM_DATA_CURRENT_VERSION 1
#define EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE EBPF_SIZE_INCLUDING_FIELD(ebpf_program_data_t, capabilities)
#define EBPF_PROGRAM_DATA_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_program_data_t)
#define EBPF_PROGRAM_DATA_HEADER             \
    {EBPF_PROGRAM_DATA_CURRENT_VERSION,      \
     EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE, \
     EBPF_PROGRAM_DATA_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION 1
#define EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_program_section_info_t, bpf_attach_type)
#define EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_program_section_info_t)
#define EBPF_PROGRAM_SECTION_INFORMATION_HEADER             \
    {EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION,      \
     EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE, \
     EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_MAP_PROVIDER_DATA_CURRENT_VERSION 1
#define EBPF_MAP_PROVIDER_DATA_CURRENT_VERSION_SIZE EBPF_SIZE_INCLUDING_FIELD(ebpf_map_provider_data_t, dispatch_table)
#define EBPF_MAP_PROVIDER_DATA_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_map_provider_data_t)
#define EBPF_MAP_PROVIDER_DATA_HEADER             \
    {EBPF_MAP_PROVIDER_DATA_CURRENT_VERSION,      \
     EBPF_MAP_PROVIDER_DATA_CURRENT_VERSION_SIZE, \
     EBPF_MAP_PROVIDER_DATA_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_MAP_CLIENT_DATA_CURRENT_VERSION 1
#define EBPF_MAP_CLIENT_DATA_CURRENT_VERSION_SIZE EBPF_SIZE_INCLUDING_FIELD(ebpf_map_client_data_t, dispatch_table)
#define EBPF_MAP_CLIENT_DATA_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_map_client_data_t)
#define EBPF_MAP_CLIENT_DATA_HEADER             \
    {EBPF_MAP_CLIENT_DATA_CURRENT_VERSION,      \
     EBPF_MAP_CLIENT_DATA_CURRENT_VERSION_SIZE, \
     EBPF_MAP_CLIENT_DATA_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_MAP_PROVIDER_DISPATCH_TABLE_CURRENT_VERSION 1
#define EBPF_MAP_PROVIDER_DISPATCH_TABLE_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_map_provider_dispatch_table_t, get_next_key_and_value_function)
#define EBPF_MAP_PROVIDER_DISPATCH_TABLE_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_map_provider_dispatch_table_t)
#define EBPF_MAP_PROVIDER_DISPATCH_TABLE_HEADER             \
    {EBPF_MAP_PROVIDER_DISPATCH_TABLE_CURRENT_VERSION,      \
     EBPF_MAP_PROVIDER_DISPATCH_TABLE_CURRENT_VERSION_SIZE, \
     EBPF_MAP_PROVIDER_DISPATCH_TABLE_CURRENT_VERSION_TOTAL_SIZE}

#define EBPF_MAP_CLIENT_DISPATCH_TABLE_CURRENT_VERSION 1
#define EBPF_MAP_CLIENT_DISPATCH_TABLE_CURRENT_VERSION_SIZE \
    EBPF_SIZE_INCLUDING_FIELD(ebpf_map_client_dispatch_table_t, epoch_free_cache_aligned)
#define EBPF_MAP_CLIENT_DISPATCH_TABLE_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_map_client_dispatch_table_t)
#define EBPF_MAP_CLIENT_DISPATCH_TABLE_HEADER             \
    {EBPF_MAP_CLIENT_DISPATCH_TABLE_CURRENT_VERSION,      \
     EBPF_MAP_CLIENT_DISPATCH_TABLE_CURRENT_VERSION_SIZE, \
     EBPF_MAP_CLIENT_DISPATCH_TABLE_CURRENT_VERSION_TOTAL_SIZE}

/**
 * @brief Header of an eBPF extension data structure.
 * Every eBPF extension data structure must start with this header.
 * New fields can be added to the end of an eBPF extension data structure
 * without breaking backward compatibility. The version field must be
 * updated only if the new data structure is not backward compatible.
 */
typedef struct _ebpf_extension_header
{
    uint16_t version;  ///< Version of the extension data structure.
    size_t size;       ///< Size of the extension data structure not including any padding.
    size_t total_size; ///< Total size of the extension data structure including any padding.
} ebpf_extension_header_t;
