// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

//! @file linux/bpf.h
//! This file should be thought of as platform/bpf.h not Linux-specific per se.
//! It is needed under this path though since the Libbpf bpf.h includes it as such.

#include <stdint.h>
#include "ebpf_structs.h"

#ifdef _MSC_VER
// This file is being included by a user-mode Windows application.
#include "ebpf_program_types.h"
#include "ebpf_api.h"
#define LIBBPF_API
#include "libbpf/src/libbpf_common.h"
#undef LIBBPF_DEPRECATED
#define LIBBPF_DEPRECATED(x)
#else
// This file is being included by an eBPF program.
typedef int32_t s32;
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define __SIZEOF_SIZE_T__ 8    /* only x64 is supported */
#define __SIZEOF_LONG_LONG__ 8 /* only x64 is supported */

typedef int32_t __s32;

typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint32_t pid_t;

enum bpf_func_id
{
    BPF_FUNC_ID_UNKNOWN
};

enum bpf_stats_type
{
    BPF_STATS_TYPE_UNKNOWN
};

enum bpf_cmd_id
{
    BPF_MAP_CREATE,
    BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_PROG_LOAD,
    BPF_OBJ_PIN,
    BPF_OBJ_GET,
    BPF_PROG_GET_NEXT_ID,
    BPF_MAP_GET_NEXT_ID,
    BPF_LINK_GET_NEXT_ID,
    BPF_PROG_GET_FD_BY_ID,
    BPF_MAP_GET_FD_BY_ID,
    BPF_LINK_GET_FD_BY_ID,
    BPF_OBJ_GET_INFO_BY_FD,
    BPF_LINK_DETACH,
    BPF_PROG_BIND_MAP,
    BPF_PROG_TEST_RUN,
};

/// Attributes used by BPF_OBJ_GET_INFO_BY_FD.
typedef struct
{
    uint32_t bpf_fd; ///< File descriptor referring to an eBPF object.
    uint64_t info;   ///< Pointer to memory in which to write the info obtained.

    /**
     * @brief On input, contains the maximum number of bytes to write into the info. On output, contains
     * the actual number of bytes written.
     */
    uint32_t info_len;
} bpf_obj_info_attr_t;

/// Attributes used by BPF_LINK_DETACH.
typedef struct
{
    uint32_t link_fd; ///< File descriptor of link to detach.
} bpf_link_detach_attr_t;

/// Attributes used by BPF_PROG_BIND_MAP.
typedef struct
{
    uint32_t prog_fd; ///< File descriptor of program to bind map to.
    uint32_t map_fd;  ///< File descriptor of map to bind.
    uint32_t flags;   ///< Flags affecting the bind operation.
} bpf_prog_bind_map_attr_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union
#endif
/// Parameters used by the bpf() API.
union bpf_attr
{
    // BPF_MAP_CREATE
    struct
    {
        enum bpf_map_type map_type; ///< Type of map to create.
        uint32_t key_size;          ///< Size in bytes of keys.
        uint32_t value_size;        ///< Size in bytes of values.
        uint32_t max_entries;       ///< Maximum number of entries in the map.
        uint32_t map_flags;         ///< Flags (currently 0).
    };                              ///< Attributes used by BPF_MAP_CREATE.

    // BPF_MAP_LOOKUP_ELEM
    // BPF_MAP_UPDATE_ELEM
    // BPF_MAP_DELETE_ELEM
    // BPF_MAP_GET_NEXT_KEY
    struct
    {
        uint32_t map_fd; ///< File descriptor of map.
        uint64_t key;    ///< Pointer to key to look up.
        union
        {
            uint64_t value;    ///< Pointer to value.
            uint64_t next_key; ///< Pointer to next key.
        };
        uint64_t flags; ///< Flags (currently 0).
    }; ///< Attributes used by BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM, and BPF_MAP_GET_NEXT_KEY.

    // BPF_PROG_LOAD
    struct
    {
        enum bpf_prog_type prog_type; ///< Program type to use for loading the program.
        uint64_t insns;               ///< Array of instructions
        uint32_t insn_cnt;            ///< Number of instructions in the array.
        uint64_t license;      ///< Optional pointer to a string specifying the license (currently ignored on Windows).
        uint32_t log_level;    ///< Logging level (currently ignored on Windows).
        uint64_t log_buf;      ///< Pointer to a buffer in which log info can be written.
        uint32_t log_size;     ///< Size in bytes of the log buffer.
        uint32_t kern_version; ///< Kernel version (currently ignored on Windows).
    };                         ///< Attributes used by BPF_PROG_LOAD.

    // BPF_OBJ_PIN
    // BPF_OBJ_GET
    struct
    {
        uint64_t pathname; ///< Path name for pinning.
        uint32_t bpf_fd;   ///< File descriptor referring to the program or map.
    };                     ///< Attributes used by BPF_OBJ_PIN and BPF_OBJ_GET.

    // BPF_PROG_GET_NEXT_ID
    // BPF_MAP_GET_NEXT_ID
    // BPF_LINK_GET_NEXT_ID
    struct
    {
        uint32_t start_id; ///< ID to look for an ID after. The start_id need not exist.
        uint32_t next_id;  ///< On return, contains the next ID.
    };                     ///< Attributes used by BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID, and BPF_LINK_GET_NEXT_ID.

    // BPF_MAP_GET_FD_BY_ID
    uint32_t map_id; ///< ID of map for BPF_MAP_GET_FD_BY_ID to find.

    // BPF_PROG_GET_FD_BY_ID
    uint32_t prog_id; ///< ID of program for BPF_PROG_GET_FD_BY_ID to find.

    // BPF_LINK_GET_FD_BY_ID
    uint32_t link_id; ///< ID of link for BPF_LINK_GET_FD_BY_ID to find.

    // BPF_OBJ_GET_INFO_BY_FD
    bpf_obj_info_attr_t info; ///< Attributes used by BPF_OBJ_GET_INFO_BY_FD.

    // BPF_LINK_DETACH
    bpf_link_detach_attr_t link_detach; ///< Attributes used by BPF_LINK_DETACH.

    // BPF_PROG_BIND_MAP
    bpf_prog_bind_map_attr_t prog_bind_map; ///< Attributes used by BPF_PROG_BIND_MAP.

    // BPF_PROG_TEST_RUN
    struct
    {
        uint32_t prog_fd;       ///< File descriptor of program to run.
        uint32_t retval;        ///< On return, contains the return value of the program.
        uint32_t data_size_in;  ///< Size in bytes of input data.
        uint32_t data_size_out; ///< Size in bytes of output data.
        uint64_t data_in;       ///< Pointer to input data.
        uint64_t data_out;      ///< Pointer to output data.
        uint32_t repeat;        ///< Number of times to repeat the program.
        uint32_t duration;      ///< Duration in milliseconds to run the program.
        uint32_t ctx_size_in;   ///< Size in bytes of input context.
        uint32_t ctx_size_out;  ///< Size in bytes of output context.
        uint64_t ctx_in;        ///< Pointer to input context.
        uint64_t ctx_out;       ///< Pointer to output context.
    } test;                     ///< Attributes used by BPF_PROG_TEST_RUN.
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

int
bpf(int cmd, union bpf_attr* attr, unsigned int size);
