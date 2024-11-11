// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

//! @file linux/bpf.h
//! This file should be thought of as platform/bpf.h not Linux-specific per se.
//! It is needed under this path though since the Libbpf bpf.h includes it as such.

#include "ebpf_structs.h"

#include <stdint.h>

#ifdef _MSC_VER
// This file is being included by a user-mode Windows application.
#include "ebpf_api.h"
#include "ebpf_program_types.h"
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

// All types below must be ABI compatible with the Linux bpf() syscalls. This means
// that the order, size and alignment of the types must match uapi/linux/bpf.h in
// a tagged release of https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/.
// Constants must also match.
//
// Names do not have to match, but try to keep them the same as much as possible.
// In case of conflicts prefix them with "sys_" or "SYS_".

#define SYS_BPF_OBJ_NAME_LEN 16U

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
    BPF_PROG_ATTACH,
    BPF_PROG_DETACH,
    BPF_PROG_TEST_RUN,
    BPF_PROG_GET_NEXT_ID,
    BPF_MAP_GET_NEXT_ID,
    BPF_PROG_GET_FD_BY_ID,
    BPF_MAP_GET_FD_BY_ID,
    BPF_OBJ_GET_INFO_BY_FD,
    BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21,
    BPF_LINK_GET_FD_BY_ID = 30,
    BPF_LINK_GET_NEXT_ID,
    BPF_LINK_DETACH = 34,
    BPF_PROG_BIND_MAP = 35,
    BPF_PROG_RUN = BPF_PROG_TEST_RUN,
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(default : 4820) // reject implicit padding
#endif

/// Attributes used by BPF_MAP_CREATE.
typedef struct
{
    enum bpf_map_type map_type;          ///< Type of map to create.
    uint32_t key_size;                   ///< Size in bytes of keys.
    uint32_t value_size;                 ///< Size in bytes of values.
    uint32_t max_entries;                ///< Maximum number of entries in the map.
    uint32_t map_flags;                  ///< Not supported, must be zero.
    uint32_t inner_map_fd;               ///< File descriptor of inner map.
    uint32_t numa_node;                  ///< Not supported, must be zero.
    char map_name[SYS_BPF_OBJ_NAME_LEN]; ///< Map name.
    uint32_t map_ifindex;                ///< Not supported, must be zero.
} sys_bpf_map_create_attr_t;

typedef struct
{
    uint32_t map_fd; ///< File descriptor of map.
    uint32_t _pad0;
    uint64_t key;   ///< Pointer to key to look up.
    uint64_t value; ///< Pointer to value.
    uint64_t flags; ///< Not supported, must be zero.
} sys_bpf_map_lookup_attr_t;

typedef struct
{
    uint32_t map_fd; ///< File descriptor of map.
    uint32_t _pad0;
    uint64_t key; ///< Pointer to key to delete.
} sys_bpf_map_delete_attr_t;

typedef struct
{
    uint32_t map_fd; ///< File descriptor of map.
    uint32_t _pad0;
    uint64_t key;      ///< Pointer to key to look up.
    uint64_t next_key; ///< Pointer to next key.
} sys_bpf_map_next_key_attr_t;

typedef struct
{
    uint32_t start_id; ///< ID to look for an ID after. The start_id need not exist.
    uint32_t next_id;  ///< On return, contains the next ID.
} sys_bpf_map_next_id_attr_t;

typedef struct
{
    enum bpf_prog_type prog_type; ///< Program type to use for loading the program.
    uint32_t insn_cnt;            ///< Number of instructions in the array.
    uint64_t insns;               ///< Array of instructions.
    uint64_t license;      ///< Optional pointer to a string specifying the license (currently ignored on Windows).
    uint32_t log_level;    ///< Logging level (currently ignored on Windows).
    uint32_t log_size;     ///< Size in bytes of the log buffer.
    uint64_t log_buf;      ///< Pointer to a buffer in which log info can be written.
    uint32_t kern_version; ///< Kernel version (currently ignored on Windows).
    uint32_t prog_flags;   ///< Not supported, must be zero.
    char prog_name[SYS_BPF_OBJ_NAME_LEN]; ///< Program name.
} sys_bpf_prog_load_attr_t;

typedef struct
{
    uint32_t target_fd;               ///< eBPF target to attach/detach to/from.
    uint32_t attach_bpf_fd;           ///< File descriptor of program to attach to.
    enum bpf_attach_type attach_type; ///< Type of program to attach/detach to/from.
    uint32_t attach_flags;            ///< Flags affecting the attach operation.
} sys_bpf_prog_attach_attr_t;

typedef struct
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
    uint32_t flags;         ///< Flags (currently 0).
    uint32_t cpu;           ///< CPU to run the program on.
    uint32_t batch_size;    ///< Number of times to run the program in a batch.
    uint32_t _pad0;
} sys_bpf_prog_run_attr_t;

typedef struct
{
    uint64_t pathname; ///< Path name for pinning.
    uint32_t bpf_fd;   ///< File descriptor referring to the program or map.
    uint32_t flags;    ///< Not supported, must be zero.
} sys_bpf_obj_pin_attr_t;

/// Attributes used by BPF_OBJ_GET_INFO_BY_FD.
typedef struct
{
    uint32_t bpf_fd; ///< File descriptor referring to an eBPF object.
    /**
     * @brief On input, contains the maximum number of bytes to write into the info. On output, contains
     * the actual number of bytes written.
     */
    uint32_t info_len;
    uint64_t info; ///< Pointer to memory in which to write the info obtained.
} sys_bpf_obj_info_attr_t;

typedef struct
{
    ebpf_map_type_t type;            ///< Type of map.
    ebpf_id_t id;                    ///< Map ID.
    uint32_t key_size;               ///< Size in bytes of a map key.
    uint32_t value_size;             ///< Size in bytes of a map value.
    uint32_t max_entries;            ///< Maximum number of entries allowed in the map.
    uint32_t map_flags;              ///< Map flags.
    char name[SYS_BPF_OBJ_NAME_LEN]; ///< Null-terminated map name.
} sys_bpf_map_info_t;

typedef struct
{
    enum bpf_prog_type type;         ///< Program type.
    ebpf_id_t id;                    ///< Program ID.
    char tag[8];                     ///< Program tag.
    uint32_t jited_prog_len;         ///< Not supported.
    uint32_t xlated_prog_len;        ///< Not supported.
    uint64_t jited_prog_insns;       ///< Not supported.
    uint64_t xlated_prog_insns;      ///< Not supported.
    uint64_t load_time;              ///< Not supported.
    uint32_t created_by_uid;         ///< Not supported.
    uint32_t nr_map_ids;             ///< Number of maps associated with this program.
    uint64_t map_ids;                ///< Pointer to caller-allocated array to fill map IDs into.
    char name[SYS_BPF_OBJ_NAME_LEN]; ///< Null-terminated program name.
} sys_bpf_prog_info_t;

typedef struct
{
    enum bpf_link_type type; ///< Link type.
    ebpf_id_t id;            ///< Link ID.
    ebpf_id_t prog_id;       ///< Program ID.
} sys_bpf_link_info_t;

/// Attributes used by BPF_LINK_DETACH.
typedef struct
{
    uint32_t link_fd; ///< File descriptor of link to detach.
} sys_bpf_link_detach_attr_t;

/// Attributes used by BPF_PROG_BIND_MAP.
typedef struct
{
    uint32_t prog_fd; ///< File descriptor of program to bind map to.
    uint32_t map_fd;  ///< File descriptor of map to bind.
    uint32_t flags;   ///< Flags affecting the bind operation.
} sys_bpf_prog_bind_map_attr_t;

/// Parameters used by the bpf() API.
union bpf_attr
{
    // BPF_MAP_CREATE
    sys_bpf_map_create_attr_t map_create; ///< Attributes used by BPF_MAP_CREATE.

    // BPF_MAP_LOOKUP_ELEM
    // BPF_MAP_UPDATE_ELEM
    sys_bpf_map_lookup_attr_t map_lookup,
        map_update; ///< Attributes used by BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM and

    // BPF_MAP_GET_NEXT_KEY
    sys_bpf_map_next_key_attr_t map_get_next_key; ///< Attributes used by BPF_MAP_GET_NEXT_KEY.

    // BPF_MAP_DELETE_ELEM
    sys_bpf_map_delete_attr_t map_delete; ///< Attributes used by BPF_MAP_DELETE_ELEM.

    // BPF_PROG_LOAD
    sys_bpf_prog_load_attr_t prog_load; ///< Attributes used by BPF_PROG_LOAD.

    // BPF_PROG_ATTACH
    // BPF_PROG_DETACH
    sys_bpf_prog_attach_attr_t prog_attach, prog_detach; ///< Attributes used by BPF_PROG_ATTACH/DETACH.

    // BPF_OBJ_PIN
    // BPF_OBJ_GET
    sys_bpf_obj_pin_attr_t obj_pin, obj_get; ///< Attributes used by BPF_OBJ_PIN and BPF_OBJ_GET.

    // BPF_PROG_GET_NEXT_ID
    // BPF_MAP_GET_NEXT_ID
    // BPF_LINK_GET_NEXT_ID
    sys_bpf_map_next_id_attr_t map_get_next_id, prog_get_next_id,
        link_get_next_id; ///< Attributes used by BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID, and BPF_LINK_GET_NEXT_ID.

    // BPF_MAP_GET_FD_BY_ID
    uint32_t map_id; ///< ID of map for BPF_MAP_GET_FD_BY_ID to find.

    // BPF_PROG_GET_FD_BY_ID
    uint32_t prog_id; ///< ID of program for BPF_PROG_GET_FD_BY_ID to find.

    // BPF_LINK_GET_FD_BY_ID
    uint32_t link_id; ///< ID of link for BPF_LINK_GET_FD_BY_ID to find.

    // BPF_OBJ_GET_INFO_BY_FD
    sys_bpf_obj_info_attr_t info; ///< Attributes used by BPF_OBJ_GET_INFO_BY_FD.

    // BPF_LINK_DETACH
    sys_bpf_link_detach_attr_t link_detach; ///< Attributes used by BPF_LINK_DETACH.

    // BPF_PROG_BIND_MAP
    sys_bpf_prog_bind_map_attr_t prog_bind_map; ///< Attributes used by BPF_PROG_BIND_MAP.

    // BPF_PROG_TEST_RUN
    sys_bpf_prog_run_attr_t test; ///< Attributes used by BPF_PROG_TEST_RUN.
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

int
bpf(int cmd, union bpf_attr* attr, unsigned int size);
