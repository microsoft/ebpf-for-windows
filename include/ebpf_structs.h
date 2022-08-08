// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file contains eBPF definitions common to eBPF programs, core execution engine
// as well as eBPF API library.

#pragma once

#if !defined(NO_CRT)
#include <stdbool.h>
#include <stdint.h>
#endif
#include "ebpf_windows.h"

#define BPF_ENUM_TO_STRING(X) #X

typedef enum bpf_map_type
{
    BPF_MAP_TYPE_UNSPEC = 0, ///< Unspecified map type.
    BPF_MAP_TYPE_HASH = 1,   ///< Hash table.
    BPF_MAP_TYPE_ARRAY = 2,  ///< Array, where the map key is the array index.
    BPF_MAP_TYPE_PROG_ARRAY =
        3, ///< Array of program fds usable with bpf_tail_call, where the map key is the array index.
    BPF_MAP_TYPE_PERCPU_HASH = 4,      ///< Per-CPU hash table.
    BPF_MAP_TYPE_PERCPU_ARRAY = 5,     ///< Per-CPU array.
    BPF_MAP_TYPE_HASH_OF_MAPS = 6,     ///< Hash table, where the map value is another map.
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 7,    ///< Array, where the map value is another map.
    BPF_MAP_TYPE_LRU_HASH = 8,         ///< Least-recently-used hash table.
    BPF_MAP_TYPE_LPM_TRIE = 9,         ///< Longest prefix match trie.
    BPF_MAP_TYPE_QUEUE = 10,           ///< Queue.
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 11, ///< Per-CPU least-recently-used hash table.
    BPF_MAP_TYPE_STACK = 12,           ///< Stack.
    BPF_MAP_TYPE_RINGBUF = 13          ///< Ring buffer.
} ebpf_map_type_t;

static const char* const _ebpf_map_type_names[] = {
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_UNSPEC),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_HASH),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_ARRAY),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_PROG_ARRAY),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_PERCPU_HASH),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_PERCPU_ARRAY),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_HASH_OF_MAPS),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_ARRAY_OF_MAPS),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_LRU_HASH),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_LPM_TRIE),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_QUEUE),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_LRU_PERCPU_HASH),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_STACK),
    BPF_ENUM_TO_STRING(BPF_MAP_TYPE_RINGBUF),
};

static const char* const _ebpf_map_display_names[] = {
    "unspec",
    "hash",
    "array",
    "prog_array",
    "percpu_hash",
    "percpu_array",
    "hash_of_maps",
    "array_of_maps",
    "lru_hash",
    "lpm_trie",
    "queue",
    "lru_percpu_hash",
    "stack",
    "ringbuf",
};

typedef enum ebpf_map_option
{
    EBPF_ANY,     ///< Create a new element or update an existing element.
    EBPF_NOEXIST, ///< Create a new element only when it does not exist.
    EBPF_EXIST    ///< Update an existing element.
} ebpf_map_option_t;

typedef enum ebpf_pin_type
{
    PIN_NONE,      ///< Object is not pinned.
    PIN_OBJECT_NS, ///< Pinning that is local to an object.
    PIN_GLOBAL_NS, ///< Pinning with a global namespace.
    PIN_CUSTOM_NS  ///< Pinning with a custom path given as section parameter.
} ebpf_pin_type_t;

static const char* const _ebpf_pin_type_names[] = {
    BPF_ENUM_TO_STRING(PIN_NONE),
    BPF_ENUM_TO_STRING(PIN_OBJECT_NS),
    BPF_ENUM_TO_STRING(PIN_GLOBAL_NS),
    BPF_ENUM_TO_STRING(PIN_CUSTOM_NS),
};

typedef uint32_t ebpf_id_t;
#define EBPF_ID_NONE UINT32_MAX

/**
 * @brief eBPF Map Definition as it is stored in memory.
 */
typedef struct _ebpf_map_definition_in_memory
{
    ebpf_map_type_t type; ///< Type of map.
    uint32_t key_size;    ///< Size in bytes of a map key.
    uint32_t value_size;  ///< Size in bytes of a map value.
    uint32_t max_entries; ///< Maximum number of entries allowed in the map.
    ebpf_id_t inner_map_id;
    ebpf_pin_type_t pinning;
} ebpf_map_definition_in_memory_t;

/**
 * @brief eBPF Map Definition as it appears in the maps section of an ELF file.
 */
typedef struct _ebpf_map_definition_in_file
{
    ebpf_map_type_t type; ///< Type of map.
    uint32_t key_size;    ///< Size in bytes of a map key.
    uint32_t value_size;  ///< Size in bytes of a map value.
    uint32_t max_entries; ///< Maximum number of entries allowed in the map.

    /** When a map definition is hard coded in an eBPF program, inner_map_idx
     * indicates the 0-based index of which map in the maps section of the ELF
     * file is the inner map template.
     */
    uint32_t inner_map_idx;
    ebpf_pin_type_t pinning;

    /** id is the identifier for a map template.
     */
    uint32_t id;
    /** For a map of map, inner_id is the id of the inner map template.
     */
    uint32_t inner_id;
} ebpf_map_definition_in_file_t;

typedef enum
{
    BPF_FUNC_map_lookup_elem = 1,            ///< \ref bpf_map_lookup_elem
    BPF_FUNC_map_update_elem = 2,            ///< \ref bpf_map_update_elem
    BPF_FUNC_map_delete_elem = 3,            ///< \ref bpf_map_delete_elem
    BPF_FUNC_map_lookup_and_delete_elem = 4, ///< \ref bpf_map_lookup_and_delete_elem
    BPF_FUNC_tail_call = 5,                  ///< \ref bpf_tail_call
    BPF_FUNC_get_prandom_u32 = 6,            ///< \ref bpf_get_prandom_u32
    BPF_FUNC_ktime_get_boot_ns = 7,          ///< \ref bpf_ktime_get_boot_ns
    BPF_FUNC_get_smp_processor_id = 8,       ///< \ref bpf_get_smp_processor_id
    BPF_FUNC_ktime_get_ns = 9,               ///< \ref bpf_ktime_get_ns
    BPF_FUNC_csum_diff = 10,                 ///< \ref bpf_csum_diff
    BPF_FUNC_ringbuf_output = 11,            ///< \ref bpf_ringbuf_output
    BPF_FUNC_trace_printk2 = 12,             ///< \ref bpf_trace_printk2 (but use \ref bpf_printk instead)
    BPF_FUNC_trace_printk3 = 13,             ///< \ref bpf_trace_printk3 (but use \ref bpf_printk instead)
    BPF_FUNC_trace_printk4 = 14,             ///< \ref bpf_trace_printk4 (but use \ref bpf_printk instead)
    BPF_FUNC_trace_printk5 = 15,             ///< \ref bpf_trace_printk5 (but use \ref bpf_printk instead)
    BPF_FUNC_map_push_elem = 16,             ///< \ref bpf_map_push_elem
    BPF_FUNC_map_pop_elem = 17,              ///< \ref bpf_map_pop_elem
    BPF_FUNC_map_peek_elem = 18,             ///< \ref bpf_map_peek_elem
    BPF_FUNC_get_current_pid_tgid = 19,      ///< \ref bpf_get_current_pid_tgid
} ebpf_helper_id_t;

// Cross-platform BPF program types.
enum bpf_prog_type
{
    BPF_PROG_TYPE_UNSPEC, ///< Unspecified program type.

    /** @brief Program type for handling incoming packets as early as possible.
     *
     * **eBPF program prototype:** \ref xdp_hook_t
     *
     * **Attach type(s):** \ref BPF_XDP
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_XDP,

    /** @brief Program type for handling socket bind() requests.
     *
     * **eBPF program prototype:** \ref bind_hook_t
     *
     * **Attach type(s):** \ref BPF_ATTACH_TYPE_BIND
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_BIND, // TODO(#333): replace with cross-platform program type

    /** @brief Program type for handling various socket operations such as connect(), accept() etc.
     *
     * **eBPF program prototype:** \ref sock_addr_hook_t
     *
     * **Attach type(s):**
     *  \ref BPF_CGROUP_INET4_CONNECT
     *  \ref BPF_CGROUP_INET6_CONNECT
     *  \ref BPF_CGROUP_INET4_RECV_ACCEPT
     *  \ref BPF_CGROUP_INET6_RECV_ACCEPT
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,

    /** @brief Program type for handling various socket event notifications such as connection established etc.
     *
     * **eBPF program prototype:** \ref sock_ops_hook_t
     *
     * **Attach type(s):**
     *  \ref BPF_CGROUP_SOCK_OPS
     *
     * **Helpers available:** all helpers defined in bpf_helpers.h
     */
    BPF_PROG_TYPE_SOCK_OPS,

    /** @brief Program type for handling calls from the eBPF sample extension. Used for
     * testing.
     *
     * **eBPF program prototype:** see the eBPF sample extension.
     *
     * **Attach type(s):** \ref BPF_ATTACH_TYPE_SAMPLE
     */
    BPF_PROG_TYPE_SAMPLE = 999
};

typedef enum bpf_prog_type bpf_prog_type_t;

#define XDP_FLAGS_REPLACE 0x01

// The link type is used to tell which union member is present
// in the bpf_link_info struct.  There is exactly one non-zero value
// per union member.
enum bpf_link_type
{
    BPF_LINK_TYPE_UNSPEC, ///< Unspecified link type.
    BPF_LINK_TYPE_PLAIN,  ///< No union members are used in bpf_link_info.
    BPF_LINK_TYPE_CGROUP, ///< cgroup struct is present in bpf_link_info.
    BPF_LINK_TYPE_XDP,    ///< xdp struct is present in bpf_link_info.
};

static const char* const _ebpf_link_display_names[] = {
    "unspec",
    "plain",
};

enum bpf_attach_type
{
    BPF_ATTACH_TYPE_UNSPEC, ///< Unspecified attach type.

    /** @brief Attach type for handling incoming packets as early as possible.
     *
     * **Program type:** \ref BPF_PROG_TYPE_XDP
     */
    BPF_XDP,

    /** @brief Attach type for handling socket bind() requests.
     *
     * **Program type:** \ref BPF_PROG_TYPE_BIND
     */
    BPF_ATTACH_TYPE_BIND,

    /** @brief Attach type for handling IPv4 TCP connect() or UDP send
     * to a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET4_CONNECT,

    /** @brief Attach type for handling IPv6 TCP connect() or UDP send
     * to a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET6_CONNECT,

    /** @brief Attach type for handling IPv4 TCP accept() or on receiving
     * the first unicast UDP packet from a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET4_RECV_ACCEPT,

    /** @brief Attach type for handling IPv6 TCP accept() or on receiving
     * the first unicast UDP packet from a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET6_RECV_ACCEPT,

    /** @brief Attach type for handling various socket event notifications.
     *
     * **Program type:** \ref BPF_PROG_TYPE_SOCK_OPS
     */
    BPF_CGROUP_SOCK_OPS,

    /** @brief Attach type implemented by eBPF Sample Extension driver, used for testing.
     *
     * **Program type:** \ref BPF_PROG_TYPE_SAMPLE
     */
    BPF_ATTACH_TYPE_SAMPLE,

    __MAX_BPF_ATTACH_TYPE,
};

typedef enum bpf_attach_type bpf_attach_type_t;

// Libbpf itself requires the following structs to be defined, but doesn't
// care what fields they have.  Applications such as bpftool on the other
// hand depend on fields of specific names and types.

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201) /* nameless struct/union */
#endif
/**
 * @brief eBPF link information.  This structure can be retrieved by calling
 * \ref bpf_obj_get_info_by_fd on a link fd.
 */
struct bpf_link_info
{
    ebpf_id_t id;                          ///< Link ID.
    ebpf_id_t prog_id;                     ///< Program ID.
    enum bpf_link_type type;               ///< Link type.
    enum bpf_attach_type attach_type;      ///< Attach type.
    ebpf_attach_type_t attach_type_uuid;   ///< Attach type UUID.
    ebpf_program_type_t program_type_uuid; ///< Program type UUID.
    union
    {
        struct
        {
            uint32_t ifindex;
        } xdp;
        struct
        {
            uint64_t cgroup_id;
        } cgroup;
        uint8_t attach_data;
    };
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#define BPF_OBJ_NAME_LEN 64

/**
 * @brief eBPF map information.  This structure can be retrieved by calling
 * \ref bpf_obj_get_info_by_fd on a map fd.
 */
struct bpf_map_info
{
    // Cross-platform fields.
    ebpf_id_t id;                ///< Map ID.
    ebpf_map_type_t type;        ///< Type of map.
    uint32_t key_size;           ///< Size in bytes of a map key.
    uint32_t value_size;         ///< Size in bytes of a map value.
    uint32_t max_entries;        ///< Maximum number of entries allowed in the map.
    char name[BPF_OBJ_NAME_LEN]; ///< Null-terminated map name.
    uint32_t map_flags;          ///< Map flags.

    // Windows-specific fields.
    ebpf_id_t inner_map_id;     ///< ID of inner map template.
    uint32_t pinned_path_count; ///< Number of pinned paths.
};

#define BPF_ANY 0x0
#define BPF_NOEXIST 0x1
#define BPF_EXIST 0x2

/**
 * @brief eBPF program information.  This structure can be retrieved by calling
 * \ref bpf_obj_get_info_by_fd on a program fd.
 */
struct bpf_prog_info
{
    // Cross-platform fields.
    ebpf_id_t id;                ///< Program ID.
    enum bpf_prog_type type;     ///< Program type, if a cross-platform type.
    uint32_t nr_map_ids;         ///< Number of maps associated with this program.
    char name[BPF_OBJ_NAME_LEN]; ///< Null-terminated program name.

    // Windows-specific fields.
    ebpf_program_type_t type_uuid;       ///< Program type UUID.
    ebpf_attach_type_t attach_type_uuid; ///< Attach type UUID.
    uint32_t pinned_path_count;          ///< Number of pinned paths.
    uint32_t link_count;                 ///< Number of attached links.
};
