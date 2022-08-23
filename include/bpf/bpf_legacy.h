// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union

/**
 * @name Map-related functions
 * @{
 */

struct bpf_create_map_attr
{
    const char* name;
    enum bpf_map_type map_type;
    __u32 map_flags;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 numa_node;
    __u32 btf_fd;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    __u32 map_ifindex;
    union
    {
        __u32 inner_map_fd;
        __u32 btf_vmlinux_value_type_id;
    };
};

/**
 * @brief Create a new map.
 *
 * @param[in] map_type Type of map to create.
 * @param[in] key_size Size in bytes of keys.
 * @param[in] value_size Size in bytes of values.
 * @param[in] max_entries Maximum number of entries in the map.
 * @param[in] map_flags Flags (currently 0).
 *
 * @returns A new file descriptor that refers to the map.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @deprecated Use bpf_map_create() instead.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception ENOMEM Out of memory.
 */
__declspec(deprecated("Use bpf_map_create() instead.")) int bpf_create_map(
    enum bpf_map_type map_type, int key_size, int value_size, int max_entries, __u32 map_flags);

/**
 * @brief Create a new map-in-map.
 *
 * @param[in] map_type Type of outer map to create.
 * @param[in] name Optionally, the name to use for the map.
 * @param[in] key_size Size in bytes of keys.
 * @param[in] inner_map_fd File descriptor of the inner map template.
 * @param[in] max_entries Maximum number of entries in the map.
 * @param[in] map_flags Flags (currently 0).
 *
 * @returns A new file descriptor that refers to the map.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @deprecated Use bpf_map_create() instead.
 *
 * @exception EBADF The file descriptor was not found.
 * @exception EINVAL An invalid argument was provided.
 * @exception ENOMEM Out of memory.
 */
__declspec(deprecated("Use bpf_map_create() instead.")) int bpf_create_map_in_map(
    enum bpf_map_type map_type, const char* name, int key_size, int inner_map_fd, int max_entries, __u32 map_flags);

/**
 * @brief Create a new map.
 *
 * @param[in] create_attr Structure of attributes using which a map gets created.
 *
 * @returns A new file descriptor that refers to the map.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception ENOMEM Out of memory.
 *
 * @deprecated Use bpf_map_create() instead.
 */
__declspec(deprecated("Use bpf_map_create() instead.")) int bpf_create_map_xattr(
    const struct bpf_create_map_attr* create_attr);

/** @} */

/**
 * @name Program-related functions
 * @{
 */

struct bpf_load_program_attr
{
    enum bpf_prog_type prog_type;
    enum bpf_attach_type expected_attach_type;
    const char* name;
    const struct bpf_insn* insns;
    size_t insns_cnt;
    const char* license;
    union
    {
        __u32 kern_version;
        __u32 attach_prog_fd;
    };
    union
    {
        __u32 prog_ifindex;
        __u32 attach_btf_id;
    };
    __u32 prog_btf_fd;
    __u32 func_info_rec_size;
    const void* func_info;
    __u32 func_info_cnt;
    __u32 line_info_rec_size;
    const void* line_info;
    __u32 line_info_cnt;
    __u32 log_level;
    __u32 prog_flags;
};

/**
 * @brief Load (but do not attach) an eBPF program from eBPF instructions
 * supplied by the caller.
 *
 * @param[in] type Program type to use.
 * @param[in] insns Array of eBPF instructions.
 * @param[in] insns_cnt Number of eBPF instructions in the array.
 * @param[in] license License.
 * @param[in] kern_version Kernel version.
 * @param[out] log_buf Buffer in which to write any log messages.
 * @param[in] log_buf_size Size in bytes of the log buffer.
 *
 * @returns File descriptor that refers to the program, or <0 on error.
 * The caller should call _close() on the fd to close this when done.
 *
 * @deprecated Use bpf_prog_load() instead.
 *
 * @exception EACCES The program failed verification.
 * @exception EINVAL One or more parameters are incorrect.
 * @exception ENOMEM Out of memory.
 *
 * @sa bpf_prog_load
 * @sa bpf_load_program_xattr
 */
__declspec(deprecated("Use bpf_prog_load() instead.")) int bpf_load_program(
    enum bpf_prog_type type,
    const struct bpf_insn* insns,
    size_t insns_cnt,
    const char* license,
    __u32 kern_version,
    char* log_buf,
    size_t log_buf_sz);

/**
 * @brief Load (but do not attach) an eBPF program from eBPF instructions
 * supplied by the caller.
 *
 * @param[in] load_attr Parameters to use to load the eBPF program.
 * @param[out] log_buf Buffer in which to write any log messages.
 * @param[in] log_buf_size Size in bytes of the log buffer.
 *
 * @returns File descriptor that refers to the program, or <0 on error.
 * The caller should call _close() on the fd to close this when done.
 *
 * @exception EACCES The program failed verification.
 * @exception EINVAL One or more parameters are incorrect.
 * @exception ENOMEM Out of memory.
 *
 * @deprecated Use bpf_prog_load() instead.
 *
 * @sa bpf_prog_load
 * @sa bpf_load_program
 */
__declspec(deprecated("Use bpf_prog_load() instead.")) int bpf_load_program_xattr(
    const struct bpf_load_program_attr* load_attr, char* log_buf, size_t log_buf_sz);

/** @} */

#pragma warning(pop)