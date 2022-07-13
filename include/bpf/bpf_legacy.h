// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#if __LIBBPF_CURRENT_VERSION_GEQ(0, 7)
#define __LIBBPF_MARK_DEPRECATED_0_7(X) X
#else
#define __LIBBPF_MARK_DEPRECATED_0_7(X)
#endif

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

LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_map_create() instead")
LIBBPF_API int
bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, __u32 map_flags);
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_map_create() instead")
LIBBPF_API int
bpf_create_map_in_map(
    enum bpf_map_type map_type, const char* name, int key_size, int inner_map_fd, int max_entries, __u32 map_flags);
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_map_create() instead")
LIBBPF_API int
bpf_create_map_xattr(const struct bpf_create_map_attr* create_attr);

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
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_prog_load() instead")
LIBBPF_API int
bpf_load_program_xattr(const struct bpf_load_program_attr* load_attr, char* log_buf, size_t log_buf_sz);
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_prog_load() instead")
LIBBPF_API int
bpf_load_program(
    enum bpf_prog_type type,
    const struct bpf_insn* insns,
    size_t insns_cnt,
    const char* license,
    __u32 kern_version,
    char* log_buf,
    size_t log_buf_sz);

struct bpf_object_load_attr
{
    struct bpf_object* obj;
    int log_level;
    const char* target_btf_path;
};
