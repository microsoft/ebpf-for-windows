// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "bpf.h"
#include "libbpf.h"
#include <linux/bpf.h>

#define CHECK_SIZE(last_field_name)                                                         \
    if (size < offsetof(union bpf_attr, last_field_name) + sizeof(attr->last_field_name)) { \
        errno = EINVAL;                                                                     \
        return -1;                                                                          \
    }

int
bpf(int cmd, union bpf_attr* attr, unsigned int size)
{
    switch (cmd) {
    case BPF_LINK_DETACH:
        CHECK_SIZE(link_detach.link_fd);
        return bpf_link_detach(attr->link_detach.link_fd);
    case BPF_LINK_GET_FD_BY_ID:
        CHECK_SIZE(link_id);
        return bpf_link_get_fd_by_id(attr->link_id);
    case BPF_LINK_GET_NEXT_ID:
        CHECK_SIZE(next_id);
        return bpf_link_get_next_id(attr->start_id, &attr->next_id);
    case BPF_MAP_CREATE: {
        CHECK_SIZE(map_flags);
        struct bpf_map_create_opts opts = {.map_flags = attr->map_flags};
        return bpf_map_create(attr->map_type, nullptr, attr->key_size, attr->value_size, attr->max_entries, &opts);
    }
    case BPF_MAP_DELETE_ELEM:
        CHECK_SIZE(key);
        return bpf_map_delete_elem(attr->map_fd, (const void*)attr->key);
    case BPF_MAP_GET_FD_BY_ID:
        CHECK_SIZE(map_id);
        return bpf_map_get_fd_by_id(attr->map_id);
    case BPF_MAP_GET_NEXT_ID:
        CHECK_SIZE(next_id);
        return bpf_map_get_next_id(attr->start_id, &attr->next_id);
    case BPF_MAP_GET_NEXT_KEY:
        CHECK_SIZE(next_key);
        return bpf_map_get_next_key(attr->map_fd, (const void*)attr->key, (void*)attr->next_key);
    case BPF_MAP_LOOKUP_ELEM:
        CHECK_SIZE(value);
        return bpf_map_lookup_elem(attr->map_fd, (const void*)attr->key, (void*)attr->value);
    case BPF_MAP_UPDATE_ELEM:
        CHECK_SIZE(flags);
        return bpf_map_update_elem(attr->map_fd, (const void*)attr->key, (const void*)attr->value, attr->flags);
    case BPF_OBJ_GET:
        CHECK_SIZE(bpf_fd);
        if (attr->bpf_fd != 0) {
            errno = EINVAL;
            return -1;
        }
        return bpf_obj_get((const char*)attr->pathname);
    case BPF_OBJ_GET_INFO_BY_FD:
        CHECK_SIZE(info.info_len);
        return bpf_obj_get_info_by_fd(attr->info.bpf_fd, (void*)attr->info.info, &attr->info.info_len);
    case BPF_OBJ_PIN:
        CHECK_SIZE(bpf_fd);
        return bpf_obj_pin(attr->bpf_fd, (const char*)attr->pathname);
    case BPF_PROG_BIND_MAP: {
        CHECK_SIZE(prog_bind_map.flags);
        struct bpf_prog_bind_opts opts = {sizeof(struct bpf_prog_bind_opts), attr->prog_bind_map.flags};
        return bpf_prog_bind_map(attr->prog_bind_map.prog_fd, attr->prog_bind_map.map_fd, &opts);
    }
    case BPF_PROG_GET_FD_BY_ID:
        CHECK_SIZE(prog_id);
        return bpf_prog_get_fd_by_id(attr->prog_id);
    case BPF_PROG_GET_NEXT_ID:
        CHECK_SIZE(next_id);
        return bpf_prog_get_next_id(attr->start_id, &attr->next_id);
    case BPF_PROG_LOAD: {
        CHECK_SIZE(kern_version);
        struct bpf_prog_load_opts opts = {
            .kern_version = attr->kern_version, .log_size = attr->log_size, .log_buf = (char*)attr->log_buf};
        return bpf_prog_load(
            attr->prog_type,
            nullptr,
            (const char*)attr->license,
            (const struct bpf_insn*)attr->insns,
            attr->insn_cnt,
            &opts);
    }
    default:
        errno = EINVAL;
        return -1;
    }
}