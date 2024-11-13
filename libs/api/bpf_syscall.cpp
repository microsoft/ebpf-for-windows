// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#include "bpf.h"
#include "libbpf.h"

#include <windows.h>
#include <WinError.h>
#include <linux/bpf.h>
#include <sal.h>
#include <stdexcept>

template <typename T> class ExtensibleStruct
{
  private:
    void* _source;
    size_t _copy_size;
    T _temporary;
    T* _pointer;

    static void
    check_tail(_In_reads_bytes_(end) const void* buffer, size_t start, size_t end)
    {
        const unsigned char* p = (const unsigned char*)buffer + start;
        const unsigned char* e = (const unsigned char*)buffer + end;

        for (; p < e; p++) {
            if ((*p) != 0) {
                throw std::runtime_error("Non-zero tail");
            }
        }
    }

  public:
    ExtensibleStruct(_In_reads_bytes_(size) void* pointer, size_t size) : _source(pointer)
    {
        if (size >= sizeof(T)) {
            // Forward compatibility: allow a larger input as long as the
            // unknown fields are all zero.
            check_tail(pointer, sizeof(T), size);
            _copy_size = 0;
            _pointer = (T*)pointer;
        } else {
            // Backwards compatibility: allow a smaller input by implicitly zeroing all
            // missing fields.
            memcpy(&_temporary, pointer, size);
            _copy_size = size;
            _pointer = &_temporary;
        }
    }

    ~ExtensibleStruct() { memcpy(_source, &_temporary, _copy_size); }

    T*
    operator->()
    {
        return _pointer;
    }

    T*
    operator&()
    {
        return _pointer;
    }

    T
    operator*()
    {
        return *_pointer;
    }
};

int
bpf(int cmd, union bpf_attr* attr, unsigned int size)
{
    // bpf() is ABI compatible with the Linux bpf() syscall.
    //
    // * Do not return errors via errno.
    // * Do not assume that bpf_attr has a particular size.

    try {
        switch (cmd) {
        case BPF_LINK_DETACH: {
            ExtensibleStruct<sys_bpf_link_detach_attr_t> detach_attr((void*)attr, (size_t)size);
            return bpf_link_detach(detach_attr->link_fd);
        }
        case BPF_LINK_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> link_id((void*)attr, (size_t)size);
            return bpf_link_get_fd_by_id(*link_id);
        }
        case BPF_LINK_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> next_id_attr((void*)attr, (size_t)size);
            return bpf_link_get_next_id(next_id_attr->start_id, &next_id_attr->next_id);
        }
        case BPF_MAP_CREATE: {
            ExtensibleStruct<sys_bpf_map_create_attr_t> map_create_attr((void*)attr, (size_t)size);

            struct bpf_map_create_opts opts = {
                .inner_map_fd = map_create_attr->inner_map_fd,
                .map_flags = map_create_attr->map_flags,
            };

            return bpf_map_create(
                map_create_attr->map_type,
                nullptr,
                map_create_attr->key_size,
                map_create_attr->value_size,
                map_create_attr->max_entries,
                &opts);
        }
        case BPF_MAP_DELETE_ELEM: {
            ExtensibleStruct<sys_bpf_map_delete_attr_t> map_delete_attr((void*)attr, (size_t)size);
            return bpf_map_delete_elem(map_delete_attr->map_fd, (const void*)map_delete_attr->key);
        }
        case BPF_MAP_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> map_id((void*)attr, (size_t)size);
            return bpf_map_get_fd_by_id(*map_id);
        }
        case BPF_MAP_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> next_id_attr((void*)attr, (size_t)size);
            return bpf_map_get_next_id(next_id_attr->start_id, &next_id_attr->next_id);
        }
        case BPF_MAP_GET_NEXT_KEY: {
            ExtensibleStruct<sys_bpf_map_next_key_attr_t> next_key_attr((void*)attr, (size_t)size);
            return bpf_map_get_next_key(
                next_key_attr->map_fd, (const void*)next_key_attr->key, (void*)next_key_attr->next_key);
        }
        case BPF_MAP_LOOKUP_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> lookup_elem_attr((void*)attr, (size_t)size);

            if (lookup_elem_attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_map_lookup_elem(
                lookup_elem_attr->map_fd, (const void*)lookup_elem_attr->key, (void*)lookup_elem_attr->value);
        }
        case BPF_MAP_LOOKUP_AND_DELETE_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> lookup_and_delete_attr((void*)attr, (size_t)size);

            if (lookup_and_delete_attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_map_lookup_and_delete_elem(
                lookup_and_delete_attr->map_fd,
                (const void*)lookup_and_delete_attr->key,
                (void*)lookup_and_delete_attr->value);
        }
        case BPF_MAP_UPDATE_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> update_elem_attr((void*)attr, (size_t)size);
            return bpf_map_update_elem(
                update_elem_attr->map_fd,
                (const void*)update_elem_attr->key,
                (const void*)update_elem_attr->value,
                update_elem_attr->flags);
        }
        case BPF_OBJ_GET: {
            ExtensibleStruct<sys_bpf_obj_pin_attr_t> obj_get_attr((void*)attr, (size_t)size);
            if (obj_get_attr->bpf_fd != 0 || obj_get_attr->flags != 0) {
                return -EINVAL;
            }
            return bpf_obj_get((const char*)obj_get_attr->pathname);
        }
        case BPF_PROG_ATTACH: {
            ExtensibleStruct<sys_bpf_prog_attach_attr_t> prog_attach_attr((void*)attr, (size_t)size);
            return bpf_prog_attach(
                prog_attach_attr->attach_bpf_fd,
                prog_attach_attr->target_fd,
                prog_attach_attr->attach_type,
                prog_attach_attr->attach_flags);
        }
        case BPF_PROG_DETACH: {
            ExtensibleStruct<sys_bpf_prog_attach_attr_t> prog_detach_attr((void*)attr, (size_t)size);
            return bpf_prog_detach(prog_detach_attr->target_fd, prog_detach_attr->attach_type);
        }
        case BPF_OBJ_GET_INFO_BY_FD: {
            ExtensibleStruct<sys_bpf_obj_info_attr_t> info_by_fd_attr((void*)attr, (size_t)size);
            return bpf_obj_get_info_by_fd(
                info_by_fd_attr->bpf_fd, (void*)info_by_fd_attr->info, &info_by_fd_attr->info_len);
        }
        case BPF_OBJ_PIN: {
            ExtensibleStruct<sys_bpf_obj_pin_attr_t> obj_pin_attr((void*)attr, (size_t)size);

            if (obj_pin_attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_obj_pin(obj_pin_attr->bpf_fd, (const char*)obj_pin_attr->pathname);
        }
        case BPF_PROG_BIND_MAP: {
            ExtensibleStruct<sys_bpf_prog_bind_map_attr_t> bind_map_attr((void*)attr, (size_t)size);
            struct bpf_prog_bind_opts opts = {sizeof(struct bpf_prog_bind_opts), bind_map_attr->flags};
            return bpf_prog_bind_map(bind_map_attr->prog_fd, bind_map_attr->map_fd, &opts);
        }
        case BPF_PROG_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> prog_id((void*)attr, (size_t)size);
            return bpf_prog_get_fd_by_id(*prog_id);
        }
        case BPF_PROG_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> next_id_attr((void*)attr, (size_t)size);
            return bpf_prog_get_next_id(next_id_attr->start_id, &next_id_attr->next_id);
        }
        case BPF_PROG_LOAD: {
            ExtensibleStruct<sys_bpf_prog_load_attr_t> prog_load_attr((void*)attr, (size_t)size);

            if (prog_load_attr->prog_flags != 0) {
                return -EINVAL;
            }

            struct bpf_prog_load_opts opts = {
                .kern_version = prog_load_attr->kern_version,
                .log_size = prog_load_attr->log_size,
                .log_buf = (char*)prog_load_attr->log_buf,
            };

            return bpf_prog_load(
                prog_load_attr->prog_type,
                nullptr,
                (const char*)prog_load_attr->license,
                (const struct bpf_insn*)prog_load_attr->insns,
                prog_load_attr->insn_cnt,
                &opts);
        }
        case BPF_PROG_TEST_RUN: {
            ExtensibleStruct<sys_bpf_prog_run_attr_t> prog_run((void*)attr, (size_t)size);

            if (prog_run->_pad0 != 0) {
                return -EINVAL;
            }

            bpf_test_run_opts test_run_opts = {
                .sz = sizeof(bpf_test_run_opts),
                .data_in = (void*)prog_run->data_in,
                .data_out = (void*)prog_run->data_out,
                .data_size_in = prog_run->data_size_in,
                .data_size_out = prog_run->data_size_out,
                .ctx_in = (void*)prog_run->ctx_in,
                .ctx_out = (void*)prog_run->ctx_out,
                .ctx_size_in = prog_run->ctx_size_in,
                .ctx_size_out = prog_run->ctx_size_out,
                .repeat = (int)(prog_run->repeat),
                .flags = prog_run->flags,
                .cpu = prog_run->cpu,
                .batch_size = prog_run->batch_size,
            };

            int retval = bpf_prog_test_run_opts(prog_run->prog_fd, &test_run_opts);
            if (retval == 0) {
                prog_run->data_size_out = test_run_opts.data_size_out;
                prog_run->ctx_size_out = test_run_opts.ctx_size_out;
                prog_run->retval = test_run_opts.retval;
                prog_run->duration = test_run_opts.duration;
            }

            return retval;
        }
        default:
            SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
            return -EINVAL;
        }
    } catch (...) {
        return -EINVAL;
    }
}
