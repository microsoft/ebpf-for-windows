// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#include "bpf.h"
#include "libbpf.h"

#include <windows.h>
#include <WinError.h>
#include <linux/bpf.h>
#include <stdexcept>

template <typename T> class ExtensibleStruct
{
  private:
    void* _orig;
    size_t _orig_size;
    T _tmp;
    T* _p;

    static void
    check_tail(const void* buf, size_t start, size_t end)
    {
        const unsigned char* p = (const unsigned char*)buf + start;
        const unsigned char* e = (const unsigned char*)buf + end;

        for (; p < e; p++) {
            if ((*p) != 0) {
                throw std::runtime_error("Non-zero tail");
            }
        }
    }

  public:
    ExtensibleStruct(void* ptr, size_t ptr_size) : _orig(ptr)
    {
        if (ptr_size >= sizeof(T)) {
            // Forward compatibility: allow a larger input as long as the
            // unknown fields are all zero.
            check_tail(ptr, sizeof(T), ptr_size);
            _orig_size = 0;
            _p = (T*)ptr;
        } else {
            // Backwards compatibility: allow a smaller input by implicitly zeroing all
            // missing fields.
            memcpy(&_tmp, ptr, ptr_size);
            _orig_size = ptr_size;
            _p = &_tmp;
        }
    }

    ~ExtensibleStruct() { memcpy(_orig, &_tmp, _orig_size); }

    T*
    operator->()
    {
        return _p;
    }

    T*
    operator&()
    {
        return _p;
    }

    T
    operator*()
    {
        return *_p;
    }
};

int
bpf(int cmd, union bpf_attr* p, unsigned int size)
{
    // bpf() is ABI compatible with the Linux bpf() syscall.
    //
    // * Do not return errors via errno.
    // * Do not assume that bpf_attr has a particular size.

    try {
        switch (cmd) {
        case BPF_LINK_DETACH: {
            ExtensibleStruct<sys_bpf_link_detach_attr_t> attr((void*)p, (size_t)size);
            return bpf_link_detach(attr->link_fd);
        }
        case BPF_LINK_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> link_id((void*)p, (size_t)size);
            return bpf_link_get_fd_by_id(*link_id);
        }
        case BPF_LINK_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> attr((void*)p, (size_t)size);
            return bpf_link_get_next_id(attr->start_id, &attr->next_id);
        }
        case BPF_MAP_CREATE: {
            ExtensibleStruct<sys_bpf_map_create_attr_t> attr((void*)p, (size_t)size);
            struct bpf_map_create_opts opts = {.map_flags = attr->map_flags};
            return bpf_map_create(attr->map_type, nullptr, attr->key_size, attr->value_size, attr->max_entries, &opts);
        }
        case BPF_MAP_DELETE_ELEM: {
            ExtensibleStruct<sys_bpf_map_delete_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_delete_elem(attr->map_fd, (const void*)attr->key);
        }
        case BPF_MAP_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> map_id((void*)p, (size_t)size);
            return bpf_map_get_fd_by_id(*map_id);
        }
        case BPF_MAP_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_get_next_id(attr->start_id, &attr->next_id);
        }
        case BPF_MAP_GET_NEXT_KEY: {
            ExtensibleStruct<sys_bpf_map_next_key_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_get_next_key(attr->map_fd, (const void*)attr->key, (void*)attr->next_key);
        }
        case BPF_MAP_LOOKUP_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> attr((void*)p, (size_t)size);

            if (attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_map_lookup_elem(attr->map_fd, (const void*)attr->key, (void*)attr->value);
        }
        case BPF_MAP_LOOKUP_AND_DELETE_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> attr((void*)p, (size_t)size);

            if (attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_map_lookup_and_delete_elem(attr->map_fd, (const void*)attr->key, (void*)attr->value);
        }
        case BPF_MAP_UPDATE_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_update_elem(attr->map_fd, (const void*)attr->key, (const void*)attr->value, attr->flags);
        }
        case BPF_OBJ_GET: {
            ExtensibleStruct<sys_bpf_obj_pin_attr_t> attr((void*)p, (size_t)size);
            if (attr->bpf_fd != 0 || attr->flags != 0) {
                return -EINVAL;
            }
            return bpf_obj_get((const char*)attr->pathname);
        }
        case BPF_PROG_ATTACH: {
            ExtensibleStruct<sys_bpf_prog_attach_attr_t> attr((void*)p, (size_t)size);
            return bpf_prog_attach(attr->attach_bpf_fd, attr->target_fd, attr->attach_type, attr->attach_flags);
        }
        case BPF_PROG_DETACH: {
            ExtensibleStruct<sys_bpf_prog_attach_attr_t> attr((void*)p, (size_t)size);
            return bpf_prog_detach(attr->target_fd, attr->attach_type);
        }
        case BPF_OBJ_GET_INFO_BY_FD: {
            ExtensibleStruct<sys_bpf_obj_info_attr_t> attr((void*)p, (size_t)size);
            return bpf_obj_get_info_by_fd(attr->bpf_fd, (void*)attr->info, &attr->info_len);
        }
        case BPF_OBJ_PIN: {
            ExtensibleStruct<sys_bpf_obj_pin_attr_t> attr((void*)p, (size_t)size);

            if (attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_obj_pin(attr->bpf_fd, (const char*)attr->pathname);
        }
        case BPF_PROG_BIND_MAP: {
            ExtensibleStruct<sys_bpf_prog_bind_map_attr_t> attr((void*)p, (size_t)size);
            struct bpf_prog_bind_opts opts = {sizeof(struct bpf_prog_bind_opts), attr->flags};
            return bpf_prog_bind_map(attr->prog_fd, attr->map_fd, &opts);
        }
        case BPF_PROG_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> prog_id((void*)p, (size_t)size);
            return bpf_prog_get_fd_by_id(*prog_id);
        }
        case BPF_PROG_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> attr((void*)p, (size_t)size);
            return bpf_prog_get_next_id(attr->start_id, &attr->next_id);
        }
        case BPF_PROG_LOAD: {
            ExtensibleStruct<sys_bpf_prog_load_attr_t> attr((void*)p, (size_t)size);

            if (attr->prog_flags != 0) {
                return -EINVAL;
            }

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
        case BPF_PROG_TEST_RUN: {
            ExtensibleStruct<sys_bpf_prog_run_attr_t> attr((void*)p, (size_t)size);

            if (attr->_pad0 != 0) {
                return -EINVAL;
            }

            bpf_test_run_opts test_run_opts = {
                .sz = sizeof(bpf_test_run_opts),
                .data_in = (void*)attr->data_in,
                .data_out = (void*)attr->data_out,
                .data_size_in = attr->data_size_in,
                .data_size_out = attr->data_size_out,
                .ctx_in = (void*)attr->ctx_in,
                .ctx_out = (void*)attr->ctx_out,
                .ctx_size_in = attr->ctx_size_in,
                .ctx_size_out = attr->ctx_size_out,
                .repeat = (int)(attr->repeat),
                .flags = attr->flags,
                .cpu = attr->cpu,
                .batch_size = attr->batch_size,
            };

            int retval = bpf_prog_test_run_opts(attr->prog_fd, &test_run_opts);
            if (retval == 0) {
                attr->data_size_out = test_run_opts.data_size_out;
                attr->ctx_size_out = test_run_opts.ctx_size_out;
                attr->retval = test_run_opts.retval;
                attr->duration = test_run_opts.duration;
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
