// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "net_ebpf_ext_program_info.h"
#include "sample_ext_program_info.h"
#include "usersim/ex.h"
#include "usersim/ke.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <vector>

// Prototypes added as the libbpf headers cause conflicts with the execution context headers.
extern "C" int
bpf_link__destroy(bpf_link* link);

extern "C" int
bpf_link__fd(const struct bpf_link* link);

extern "C" int
bpf_link_detach(int link_fd);

extern "C" int
bpf_program__fd(const struct bpf_program* prog);

typedef struct _close_bpf_link
{
    void
    operator()(_In_opt_ _Post_invalid_ bpf_link* link)
    {
        bpf_link__destroy(link);
    }
} close_bpf_link_t;

typedef std::unique_ptr<bpf_link, close_bpf_link_t> bpf_link_ptr;

/**
 * @brief Thin wrapper over eBPF attach/detach APIs.
 *        Manages a collection of bpf_link objects. Links created via the attach() methods
 *        are owned by this class and cleaned up in the destructor. Links created via
 *        attach_link() are returned to the caller and not tracked internally.
 */
typedef class _hook_helper
{
  public:
    _hook_helper(ebpf_attach_type_t attach_type) : _attach_type(attach_type) {}

    ~_hook_helper() { detach_all(); }

    // Existing methods (backward compat) — caller manages link lifetime.

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Out_ bpf_link_ptr* unique_link)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result;

        result = ebpf_program_attach_by_fd(program_fd, &_attach_type, attach_parameters, attach_parameters_size, &link);
        if (result == EBPF_SUCCESS) {
            unique_link->reset(link);
        }

        return result;
    }

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Outptr_ bpf_link** link)
    {
        return ebpf_program_attach_by_fd(program_fd, &_attach_type, attach_parameters, attach_parameters_size, link);
    }

    void
    detach_link(_Inout_ bpf_link* link)
    {
        bpf_link_detach(bpf_link__fd(link));
    }

    void
    close_link(_Frees_ptr_ bpf_link* link)
    {
        bpf_link__destroy(link);
    }

    void
    detach_and_close_link(_Inout_ bpf_link_ptr* unique_link)
    {
        unique_link->reset();
    }

    // New methods — hook_helper owns the link lifetime.

    _Ret_maybenull_ bpf_link*
    attach(fd_t program_fd, _In_reads_bytes_opt_(params_size) void* params, size_t params_size)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result = ebpf_program_attach_by_fd(program_fd, &_attach_type, params, params_size, &link);
        if (result == EBPF_SUCCESS && link != nullptr) {
            _entries.push_back({link, program_fd, _copy_params(params, params_size)});
        }
        return link;
    }

    _Ret_maybenull_ bpf_link*
    attach(_In_ const bpf_program* program, _In_reads_bytes_opt_(params_size) void* params, size_t params_size)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result = ebpf_program_attach(program, &_attach_type, params, params_size, &link);
        if (result == EBPF_SUCCESS && link != nullptr) {
            fd_t fd = bpf_program__fd(program);
            _entries.push_back({link, fd, _copy_params(params, params_size)});
        }
        return link;
    }

    void
    detach(_In_ bpf_link* link)
    {
        auto it =
            std::find_if(_entries.begin(), _entries.end(), [link](const link_entry_t& e) { return e.link == link; });
        if (it != _entries.end()) {
            _entries.erase(it);
        }
        bpf_link__destroy(link);
    }

    void
    detach_first()
    {
        if (_entries.empty()) {
            return;
        }
        bpf_link* link = _entries.front().link;
        _entries.erase(_entries.begin());
        bpf_link__destroy(link);
    }

    _Must_inspect_result_ ebpf_result_t
    detach(fd_t program_fd, _In_reads_bytes_(params_size) void* params, size_t params_size)
    {
        auto it = std::find_if(_entries.begin(), _entries.end(), [&](const link_entry_t& e) {
            return e.program_fd == program_fd && e.params.size() == params_size &&
                   (params_size == 0 || memcmp(e.params.data(), params, params_size) == 0);
        });
        if (it == _entries.end()) {
            return EBPF_INVALID_ARGUMENT;
        }
        bpf_link* link = it->link;
        _entries.erase(it);
        bpf_link__destroy(link);
        return EBPF_SUCCESS;
    }

    void
    detach_all()
    {
        for (auto& entry : _entries) {
            bpf_link__destroy(entry.link);
        }
        _entries.clear();
    }

    ebpf_attach_type_t
    get_attach_type() const
    {
        return _attach_type;
    }

  private:
    struct link_entry_t
    {
        bpf_link* link;
        fd_t program_fd;
        std::vector<uint8_t> params;
    };

    static std::vector<uint8_t>
    _copy_params(_In_reads_bytes_opt_(size) const void* params, size_t size)
    {
        if (params == nullptr || size == 0) {
            return {};
        }
        auto* bytes = static_cast<const uint8_t*>(params);
        return std::vector<uint8_t>(bytes, bytes + size);
    }

    ebpf_attach_type_t _attach_type;
    std::vector<link_entry_t> _entries;
} hook_helper_t;

/**
 * @brief Mock NMR hook provider for user-mode testing.
 *        Supports multiple clients, each identified by unique attach parameters (client_data).
 *        Clients are stored in a vector of shared_ptr for safe concurrent fire/detach.
 *
 *        Typical usage:
 *          single_instance_hook_t hook(prog_type, attach_type);
 *          hook.initialize();
 *          hook.attach(fd);                          // single client
 *          hook.attach(fd, &params, sizeof(params)); // additional clients
 *          hook.fire(ctx, &result);                  // invoke client[0]
 *          hook.fire(attach_data, ctx, &result);     // invoke by matching client_data
 */
typedef class _single_instance_hook
{
  public:
    _single_instance_hook(
        ebpf_program_type_t program_type,
        ebpf_attach_type_t attach_type,
        bpf_link_type link_type = BPF_LINK_TYPE_UNSPEC);

    ~_single_instance_hook();

    // NMR provider registration.
    ebpf_result_t
    initialize();

    // Delegated to hook_helper (backward compat — caller manages link lifetime).
    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Out_ bpf_link_ptr* unique_link)
    {
        return _helper.attach_link(program_fd, attach_parameters, attach_parameters_size, unique_link);
    }

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Outptr_ bpf_link** link)
    {
        return _helper.attach_link(program_fd, attach_parameters, attach_parameters_size, link);
    }

    void
    detach_link(_Inout_ bpf_link* link)
    {
        _helper.detach_link(link);
    }

    void
    close_link(_Frees_ptr_ bpf_link* link)
    {
        _helper.close_link(link);
    }

    void
    detach_and_close_link(_Inout_ bpf_link_ptr* unique_link)
    {
        _helper.detach_and_close_link(unique_link);
    }

    // Attach — hook_helper owns the link, NMR callback tracks the client.
    _Must_inspect_result_ ebpf_result_t
    attach(_In_ const bpf_program* program);

    _Must_inspect_result_ ebpf_result_t
    attach(_In_ const bpf_program* program, _In_reads_bytes_(params_size) void* params, size_t params_size);

    // Detach — single client (client[0]).
    void
    detach();

    // Detach — by attach parameters (finds matching client_data, first match wins).
    _Must_inspect_result_ ebpf_result_t
    detach(fd_t program_fd, _In_reads_bytes_(params_size) void* params, size_t params_size);

    // Fire client[0].
    _Must_inspect_result_ ebpf_result_t
    fire(_Inout_ void* context, _Out_ uint32_t* result);

    // Fire client matching attach parameters in client_data.
    _Must_inspect_result_ ebpf_result_t
    fire(
        _In_reads_bytes_(params_size) const void* params,
        size_t params_size,
        _Inout_ void* context,
        _Out_ uint32_t* result);

    // Batch operations — param-less targets client[0].
    _Must_inspect_result_ ebpf_result_t
    batch_begin(size_t state_size, _Out_writes_(state_size) void* state);

    _Must_inspect_result_ ebpf_result_t
    batch_invoke(_Inout_ void* program_context, _Out_ uint32_t* result, _In_ const void* state);

    _Must_inspect_result_ ebpf_result_t
    batch_end(_In_ void* state);

    // Client data — param-less returns client[0].
    _Ret_maybenull_ const ebpf_extension_data_t*
    get_client_data() const;

    _Ret_maybenull_ const ebpf_extension_data_t*
    get_client_data(_In_reads_bytes_(params_size) const void* params, size_t params_size) const;

    // Allow implicit conversion to hook_helper_t& for backward compatibility
    // (e.g., _program_load_attach_helper::initialize takes hook_helper_t&).
    operator hook_helper_t&() { return _helper; }

  private:
    struct client_entry_t
    {
        _single_instance_hook* owner = nullptr;
        PNPI_REGISTRATION_INSTANCE registration_instance = nullptr;
        const void* binding_context = nullptr;
        const ebpf_extension_data_t* data = nullptr;
        const ebpf_extension_dispatch_table_t* dispatch_table = nullptr;
        HANDLE nmr_binding_handle = nullptr;
        std::atomic<int32_t> invoke_count{0};
        std::atomic<bool> detached{false};
    };

    // Find client whose client_data matches the given params (raw byte comparison).
    std::shared_ptr<client_entry_t>
    find_client_by_params(_In_reads_bytes_(params_size) const void* params, size_t params_size) const;

    // Find client[0] — returns shared_ptr copy for refcount safety.
    std::shared_ptr<client_entry_t>
    first_client() const;

    // Invoke a client's dispatch function with rundown protection.
    _Must_inspect_result_ ebpf_result_t
    invoke_client(_In_ std::shared_ptr<client_entry_t> client, _Inout_ void* context, _Out_ uint32_t* result);

    // NMR callbacks.
    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Outptr_result_maybenull_ const void** provider_dispatch);

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context);

    _hook_helper _helper;
    std::vector<std::shared_ptr<client_entry_t>> _clients;
    mutable std::mutex _mutex;

    // NMR provider data.
    ebpf_attach_provider_data_t _attach_provider_data = {};
    NPI_MODULEID _module_id = {sizeof(NPI_MODULEID), MIT_GUID};
    NPI_PROVIDER_CHARACTERISTICS _provider_characteristics = {};
    HANDLE _nmr_provider_handle = nullptr;
} single_instance_hook_t;

// Alias for multi-client usage (same class, just a name).
typedef _single_instance_hook multi_instance_hook_t;