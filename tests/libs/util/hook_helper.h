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

// Prototype added as the libbpf headers cause conflicts with the execution context headers.
int
bpf_link__destroy(bpf_link* link);

typedef struct _close_bpf_link
{
    void
    operator()(_In_opt_ _Post_invalid_ bpf_link* link)
    {
        bpf_link__destroy(link);
    }
} close_bpf_link_t;

typedef std::unique_ptr<bpf_link, close_bpf_link_t> bpf_link_ptr;

typedef class _hook_helper
{
  public:
    _hook_helper(ebpf_attach_type_t attach_type) : _attach_type(attach_type) {}

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

  private:
    ebpf_attach_type_t _attach_type;
} hook_helper_t;

typedef class _single_instance_hook : public _hook_helper
{
  public:
    _single_instance_hook(
        ebpf_program_type_t program_type,
        ebpf_attach_type_t attach_type,
        bpf_link_type link_type = BPF_LINK_TYPE_UNSPEC)
        : _hook_helper{attach_type}, client_binding_context(nullptr), client_data(nullptr),
          client_dispatch_table(nullptr), link_object(nullptr), client_registration_instance(nullptr),
          nmr_binding_handle(nullptr), nmr_provider_handle(nullptr)
    {
        attach_provider_data.header = EBPF_ATTACH_PROVIDER_DATA_HEADER;
        attach_provider_data.supported_program_type = program_type;
        attach_provider_data.bpf_attach_type = ebpf_get_bpf_attach_type(&attach_type);
        this->attach_type = attach_type;
        attach_provider_data.link_type = link_type;
        module_id.Guid = attach_type;
    }
    ebpf_result_t
    initialize()
    {
        NTSTATUS status = NmrRegisterProvider(&provider_characteristics, this, &nmr_provider_handle);
        return (status == STATUS_SUCCESS) ? EBPF_SUCCESS : EBPF_FAILED;
    }
    ~_single_instance_hook()
    {
        // Best effort cleanup. Ignore errors.
        if (link_object) {
            (void)ebpf_link_detach(link_object);
            (void)ebpf_link_close(link_object);
        }
        if (nmr_provider_handle != NULL) {
            NTSTATUS status = NmrDeregisterProvider(nmr_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(nmr_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }
        }
    }

    uint32_t
    attach(bpf_program* program)
    {
        return ebpf_program_attach(program, &attach_type, nullptr, 0, &link_object);
    }

    uint32_t
    attach(
        _In_ const bpf_program* program,
        _In_reads_bytes_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size)
    {
        return ebpf_program_attach(program, &attach_type, attach_parameters, attach_parameters_size, &link_object);
    }

    void
    detach()
    {
        if (link_object != nullptr) {
            if (ebpf_link_detach(link_object) == EBPF_SUCCESS) {
                throw std::runtime_error("ebpf_link_detach failed");
            }
            ebpf_link_close(link_object);
            link_object = nullptr;
        }
    }

    _Must_inspect_result_ ebpf_result_t
    detach(
        fd_t program_fd, _In_reads_bytes_(attach_parameter_size) void* attach_parameter, size_t attach_parameter_size)
    {
        ebpf_result_t result = ebpf_program_detach(program_fd, &attach_type, attach_parameter, attach_parameter_size);
        if (result == EBPF_SUCCESS) {
            ebpf_link_close(link_object);
            link_object = nullptr;
        }
        return result;
    }

    void
    detach_link(bpf_link* link)
    {
        if (ebpf_link_detach(link) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_link_detach failed");
        }
    }

    void
    close_link(bpf_link* link)
    {
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*link'.
        ebpf_link_close(link);
#pragma warning(pop)
    }

    void
    detach_and_close_link(_Inout_ bpf_link_ptr* unique_link)
    {
        bpf_link* link = unique_link->release();
        detach_link(link);
        close_link(link);
    }

    _Must_inspect_result_ ebpf_result_t
    fire(_Inout_ void* context, _Out_ uint32_t* result)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }
        ebpf_result_t (*invoke_program)(_In_ const void* link, _Inout_ void* context, _Out_ uint32_t* result) =
            reinterpret_cast<decltype(invoke_program)>(client_dispatch_table->function[0]);

        return invoke_program(client_binding_context, context, result);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_begin(size_t state_size, _Out_writes_(state_size) void* state)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }

        ebpf_program_batch_begin_invoke_function_t batch_begin_function;
        batch_begin_function = reinterpret_cast<decltype(batch_begin_function)>(client_dispatch_table->function[1]);

        return batch_begin_function(state_size, state);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_invoke(_Inout_ void* program_context, _Out_ uint32_t* result, _In_ const void* state)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }

        ebpf_program_batch_invoke_function_t batch_invoke_function;
        batch_invoke_function = reinterpret_cast<decltype(batch_invoke_function)>(client_dispatch_table->function[2]);
        return batch_invoke_function(client_binding_context, program_context, result, state);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_end(_In_ void* state)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }

        ebpf_program_batch_end_invoke_function_t batch_end_function;
        batch_end_function = reinterpret_cast<decltype(batch_end_function)>(client_dispatch_table->function[3]);
        return batch_end_function(state);
    }

    const ebpf_extension_data_t*
    get_client_data() const
    {
        return client_data;
    }

  private:
    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Out_ const void** provider_dispatch)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(provider_context);

        if (hook->client_binding_context != nullptr) {
            // Can't attach a single-instance provider to a second client.
            return STATUS_NOINTERFACE;
        }
        UNREFERENCED_PARAMETER(nmr_binding_handle);
        hook->client_registration_instance = client_registration_instance;
        hook->client_binding_context = client_binding_context;
        hook->nmr_binding_handle = nmr_binding_handle;
        hook->client_dispatch_table = (ebpf_extension_dispatch_table_t*)client_dispatch;
        hook->client_data =
            reinterpret_cast<const ebpf_extension_data_t*>(client_registration_instance->NpiSpecificCharacteristics);
        *provider_binding_context = provider_context;
        *provider_dispatch = NULL;
        return STATUS_SUCCESS;
    };

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(provider_binding_context);
        hook->client_binding_context = nullptr;
        hook->client_data = nullptr;
        hook->client_dispatch_table = nullptr;

        // There should be no in-progress calls to any client functions,
        // we we can return success rather than pending.
        return EBPF_SUCCESS;
    };
    ebpf_attach_type_t attach_type;
    ebpf_attach_provider_data_t attach_provider_data;

    NPI_MODULEID module_id = {
        sizeof(NPI_MODULEID),
        MIT_GUID,
    };
    const NPI_PROVIDER_CHARACTERISTICS provider_characteristics = {
        0,
        sizeof(provider_characteristics),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_HOOK_EXTENSION_IID,
            &module_id,
            0,
            &attach_provider_data,
        },
    };
    HANDLE nmr_provider_handle;

    PNPI_REGISTRATION_INSTANCE client_registration_instance = nullptr;
    const void* client_binding_context = nullptr;
    const ebpf_extension_data_t* client_data = nullptr;
    const ebpf_extension_dispatch_table_t* client_dispatch_table = nullptr;
    HANDLE nmr_binding_handle = nullptr;
    bpf_link* link_object = nullptr;
} single_instance_hook_t;