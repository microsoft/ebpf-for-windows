// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "hook_helper.h"

_single_instance_hook::_single_instance_hook(
    ebpf_program_type_t program_type, ebpf_attach_type_t attach_type, bpf_link_type link_type)
    : _helper(attach_type)
{
    _attach_provider_data.header = EBPF_ATTACH_PROVIDER_DATA_HEADER;
    _attach_provider_data.supported_program_type = program_type;
    _attach_provider_data.bpf_attach_type = ebpf_get_bpf_attach_type(&attach_type);
    _attach_provider_data.link_type = link_type;
    _module_id.Guid = attach_type;

    _provider_characteristics.Length = sizeof(_provider_characteristics);
    _provider_characteristics.ProviderAttachClient = (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback;
    _provider_characteristics.ProviderDetachClient = (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback;
    _provider_characteristics.ProviderCleanupBindingContext = NULL;
    _provider_characteristics.ProviderRegistrationInstance.Size = sizeof(NPI_REGISTRATION_INSTANCE);
    _provider_characteristics.ProviderRegistrationInstance.NpiId = &EBPF_HOOK_EXTENSION_IID;
    _provider_characteristics.ProviderRegistrationInstance.ModuleId = &_module_id;
    _provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics = &_attach_provider_data;
}

_single_instance_hook::~_single_instance_hook()
{
    if (_nmr_provider_handle != NULL) {
        NTSTATUS status = NmrDeregisterProvider(_nmr_provider_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForProviderDeregisterComplete(_nmr_provider_handle);
        } else {
            ebpf_assert(status == STATUS_SUCCESS);
        }
    }
    // _helper destructor detaches all owned links.
}

ebpf_result_t
_single_instance_hook::initialize()
{
    NTSTATUS status = NmrRegisterProvider(&_provider_characteristics, this, &_nmr_provider_handle);
    return (status == STATUS_SUCCESS) ? EBPF_SUCCESS : EBPF_FAILED;
}

// Attach — param-less (single client).

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::attach(_In_ const bpf_program* program)
{
    fd_t fd = bpf_program__fd(program);
    bpf_link* link = _helper.attach(fd, nullptr, 0);
    return (link != nullptr) ? EBPF_SUCCESS : EBPF_EXTENSION_FAILED_TO_LOAD;
}

// Attach — with params.

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::attach(
    _In_ const bpf_program* program, _In_reads_bytes_(params_size) void* params, size_t params_size)
{
    fd_t fd = bpf_program__fd(program);
    bpf_link* link = _helper.attach(fd, params, params_size);
    return (link != nullptr) ? EBPF_SUCCESS : EBPF_EXTENSION_FAILED_TO_LOAD;
}

// Detach — single client (client[0]).

void
_single_instance_hook::detach()
{
    // Detach the first link — NMR detach callback removes the client from _clients.
    _helper.detach_first();
}

// Detach — by attach parameters.

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::detach(fd_t program_fd, _In_reads_bytes_(params_size) void* params, size_t params_size)
{
    return _helper.detach(program_fd, params, params_size);
}

// Invoke a client's dispatch function with rundown protection.

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::invoke_client(
    _In_ std::shared_ptr<client_entry_t> client, _Inout_ void* context, _Out_ uint32_t* result)
{
    client->invoke_count++;
    if (client->detached) {
        client->invoke_count--;
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    auto invoke_program = reinterpret_cast<ebpf_result_t (*)(_In_ const void*, _Inout_ void*, _Out_ uint32_t*)>(
        client->dispatch_table->function[0]);
    ebpf_result_t status = invoke_program(client->binding_context, context, result);
    client->invoke_count--;
    return status;
}

// Fire client[0].

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::fire(_Inout_ void* context, _Out_ uint32_t* result)
{
    std::shared_ptr<client_entry_t> client = first_client();
    if (!client) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    return invoke_client(client, context, result);
}

// Fire by attach params.

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::fire(
    _In_reads_bytes_(params_size) const void* params, size_t params_size, _Inout_ void* context, _Out_ uint32_t* result)
{
    std::shared_ptr<client_entry_t> client = find_client_by_params(params, params_size);
    if (!client) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    return invoke_client(client, context, result);
}

// Batch — param-less targets client[0].

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::batch_begin(size_t state_size, _Out_writes_(state_size) void* state)
{
    std::shared_ptr<client_entry_t> client = first_client();
    if (!client) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    auto batch_begin_function =
        reinterpret_cast<ebpf_program_batch_begin_invoke_function_t>(client->dispatch_table->function[1]);
    return batch_begin_function(state_size, state);
}

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::batch_invoke(_Inout_ void* program_context, _Out_ uint32_t* result, _In_ const void* state)
{
    std::shared_ptr<client_entry_t> client = first_client();
    if (!client) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    auto batch_invoke_function =
        reinterpret_cast<ebpf_program_batch_invoke_function_t>(client->dispatch_table->function[2]);
    return batch_invoke_function(client->binding_context, program_context, result, state);
}

_Must_inspect_result_ ebpf_result_t
_single_instance_hook::batch_end(_In_ void* state)
{
    std::shared_ptr<client_entry_t> client = first_client();
    if (!client) {
        return EBPF_EXTENSION_FAILED_TO_LOAD;
    }
    auto batch_end_function =
        reinterpret_cast<ebpf_program_batch_end_invoke_function_t>(client->dispatch_table->function[3]);
    return batch_end_function(state);
}

// Client data.

_Ret_maybenull_ const ebpf_extension_data_t*
_single_instance_hook::get_client_data() const
{
    std::shared_ptr<client_entry_t> client = first_client();
    return client ? client->data : nullptr;
}

_Ret_maybenull_ const ebpf_extension_data_t*
_single_instance_hook::get_client_data(_In_reads_bytes_(params_size) const void* params, size_t params_size) const
{
    std::shared_ptr<client_entry_t> client = find_client_by_params(params, params_size);
    return client ? client->data : nullptr;
}

// Private helpers.

std::shared_ptr<_single_instance_hook::client_entry_t>
_single_instance_hook::first_client() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    if (_clients.empty()) {
        return nullptr;
    }
    return _clients.front();
}

std::shared_ptr<_single_instance_hook::client_entry_t>
_single_instance_hook::find_client_by_params(_In_reads_bytes_(params_size) const void* params, size_t params_size) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    for (const auto& client : _clients) {
        if (client->data != nullptr && client->data->data != nullptr && client->data->data_size >= params_size &&
            memcmp(client->data->data, params, params_size) == 0) {
            return client;
        }
    }
    return nullptr;
}

// NMR callbacks.

NTSTATUS
_single_instance_hook::provider_attach_client_callback(
    HANDLE nmr_binding_handle,
    _Inout_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    auto hook = reinterpret_cast<_single_instance_hook*>(provider_context);
    std::lock_guard<std::mutex> lock(hook->_mutex);

    auto client_data =
        reinterpret_cast<const ebpf_extension_data_t*>(client_registration_instance->NpiSpecificCharacteristics);

    // Reject if a client with identical client_data already exists.
    // Two clients match if both have no data (null/empty) or both have the same byte content.
    auto has_data = [](const ebpf_extension_data_t* d) -> bool {
        return d != nullptr && d->data != nullptr && d->data_size > 0;
    };
    bool incoming_has_data = has_data(client_data);
    for (const auto& existing : hook->_clients) {
        bool existing_has_data = has_data(existing->data);
        if (!incoming_has_data && !existing_has_data) {
            // Both have no attach params — duplicate.
            return STATUS_NOINTERFACE;
        }
        if (incoming_has_data && existing_has_data && existing->data->data_size == client_data->data_size &&
            memcmp(existing->data->data, client_data->data, client_data->data_size) == 0) {
            return STATUS_NOINTERFACE;
        }
    }

    auto entry = std::make_shared<client_entry_t>();
    entry->owner = hook;
    entry->registration_instance = client_registration_instance;
    entry->binding_context = client_binding_context;
    entry->nmr_binding_handle = nmr_binding_handle;
    entry->dispatch_table = (const ebpf_extension_dispatch_table_t*)client_dispatch;
    entry->data = client_data;

    *provider_binding_context = entry.get();
    *provider_dispatch = NULL;

    hook->_clients.push_back(std::move(entry));
    return STATUS_SUCCESS;
}

NTSTATUS
_single_instance_hook::provider_detach_client_callback(_Inout_ void* provider_binding_context)
{
    auto* raw_entry = reinterpret_cast<client_entry_t*>(provider_binding_context);
    auto* hook = raw_entry->owner;

    // Mark as detached so new fire() calls bail out.
    raw_entry->detached = true;

    // Wait for in-flight invocations to drain.
    while (raw_entry->invoke_count > 0) {
        SwitchToThread();
    }

    std::lock_guard<std::mutex> lock(hook->_mutex);
    auto it = std::find_if(
        hook->_clients.begin(), hook->_clients.end(), [raw_entry](const std::shared_ptr<client_entry_t>& sp) {
            return sp.get() == raw_entry;
        });
    if (it != hook->_clients.end()) {
        hook->_clients.erase(it);
    }

    return EBPF_SUCCESS;
}
