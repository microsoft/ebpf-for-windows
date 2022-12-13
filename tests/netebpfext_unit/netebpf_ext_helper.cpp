// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "netebpf_ext_helper.h"

ebpf_registry_key_t ebpf_root_registry_key = HKEY_CURRENT_USER;
DEVICE_OBJECT* _net_ebpf_ext_driver_device_object;

_netebpf_ext_helper::_netebpf_ext_helper()
{
    NTSTATUS status;
    status = net_ebpf_ext_trace_initiate();
    REQUIRE(NT_SUCCESS(status));
    trace_initiated = true;

    status = net_ebpf_ext_initialize_ndis_handles(driver_object);
    REQUIRE(NT_SUCCESS(status));

    ndis_handle_initialized = true;

    status = net_ebpf_ext_register_providers();
    REQUIRE(NT_SUCCESS(status));

    provider_registered = true;

    status = net_ebpf_extension_initialize_wfp_components(device_object);
    REQUIRE(NT_SUCCESS(status));

    wfp_initialized = true;

    REQUIRE(NmrRegisterClient(&client, this, &nmr_client_handle) == STATUS_SUCCESS);
}

_netebpf_ext_helper::~_netebpf_ext_helper()
{
    REQUIRE(NmrDeregisterClient(nmr_client_handle) == STATUS_SUCCESS);

    if (wfp_initialized) {
        net_ebpf_extension_uninitialize_wfp_components();
    }

    if (provider_registered) {
        net_ebpf_ext_unregister_providers();
    }

    if (ndis_handle_initialized) {
        net_ebpf_ext_uninitialize_ndis_handles();
    }

    if (trace_initiated) {
        net_ebpf_ext_trace_terminate();
    }
}

std::vector<GUID>
_netebpf_ext_helper::program_info_provider_guids()
{
    std::vector<GUID> guids;
    for (const auto& [id, provider] : program_info_providers) {
        guids.push_back(id);
    }
    return guids;
}

ebpf_extension_data_t
_netebpf_ext_helper::get_program_info_provider_data(const GUID& program_info_provider)
{
    auto iter = program_info_providers.find(program_info_provider);

    if (iter == program_info_providers.end()) {
        throw std::runtime_error("Invalid program_info_provider guid");
    }
    return *iter->second->provider_data;
}

NTSTATUS
_netebpf_ext_helper::_program_info_client_attach_provider(
    _In_ const HANDLE nmr_binding_handle,
    _In_ const PVOID client_context,
    _In_ const PNPI_REGISTRATION_INSTANCE provider_registration_instance)
{
    auto& helper = *reinterpret_cast<_netebpf_ext_helper*>(client_context);
    auto client_binding_context = std::make_unique<program_info_provider_t>();
    client_binding_context->module_id = *provider_registration_instance->ModuleId;
    client_binding_context->parent = &helper;
    client_binding_context->provider_data =
        reinterpret_cast<const ebpf_extension_data_t*>(provider_registration_instance->NpiSpecificCharacteristics);

    NTSTATUS status = NmrClientAttachProvider(
        nmr_binding_handle,
        client_binding_context.get(),
        &client_binding_context,
        &client_binding_context->context,
        &client_binding_context->dispatch);

    if (NT_SUCCESS(status)) {
        helper.program_info_providers[provider_registration_instance->ModuleId->Guid].reset(
            client_binding_context.release());
    }
    return status;
}

NTSTATUS
_netebpf_ext_helper::_program_info_client_detach_provider(_In_ const PVOID client_binding_context)
{
    auto& program_info_provider = *reinterpret_cast<program_info_provider_t*>(client_binding_context);
    program_info_provider.parent->program_info_providers.erase(program_info_provider.module_id.Guid);
    return STATUS_SUCCESS;
}

void
_netebpf_ext_helper::_program_info_client_cleanup_binding_context(_In_ const PVOID client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);
}
