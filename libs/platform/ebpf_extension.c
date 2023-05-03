// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

// EBPF_RETURN_NTSTATUS(STATUS_SUCCESS) and similar macro invocations trigger C4127.
#pragma warning(disable : 4127) // conditional expression is constant

ebpf_result_t
ebpf_allocate_and_initialize_npi_provider_characteristics(
    _In_ const GUID* interface_id,
    _In_ const GUID* provider_module_id,
    _In_opt_ const void* npi_specific_characteristics,
    _In_ NPI_PROVIDER_ATTACH_CLIENT_FN attach_client_callback,
    _In_ NPI_PROVIDER_DETACH_CLIENT_FN detach_client_callback,
    _In_opt_ PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN provider_cleanup_binding_context_callback,
    _Outptr_ const NPI_PROVIDER_CHARACTERISTICS** provider_characteristics)
{
    ebpf_result_t return_value;
    NPI_PROVIDER_CHARACTERISTICS* local_provider_characteristics = NULL;
    NPI_REGISTRATION_INSTANCE* provider_registration_instance;
    NPI_MODULEID* module_id;

    // Allocate a buffer large enough to hold the provider characteristics and the module id.
    local_provider_characteristics =
        (NPI_PROVIDER_CHARACTERISTICS*)ebpf_allocate(sizeof(NPI_PROVIDER_CHARACTERISTICS) + sizeof(NPI_MODULEID));

    if (!local_provider_characteristics) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // Obtain pointers to the module id and provider characteristics.
    provider_registration_instance = &(local_provider_characteristics->ProviderRegistrationInstance);
    module_id = (NPI_MODULEID*)(((uint8_t*)local_provider_characteristics) + sizeof(NPI_PROVIDER_CHARACTERISTICS));

    // Initialize the provider characteristics.
    local_provider_characteristics->Version = 0;
    local_provider_characteristics->Length = sizeof(*local_provider_characteristics);
    local_provider_characteristics->ProviderAttachClient = attach_client_callback;
    local_provider_characteristics->ProviderDetachClient = detach_client_callback;
    local_provider_characteristics->ProviderCleanupBindingContext = provider_cleanup_binding_context_callback;

    // Initialize the provider registration instance.
    provider_registration_instance->Version = 0;
    provider_registration_instance->Size = sizeof(*provider_registration_instance);
    provider_registration_instance->NpiId = interface_id;
    provider_registration_instance->ModuleId = module_id;
    provider_registration_instance->NpiSpecificCharacteristics = npi_specific_characteristics;

    // Initialize the module id.
    module_id->Length = sizeof(*module_id);
    module_id->Type = MIT_GUID;
    module_id->Guid = *provider_module_id;

    *provider_characteristics = local_provider_characteristics;
    local_provider_characteristics = NULL;
    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_provider_characteristics);
    return return_value;
}

ebpf_result_t
ebpf_allocate_and_initialize_npi_client_characteristics(
    _In_ const GUID* interface_id,
    _In_ const GUID* client_module_id,
    _In_opt_ const void* npi_specific_characteristics,
    _In_ NPI_CLIENT_ATTACH_PROVIDER_FN attach_provider_callback,
    _In_ NPI_CLIENT_DETACH_PROVIDER_FN detach_provider_callback,
    _In_opt_ PNPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN client_cleanup_binding_context_callback,
    _Outptr_ const NPI_CLIENT_CHARACTERISTICS** client_characteristics)
{
    ebpf_result_t return_value;
    NPI_CLIENT_CHARACTERISTICS* local_client_characteristics = NULL;
    NPI_REGISTRATION_INSTANCE* client_registration_instance;
    NPI_MODULEID* module_id;

    // Allocate a buffer large enough to hold the provider characteristics and the module id.
    local_client_characteristics =
        (NPI_CLIENT_CHARACTERISTICS*)ebpf_allocate(sizeof(NPI_PROVIDER_CHARACTERISTICS) + sizeof(NPI_MODULEID));

    if (!local_client_characteristics) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // Obtain pointers to the module id and provider characteristics.
    client_registration_instance = &(local_client_characteristics->ClientRegistrationInstance);
    module_id = (NPI_MODULEID*)(((uint8_t*)local_client_characteristics) + sizeof(NPI_PROVIDER_CHARACTERISTICS));

    // Initialize the provider characteristics.
    local_client_characteristics->Version = 0;
    local_client_characteristics->Length = sizeof(*local_client_characteristics);
    local_client_characteristics->ClientAttachProvider = attach_provider_callback;
    local_client_characteristics->ClientDetachProvider = detach_provider_callback;
    local_client_characteristics->ClientCleanupBindingContext = client_cleanup_binding_context_callback;

    // Initialize the provider registration instance.
    client_registration_instance->Version = 0;
    client_registration_instance->Size = sizeof(*client_registration_instance);
    client_registration_instance->NpiId = interface_id;
    client_registration_instance->ModuleId = module_id;
    client_registration_instance->NpiSpecificCharacteristics = npi_specific_characteristics;

    // Initialize the module id.
    module_id->Length = sizeof(*module_id);
    module_id->Type = MIT_GUID;
    module_id->Guid = *client_module_id;

    *client_characteristics = local_client_characteristics;
    local_client_characteristics = NULL;
    return_value = EBPF_SUCCESS;

Done:
    ebpf_free(local_client_characteristics);
    return return_value;
}
