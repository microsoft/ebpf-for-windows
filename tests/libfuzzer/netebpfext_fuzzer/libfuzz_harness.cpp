// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "libfuzzer.h"
#include "netebpf_ext_helper.h"

// The fuzzer will fuzz the fields in the following structure.
typedef struct
{
    uint16_t prog_type;
    uint16_t data_offset;
    uint16_t data_length;
    uint8_t ctx_offset;
    uint8_t ctx_length;
    uint32_t return_value;
} netebpfext_fuzzer_metadata_t;

typedef struct _test_client_context
{
    void* provider_binding_context;
    ebpf_context_descriptor_t* ctx_descriptor;
    netebpfext_fuzzer_metadata_t metadata;
} test_client_context_t;

// This callback occurs when netebpfext gets a packet and submits it to our dummy
// eBPF program to handle.
_Must_inspect_result_ ebpf_result_t
netebpfext_unit_invoke_program(
    _In_ const void* client_binding_context, _In_ const void* context, _Out_ uint32_t* result)
{
    auto client_context = (test_client_context_t*)client_binding_context;
    netebpfext_fuzzer_metadata_t* metadata = &client_context->metadata;
    size_t context_size = client_context->ctx_descriptor->size;
    uint8_t* ctx_data_end = *(uint8_t**)((char*)context + client_context->ctx_descriptor->end);
    uint8_t* ctx_data = *(uint8_t**)((char*)context + client_context->ctx_descriptor->data);

    // Sanity check ctx_length against prog type specific max (hard coded).
    if (metadata->ctx_offset + metadata->ctx_length > context_size) {
        *result = (uint32_t)-1;
        return EBPF_SUCCESS;
    }

    // Sanity check data_length against ctx values.
    if (metadata->data_offset + metadata->data_length > ctx_data_end - ctx_data) {
        *result = (uint32_t)-1;
        return EBPF_SUCCESS;
    }

    // Copy over some portion of the data if requested.
    for (int i = metadata->data_offset; i < metadata->data_offset + metadata->data_length; i++) {
        ctx_data[i] = 0xde;
    }

    // Copy over some portion of the ctx if requested.
    for (int i = metadata->ctx_offset; i < metadata->ctx_offset + metadata->ctx_length; i++) {
        ((uint8_t*)context)[i] = 0xad;
    }

    *result = client_context->metadata.return_value;
    return EBPF_SUCCESS;
}

// Netebpfext is ready for us to attach to it as if we were ebpfcore.
NTSTATUS
netebpf_fuzzer_attach_extension(
    _In_ HANDLE nmr_binding_handle,
    _Inout_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    const void* provider_dispatch_table;
    ebpf_extension_dispatch_table_t client_dispatch_table = {.size = 1};
    client_dispatch_table.function[0] = (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_program;
#if 0
    auto provider_characteristics =
        (const ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    auto provider_data = (const ebpf_attach_provider_data_t*)provider_characteristics->data;
#else
    UNREFERENCED_PARAMETER(provider_registration_instance);
#endif
    auto test_client_context = (test_client_context_t*)client_context;

    return NmrClientAttachProvider(
        nmr_binding_handle,
        test_client_context, // Client binding context.
        &client_dispatch_table,
        &test_client_context->provider_binding_context,
        &provider_dispatch_table);
}

// Detach from netebpfext.
NTSTATUS
netebpf_fuzzer_detach_extension(_Inout_ void* client_binding_context)
{
    auto test_client_context = (test_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(test_client_context);

    // All callbacks we implement are done.
    return STATUS_SUCCESS;
}

void
netebpfext_fuzzer_cleanup_binding_context(_In_ const void* client_binding_context)
{
    auto test_client_context = (test_client_context_t*)client_binding_context;
    UNREFERENCED_PARAMETER(test_client_context);
}

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < sizeof(netebpfext_fuzzer_metadata_t)) {
        return 0;
    }
    netebpfext_fuzzer_metadata_t* metadata = (netebpfext_fuzzer_metadata_t*)data;

    // Read program type.
    bpf_prog_type_t prog_type = (bpf_prog_type_t)metadata->prog_type;

    netebpf_ext_helper_t helper;
    test_client_context_t client_context = {};

    // Look up the context descriptor for the requested program type.
    std::vector<GUID> guids = helper.program_info_provider_guids();
    for (const auto& guid : guids) {
        ebpf_extension_data_t extension_data = helper.get_program_info_provider_data(guid);
        auto& program_data = *reinterpret_cast<ebpf_program_data_t*>(extension_data.data);
        if (prog_type == (bpf_prog_type_t)program_data.program_info->program_type_descriptor.bpf_prog_type) {
            client_context.ctx_descriptor = program_data.program_info->program_type_descriptor.context_descriptor;
            break;
        }
    }
    if (client_context.ctx_descriptor == nullptr) {
        return 0;
    }

    // Register with NMR as if we were ebpfcore.sys.
    NPI_CLIENT_CHARACTERISTICS client_characteristics = {};
    client_characteristics.ClientRegistrationInstance.NpiId = &EBPF_HOOK_EXTENSION_IID;
    GUID module_guid = {/* dced0fd8-2922-436c-b3f0-e8609a3a2dc6 */
                        0xdced0fd8,
                        0x2922,
                        0x436c,
                        {0xb3, 0xf0, 0xe8, 0x60, 0x9a, 0x3a, 0x2d, 0xc6}};
    NPI_MODULEID module_id = {.Length = sizeof(NPI_MODULEID), .Type = MIT_GUID, .Guid = module_guid};
    client_characteristics.ClientRegistrationInstance.ModuleId = &module_id;
    NET_IFINDEX if_index = 0;
    ebpf_extension_data_t npi_specific_characteristics = {.size = sizeof(if_index), .data = &if_index};
    client_characteristics.ClientRegistrationInstance.NpiSpecificCharacteristics = &npi_specific_characteristics;
    client_characteristics.ClientAttachProvider = netebpf_fuzzer_attach_extension;
    client_characteristics.ClientDetachProvider = netebpf_fuzzer_detach_extension;
    client_characteristics.ClientCleanupBindingContext =
        (NPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN*)netebpfext_fuzzer_cleanup_binding_context;
    HANDLE nmr_client_handle;
    if (NmrRegisterClient(&client_characteristics, &client_context, &nmr_client_handle) != STATUS_SUCCESS) {
        return 0;
    }

    FWP_ACTION_TYPE result;

    // Verify we successfully attached to netebpfext.
    if (client_context.provider_binding_context == nullptr) {
        goto Done;
    }

    // Classify an inbound packet that should pass.
    client_context.metadata = *metadata;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    if (result != FWP_ACTION_PERMIT && result != FWP_ACTION_BLOCK) {
        goto Done;
    }

    // Classify an inbound packet that should be dropped.
    client_context.metadata = *metadata;
    result = helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
    if (result != FWP_ACTION_PERMIT && result != FWP_ACTION_BLOCK) {
        goto Done;
    }

Done:
    NTSTATUS status = NmrDeregisterClient(nmr_client_handle);
    if (status == STATUS_PENDING) {
        NmrWaitForClientDeregisterComplete(nmr_client_handle);
    }

    return 0; // Non-zero return values are reserved for future use.
}
