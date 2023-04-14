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
    netebpfext_helper_base_client_context_t base;
    const ebpf_context_descriptor_t* ctx_descriptor;
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

    // Sanity check ctx_length against prog type specific max (hard coded).
    if ((size_t)metadata->ctx_offset + metadata->ctx_length > context_size) {
        *result = (uint32_t)-1;
        return EBPF_SUCCESS;
    }

    // Copy over some portion of the data if requested.
    if (metadata->data_length > 0) {
        uint8_t* ctx_data_end = *(uint8_t**)((char*)context + client_context->ctx_descriptor->end);
        uint8_t* ctx_data = *(uint8_t**)((char*)context + client_context->ctx_descriptor->data);

        // Sanity check data_length against ctx descriptor.
        if ((size_t)metadata->data_offset + metadata->data_length > (size_t)(ctx_data_end - ctx_data)) {
            *result = (uint32_t)-1;
            return EBPF_SUCCESS;
        }

        for (int i = metadata->data_offset; i < metadata->data_offset + metadata->data_length; i++) {
            ctx_data[i] = 0xde;
        }
    }

    // Copy over some portion of the ctx if requested.
    for (int i = metadata->ctx_offset; i < metadata->ctx_offset + metadata->ctx_length; i++) {
        ((uint8_t*)context)[i] = 0xad;
    }

    *result = client_context->metadata.return_value;
    return EBPF_SUCCESS;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    if (size < sizeof(netebpfext_fuzzer_metadata_t)) {
        return 0;
    }
    netebpfext_fuzzer_metadata_t* metadata = (netebpfext_fuzzer_metadata_t*)data;

    // Read program type.
    bpf_prog_type_t prog_type = (bpf_prog_type_t)metadata->prog_type;

    NET_IFINDEX if_index = 0;
    ebpf_extension_data_t npi_specific_characteristics = {.size = sizeof(if_index), .data = &if_index};
    test_client_context_t client_context = {};
    netebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)netebpfext_unit_invoke_program,
        &client_context.base);

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
    if (client_context.ctx_descriptor->data < 0 && metadata->data_length > 0) {
        // This program type does not use a data buffer.
        return 0;
    }

    fwp_classify_parameters_t parameters = {};
    netebpfext_initialize_fwp_classify_parameters(&parameters);

    client_context.metadata = *metadata;
    switch (prog_type) {
    case BPF_PROG_TYPE_XDP:
        (void)helper.classify_test_packet(&FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, if_index);
        break;
    case BPF_PROG_TYPE_BIND:
        (void)helper.test_bind_ipv4(&parameters);
        break;
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
        (void)helper.test_cgroup_inet4_recv_accept(&parameters);
        (void)helper.test_cgroup_inet6_recv_accept(&parameters);
        (void)helper.test_cgroup_inet4_connect(&parameters);
        (void)helper.test_cgroup_inet6_connect(&parameters);
        break;
    case BPF_PROG_TYPE_SOCK_OPS:
        (void)helper.test_sock_ops_v4(&parameters);
        (void)helper.test_sock_ops_v6(&parameters);
        break;
    }

    return 0; // Non-zero return values are reserved for future use.
}
