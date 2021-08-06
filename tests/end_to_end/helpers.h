/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_api.h"
#include "ebpf_link.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"

typedef struct _ebpf_free_memory
{
    void
    operator()(uint8_t* memory)
    {
        ebpf_free(memory);
    }
} ebpf_free_memory_t;

typedef std::unique_ptr<uint8_t, ebpf_free_memory_t> ebpf_memory_t;

typedef class _single_instance_hook
{
  public:
    _single_instance_hook(ebpf_program_type_t program_type, ebpf_attach_type_t attach_type)
        : provider(nullptr), client_binding_context(nullptr), client_data(nullptr), client_dispatch_table(nullptr),
          link_handle(nullptr)
    {
        ebpf_guid_create(&client_id);
        attach_provider_data.supported_program_type = program_type;
        this->attach_type = attach_type;
        REQUIRE(
            ebpf_provider_load(
                &provider,
                &attach_type,
                nullptr,
                &provider_data,
                nullptr,
                this,
                client_attach_callback,
                client_detach_callback) == EBPF_SUCCESS);
    }
    ~_single_instance_hook() { ebpf_provider_unload(provider); }

    uint32_t
    attach(ebpf_handle_t program_handle)
    {
        return ebpf_api_link_program(program_handle, attach_type, &link_handle);
    }

    void
    detach()
    {
        ebpf_api_unlink_program(link_handle);
        ebpf_api_close_handle(link_handle);
    }

    void
    close_handle()
    {
        ebpf_api_close_handle(link_handle);
    }

    ebpf_result_t
    fire(void* context, int* result)
    {
        ebpf_result_t (*invoke_program)(void* link, void* context, int* result) =
            reinterpret_cast<decltype(invoke_program)>(client_dispatch_table->function[0]);

        return invoke_program(client_binding_context, context, result);
    }

  private:
    static ebpf_result_t
    client_attach_callback(
        void* context,
        const GUID* client_id,
        void* client_binding_context,
        const ebpf_extension_data_t* client_data,
        const ebpf_extension_dispatch_table_t* client_dispatch_table)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(context);
        hook->client_id = *client_id;
        hook->client_binding_context = client_binding_context;
        hook->client_data = client_data;
        hook->client_dispatch_table = client_dispatch_table;
        return EBPF_SUCCESS;
    };

    static ebpf_result_t
    client_detach_callback(void* context, const GUID* client_id)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(context);
        hook->client_binding_context = nullptr;
        hook->client_data = nullptr;
        hook->client_dispatch_table = nullptr;
        UNREFERENCED_PARAMETER(client_id);
        return EBPF_SUCCESS;
    };
    ebpf_attach_type_t attach_type;
    ebpf_attach_provider_data_t attach_provider_data;

    ebpf_extension_data_t provider_data = {
        EBPF_ATTACH_PROVIDER_DATA_VERSION, sizeof(attach_provider_data), &attach_provider_data};
    ebpf_extension_provider_t* provider;
    GUID client_id;
    void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
    ebpf_handle_t link_handle;
} single_instance_hook_t;

#define TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

static ebpf_helper_function_prototype_t _ebpf_map_helper_function_prototype[] = {
    {1,
     "bpf_map_lookup_elem",
     EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    {2,
     "bpf_map_update_elem",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
    {3,
     "bpf_map_delete_elem",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
    {4,
     "bpf_tail_call",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_ANYTHING}},
};

static ebpf_context_descriptor_t _ebpf_xdp_context_descriptor = {sizeof(xdp_md_t),
                                                                 EBPF_OFFSET_OF(xdp_md_t, data),
                                                                 EBPF_OFFSET_OF(xdp_md_t, data_end),
                                                                 EBPF_OFFSET_OF(xdp_md_t, data_meta)};
static ebpf_program_info_t _ebpf_xdp_program_info = {{"xdp", &_ebpf_xdp_context_descriptor, {0}},
                                                     EBPF_COUNT_OF(_ebpf_map_helper_function_prototype),
                                                     _ebpf_map_helper_function_prototype};

static ebpf_program_data_t _ebpf_xdp_program_data = {&_ebpf_xdp_program_info, NULL};

static ebpf_extension_data_t _ebpf_xdp_program_info_provider_data = {
    TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_xdp_program_data), &_ebpf_xdp_program_data};

static ebpf_context_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
static ebpf_program_info_t _ebpf_bind_program_info = {{"bind", &_ebpf_bind_context_descriptor, {0}},
                                                      EBPF_COUNT_OF(_ebpf_map_helper_function_prototype),
                                                      _ebpf_map_helper_function_prototype};

static ebpf_program_data_t _ebpf_bind_program_data = {&_ebpf_bind_program_info, NULL};

static ebpf_extension_data_t _ebpf_bind_program_info_provider_data = {
    TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_bind_program_data), &_ebpf_bind_program_data};

typedef class _program_info_provider
{
  public:
    _program_info_provider(ebpf_program_type_t program_type) : program_type(program_type)
    {
        ebpf_program_data_t* program_data;
        if (program_type == EBPF_PROGRAM_TYPE_XDP) {
            provider_data = &_ebpf_xdp_program_info_provider_data;
            program_data = (ebpf_program_data_t*)provider_data->data;
            program_data->program_info->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_XDP;
        } else if (program_type == EBPF_PROGRAM_TYPE_BIND) {
            provider_data = &_ebpf_bind_program_info_provider_data;
            program_data = (ebpf_program_data_t*)provider_data->data;
            program_data->program_info->program_type_descriptor.program_type = EBPF_PROGRAM_TYPE_BIND;
        }

        REQUIRE(
            ebpf_provider_load(&provider, &program_type, nullptr, provider_data, nullptr, nullptr, nullptr, nullptr) ==
            EBPF_SUCCESS);
    }
    ~_program_info_provider() { ebpf_provider_unload(provider); }

  private:
    ebpf_program_type_t program_type;

    ebpf_extension_data_t* provider_data;
    ebpf_extension_provider_t* provider;
} program_info_provider_t;

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length);
