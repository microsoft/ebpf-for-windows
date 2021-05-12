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
    _single_instance_hook()
    {
        ebpf_guid_create(&attach_type);

        REQUIRE(
            ebpf_provider_load(
                &provider,
                &attach_type,
                nullptr,
                &provider_data,
                nullptr,
                this,
                client_attach_callback,
                client_detach_callback) == EBPF_ERROR_SUCCESS);
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
        ebpf_api_close_handle(link_handle);
    }

    ebpf_error_code_t
    fire(void* context, uint32_t* result)
    {
        ebpf_error_code_t (*invoke_program)(void* link, void* context, uint32_t* result) =
            reinterpret_cast<decltype(invoke_program)>(client_dispatch_table->function[0]);

        return invoke_program(client_binding_context, context, result);
    }

  private:
    static ebpf_error_code_t
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
        return EBPF_ERROR_SUCCESS;
    };

    static ebpf_error_code_t
    client_detach_callback(void* context, const GUID* client_id)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(context);
        hook->client_binding_context = nullptr;
        hook->client_data = nullptr;
        hook->client_dispatch_table = nullptr;
        UNREFERENCED_PARAMETER(client_id);
        return EBPF_ERROR_SUCCESS;
    };
    ebpf_attach_type_t attach_type;

    ebpf_extension_data_t provider_data = {0, 0};
    ebpf_extension_provider_t* provider;
    GUID client_id;
    void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
    ebpf_handle_t link_handle;
} single_instance_hook_t;

typedef class _program_information_provider
{
  public:
    _program_information_provider(ebpf_program_type_t program_type) : program_type(program_type)
    {
        if (program_type == EBPF_PROGRAM_TYPE_XDP)
            encode_xdp();
        else if (program_type == EBPF_PROGRAM_TYPE_BIND)
            encode_bind();

        REQUIRE(
            ebpf_provider_load(
                &provider,
                &program_type,
                nullptr,
                reinterpret_cast<ebpf_extension_data_t*>(provider_data.data()),
                nullptr,
                nullptr,
                nullptr,
                nullptr) == EBPF_ERROR_SUCCESS);
    }
    ~_program_information_provider() { ebpf_provider_unload(provider); }

  private:
    void
    encode_bind()
    {
        ebpf_helper_function_prototype_t helper_functions[] = {
            {1,
             "ebpf_map_lookup_element",
             EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
             {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
            {2,
             "ebpf_map_update_element",
             EBPF_RETURN_TYPE_INTEGER,
             {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
            {3,
             "ebpf_map_delete_element",
             EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
             {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
        };
        ebpf_context_descriptor_t context_descriptor{
            sizeof(bind_md_t), EBPF_OFFSET_OF(bind_md_t, app_id_start), EBPF_OFFSET_OF(bind_md_t, app_id_end), -1};
        ebpf_program_type_descriptor_t program_type_descriptor{"bind", &context_descriptor, EBPF_PROGRAM_TYPE_BIND};
        ebpf_program_information_t program_information{
            program_type_descriptor, _countof(helper_functions), helper_functions};
        uint8_t* buffer;
        unsigned long buffer_size;
        REQUIRE(ebpf_program_information_encode(&program_information, &buffer, &buffer_size) == EBPF_ERROR_SUCCESS);
        // Capture the buffer so that it's freed on scope exit.
        ebpf_memory_t memory(buffer);

        provider_data.resize(EBPF_OFFSET_OF(ebpf_extension_data_t, data) + buffer_size);
        ebpf_extension_data_t* extension_data = reinterpret_cast<ebpf_extension_data_t*>(provider_data.data());
        extension_data->size = static_cast<uint16_t>(provider_data.size());
        extension_data->version = 0;
        memcpy(extension_data->data, buffer, buffer_size);
    }

    void
    encode_xdp()
    {
        ebpf_helper_function_prototype_t helper_functions[] = {
            {1,
             "ebpf_map_lookup_element",
             EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
             {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
            {2,
             "ebpf_map_update_element",
             EBPF_RETURN_TYPE_INTEGER,
             {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
            {3,
             "ebpf_map_delete_element",
             EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
             {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY}},
        };
        ebpf_context_descriptor_t context_descriptor{
            sizeof(xdp_md_t),
            EBPF_OFFSET_OF(xdp_md_t, data),
            EBPF_OFFSET_OF(xdp_md_t, data_end),
            EBPF_OFFSET_OF(xdp_md_t, data_meta)};
        ebpf_program_type_descriptor_t program_type_descriptor{"xdp", &context_descriptor, EBPF_PROGRAM_TYPE_XDP};
        ebpf_program_information_t program_information{
            program_type_descriptor, _countof(helper_functions), helper_functions};
        uint8_t* buffer;
        unsigned long buffer_size;
        REQUIRE(ebpf_program_information_encode(&program_information, &buffer, &buffer_size) == EBPF_ERROR_SUCCESS);
        // Capture the buffer so that it's freed on scope exit.
        ebpf_memory_t memory(buffer);

        provider_data.resize(EBPF_OFFSET_OF(ebpf_extension_data_t, data) + buffer_size);
        ebpf_extension_data_t* extension_data = reinterpret_cast<ebpf_extension_data_t*>(provider_data.data());
        extension_data->size = static_cast<uint16_t>(provider_data.size());
        extension_data->version = 0;
        memcpy(extension_data->data, buffer, buffer_size);
    }
    ebpf_program_type_t program_type;

    std::vector<uint8_t> provider_data;
    ebpf_extension_provider_t* provider;
} program_information_provider_t;