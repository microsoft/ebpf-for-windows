/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_api.h"
#include "ebpf_link.h"
#include "ebpf_platform.h"

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
        REQUIRE(
            ebpf_provider_load(&provider, &program_type, nullptr, &provider_data, nullptr, nullptr, nullptr, nullptr) ==
            EBPF_ERROR_SUCCESS);
    }
    ~_program_information_provider() { ebpf_provider_unload(provider); }

  private:
    ebpf_program_type_t program_type;

    ebpf_extension_data_t provider_data = {0, 0};
    ebpf_extension_provider_t* provider;
} program_information_provider_t;