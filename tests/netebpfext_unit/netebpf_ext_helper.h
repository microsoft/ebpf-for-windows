// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <iostream>
#include <vector>

#include "catch_wrapper.hpp"
#include "ebpf_extension_uuids.h"
#include "ebpf_registry_helper.h"
#include "net_ebpf_ext.h"
#include "fwp_um.h"

typedef class _netebpf_ext_helper
{
  public:
    _netebpf_ext_helper();
    ~_netebpf_ext_helper();

    std::vector<GUID>
    program_info_provider_guids();

    ebpf_extension_data_t
    get_program_info_provider_data(const GUID& program_info_provider);

    FWP_ACTION_TYPE
    classify_test_packet(_In_ const GUID* layer_guid, NET_IFINDEX if_index)
    {
        return _fwp_engine::get()->classify_test_packet(layer_guid, if_index);
    }

  private:
    bool trace_initiated = false;
    bool ndis_handle_initialized = false;
    bool provider_registered = false;
    bool wfp_initialized = false;
    DRIVER_OBJECT* driver_object = reinterpret_cast<DRIVER_OBJECT*>(this);
    DEVICE_OBJECT* device_object = reinterpret_cast<DEVICE_OBJECT*>(this);

    struct NPI_MODULEID_LESS
    {
        bool
        operator()(const GUID& lhs, const GUID& rhs) const
        {
            int result = memcmp(&lhs, &rhs, sizeof(lhs));
            return result < 0;
        }
    };

    typedef struct _program_info_provider
    {
        _netebpf_ext_helper* parent;
        NPI_MODULEID module_id;
        void* context;
        const void* dispatch;
        const ebpf_extension_data_t* provider_data;
    } program_info_provider_t;
    std::map<GUID, std::unique_ptr<program_info_provider_t>, NPI_MODULEID_LESS> program_info_providers;

    static NTSTATUS
    _program_info_client_attach_provider(
        _In_ HANDLE nmr_binding_handle,
        _In_ PVOID client_context,
        _In_ PNPI_REGISTRATION_INSTANCE provider_registration_instance);

    static NTSTATUS
    _program_info_client_detach_provider(_In_ PVOID client_binding_context);

    static void
    _program_info_client_cleanup_binding_context(_In_ PVOID client_binding_context);

    NPI_MODULEID module_id = {};
    NPI_CLIENT_CHARACTERISTICS client{
        1,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        _program_info_client_attach_provider,
        _program_info_client_detach_provider,
        _program_info_client_cleanup_binding_context,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_PROGRAM_INFO_EXTENSION_IID,
            &module_id,
            0,
            nullptr,
        },
    };

    HANDLE nmr_client_handle;

} netebpf_ext_helper_t;
