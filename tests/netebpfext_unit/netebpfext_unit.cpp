// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "catch_wrapper.hpp"

#include "ebpf_registry_helper.h"

#include "net_ebpf_ext.h"

ebpf_registry_key_t ebpf_root_registry_key = HKEY_CURRENT_USER;
DEVICE_OBJECT* _net_ebpf_ext_driver_device_object;

class _netebpf_ext_helper
{
  public:
    _netebpf_ext_helper()
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
    }
    ~_netebpf_ext_helper()
    {
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

  private:
    bool trace_initiated = false;
    bool ndis_handle_initialized = false;
    bool provider_registered = false;
    bool wfp_initialized = false;
    DRIVER_OBJECT* driver_object = nullptr;
    DEVICE_OBJECT* device_object = nullptr;
};

TEST_CASE("start_stop_test", "[netebpfext]") { _netebpf_ext_helper hepler; }