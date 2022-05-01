// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

class _test_helper_end_to_end
{
  public:
    _test_helper_end_to_end();
    ~_test_helper_end_to_end();

  private:
    bool ec_initialized = false;
    bool api_initialized = false;
};

class _program_info_provider;
class _single_instance_hook;

class _test_helper_libbpf
{
  public:
    _test_helper_libbpf();
    ~_test_helper_libbpf();

  private:
    _test_helper_end_to_end test_helper_end_to_end;
    _program_info_provider* xdp_program_info;
    _single_instance_hook* xdp_hook;
    _program_info_provider* bind_program_info;
    _single_instance_hook* bind_hook;
    _program_info_provider* cgroup_sock_addr_program_info;
    _single_instance_hook* cgroup_inet4_connect_hook;
};

void
set_native_module_failures(bool expected);

ebpf_result_t
get_service_details_for_file(
    _In_ const std::wstring& file_path, _Out_ const wchar_t** service_name, _Out_ GUID* provider_guid);