// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

class _test_helper_end_to_end
{
  public:
    _test_helper_end_to_end();
    ~_test_helper_end_to_end();
    void
    initialize();

  private:
    bool ec_initialized = false;
    bool api_initialized = false;
    bool service_initialized = false;
};

class _program_info_provider;
class _single_instance_hook;

class _test_helper_libbpf
{
  public:
    _test_helper_libbpf();
    ~_test_helper_libbpf();
    void
    initialize();

  private:
    _test_helper_end_to_end test_helper_end_to_end;
    _program_info_provider* xdp_program_info;
    _single_instance_hook* xdp_hook;
    _program_info_provider* bind_program_info;
    _single_instance_hook* bind_hook;
    _program_info_provider* cgroup_sock_addr_program_info;
    _single_instance_hook* cgroup_inet4_connect_hook;
    _program_info_provider* sample_program_info;
    _single_instance_hook* sample_hook;
    _program_info_provider* xdp_test_program_info;
    _single_instance_hook* xdp_test_hook;
};

class _test_handle_helper
{
  public:
    _test_handle_helper() : handle(ebpf_handle_invalid) {};
    _test_handle_helper(ebpf_handle_t handle) : handle(handle) {};
    _test_handle_helper(const _test_handle_helper& object) = delete;
    void
    operator=(const _test_handle_helper& object) = delete;
    ~_test_handle_helper();
    ebpf_handle_t*
    get_handle_pointer()
    {
        return &handle;
    };

  private:
    ebpf_handle_t handle = ebpf_handle_invalid;
};

void
set_native_module_failures(bool expected);

bool
get_native_module_failures();

_Must_inspect_result_ ebpf_result_t
get_service_details_for_file(
    _In_ const std::wstring& file_path, _Out_ const wchar_t** service_name, _Out_ GUID* provider_guid);
