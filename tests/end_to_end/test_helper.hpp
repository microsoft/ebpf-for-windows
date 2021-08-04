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
    _single_instance_hook* hook;
};
