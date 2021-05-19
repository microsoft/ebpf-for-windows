// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "header.h"

class service_install_helper
{
  public:
    service_install_helper(std::wstring _service_name, std::wstring _binary_name)
        : service_name(_service_name), binary_name(_binary_name), service_handle(nullptr), scm_handle(nullptr),
          already_installed(false)
    {}

    ~service_install_helper() { uninitialize(); }

    int
    initialize();
    void
    uninitialize();
    int
    start_service();
    int
    stop_service();

  private:
    std::wstring service_name;
    std::wstring binary_name;
    SC_HANDLE service_handle;
    SC_HANDLE scm_handle;
    bool already_installed;
};
