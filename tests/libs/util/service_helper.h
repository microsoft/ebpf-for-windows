// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "header.h"

class service_install_helper
{
  public:
    service_install_helper(std::wstring _service_name, std::wstring _binary_name, DWORD _service_type)
        : service_name(_service_name), binary_name(_binary_name), service_type(_service_type), service_handle(nullptr),
          scm_handle(nullptr), already_installed(false), initialized(false)
    {
        initialize();
    }

    ~service_install_helper() { cleanup(); }

    int
    initialize(void);
    void
    cleanup(void);
    int
    start_service(void);
    int
    stop_service(void);
    bool
    check_service_state(DWORD expected_state, DWORD* final_state);

  private:
    std::wstring service_name;
    std::wstring binary_name;
    SC_HANDLE service_handle;
    SC_HANDLE scm_handle;
    DWORD service_type;
    bool already_installed;
    bool initialized;
};