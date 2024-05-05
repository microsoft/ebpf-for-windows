// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once
#include "header.h"

class service_install_helper
{
  public:
    service_install_helper(std::wstring _service_name, std::wstring _binary_name, unsigned long _service_type)
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
    check_service_state(unsigned long expected_state, unsigned long* final_state);

  private:
    std::wstring service_name;
    std::wstring binary_name;
    SC_HANDLE service_handle;
    SC_HANDLE scm_handle;
    unsigned long service_type;
    bool already_installed;
    bool initialized;
};
