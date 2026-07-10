// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>
#include "sample_ext_ioctls.h"

#include <Windows.h>
#include <vector>

class _sample_extension_helper
{
  public:
    _sample_extension_helper(bool log_invoke_errors = true);
    ~_sample_extension_helper();

    bool
    invoke(std::vector<char>& input_buffer, std::vector<char>& output_buffer);

    bool
    invoke_by_attach_parameter(
        const void* attach_parameter,
        size_t attach_parameter_size,
        std::vector<char>& input_buffer,
        std::vector<char>& output_buffer);

    bool
    try_invoke_by_attach_parameter(
        const void* attach_parameter,
        size_t attach_parameter_size,
        std::vector<char>& input_buffer,
        std::vector<char>& output_buffer);

    bool
    invoke_batch(std::vector<char>& input_buffer, std::vector<char>& output_buffer);

  private:
    HANDLE _device_handle;
    bool _log_invoke_errors;
};
