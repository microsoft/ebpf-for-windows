// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <sal.h>
#include <stdio.h>
#include <string>

class capture_helper_t final
{
  private:
    int _original_stdout_fd = -1;
    int _original_stderr_fd = -1;
    std::string _stdout_contents;
    std::string _stderr_contents;

    _Success_(return == 0) errno_t
        begin_fd_capture(_In_ FILE* fp, _Out_ int* original_fd, _In_z_ const char* temporary_filename);
    std::string
    end_fd_capture(_In_ FILE* fp, _Inout_ int* original_fd, _In_z_ const char* temporary_filename);
    void
    end_capture(void);

  public:
    errno_t
    begin_capture(void);
    ~capture_helper_t(void);
    std::string
    get_stdout_contents(void);
    std::string
    get_stderr_contents(void);
};