// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "capture_helper.hpp"

#include <windows.h>
#include <fcntl.h>
#include <fstream>
#include <io.h>
#include <iostream>
#include <sal.h>
#include <sstream>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

// This class can be used by tests to catch stdout and stderr output.

#define TEMPORARY_STDOUT_FILENAME ".\\stdout.txt"
#define TEMPORARY_STDERR_FILENAME ".\\stderr.txt"

std::string
capture_helper_t::get_stdout_contents(void)
{
    end_capture();
    return _stdout_contents;
}

std::string
capture_helper_t::get_stderr_contents(void)
{
    end_capture();
    return _stderr_contents;
}

_Success_(return == 0) errno_t capture_helper_t::begin_fd_capture(
    _In_ FILE* fp, _Out_ int* original_fd, _In_z_ const char* temporary_filename)
{
    // Create a temporary file.
    int destination_fd;
    errno_t err =
        _sopen_s(&destination_fd, temporary_filename, _O_WRONLY | O_CREAT | O_TRUNC, _SH_DENYNO, _S_IREAD | _S_IWRITE);
    if (err != 0) {
        return err;
    }

    int standard_fileno = _fileno(fp);
    fflush(fp);
    *original_fd = _dup(standard_fileno);

    // Redirect fp to the temporary file.
    if (_dup2(destination_fd, standard_fileno) < 0) {
        err = errno;
    }
    _close(destination_fd);

    return err;
}

std::string
capture_helper_t::end_fd_capture(_In_ FILE* fp, _Inout_ int* original_fd, _In_z_ const char* temporary_filename)
{
    if (*original_fd == -1) {
        // Nothing to do.
        return {};
    }

    // Restore standard fd to original.
    int standard_fileno = _fileno(fp);
    fflush(fp);
    if (_dup2(*original_fd, standard_fileno) < 0) {
        fprintf(stderr, "Failed to restore stdout\n");
    }
    _close(*original_fd);
    *original_fd = -1;

    // Read the contents of the temporary file.
    std::ifstream stdout_fs(temporary_filename);
    std::string contents((std::istreambuf_iterator<char>(stdout_fs)), std::istreambuf_iterator<char>());
    stdout_fs.close();

    // Clean up the temporary file.
    int ret = _unlink(temporary_filename);
    if (ret) {
        printf("Error %d unlinking %s\n", errno, temporary_filename);
    }

    return contents;
}

errno_t
capture_helper_t::begin_capture(void)
{
    errno_t error = begin_fd_capture(stdout, &_original_stdout_fd, TEMPORARY_STDOUT_FILENAME);
    if (error != 0) {
        return error;
    }

    error = begin_fd_capture(stderr, &_original_stderr_fd, TEMPORARY_STDERR_FILENAME);
    if (error != 0) {
        end_fd_capture(stdout, &_original_stdout_fd, TEMPORARY_STDOUT_FILENAME);
        return error;
    }

    return 0;
}

void
capture_helper_t::end_capture(void)
{
    if (_original_stdout_fd != -1) {
        _stdout_contents = end_fd_capture(stdout, &_original_stdout_fd, TEMPORARY_STDOUT_FILENAME);
    }

    if (_original_stderr_fd != -1) {
        _stderr_contents = end_fd_capture(stderr, &_original_stderr_fd, TEMPORARY_STDERR_FILENAME);
    }
}

capture_helper_t::~capture_helper_t(void) { end_capture(); }
