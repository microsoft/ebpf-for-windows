// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Lightweight RAII wrappers for common handle types.
 *
 * This header has minimal dependencies (just Windows headers) so it can be used
 * in contexts where including ebpf headers is not desirable.
 */

#include <windows.h>
#include <io.h>

/**
 * @brief RAII wrapper for Windows HANDLE.
 */
struct unique_handle
{
    unique_handle() = default;
    explicit unique_handle(HANDLE handle) : _handle(handle) {}
    ~unique_handle() { reset(); }

    unique_handle(const unique_handle&) = delete;
    unique_handle&
    operator=(const unique_handle&) = delete;

    unique_handle(unique_handle&& other) noexcept : _handle(other._handle) { other._handle = nullptr; }
    unique_handle&
    operator=(unique_handle&& other) noexcept
    {
        if (this != &other) {
            reset();
            _handle = other._handle;
            other._handle = nullptr;
        }
        return *this;
    }

    void
    reset(HANDLE handle = nullptr) noexcept
    {
        if (_handle != nullptr && _handle != INVALID_HANDLE_VALUE) {
            CloseHandle(_handle);
        }
        _handle = handle;
    }

    HANDLE
    get() const noexcept { return _handle; }

    HANDLE
    release() noexcept
    {
        HANDLE handle = _handle;
        _handle = nullptr;
        return handle;
    }

    explicit
    operator bool() const noexcept
    {
        return _handle != nullptr && _handle != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE _handle{nullptr};
};

/**
 * @brief RAII wrapper for Windows SC_HANDLE (Service Control Manager handle).
 */
struct unique_sc_handle
{
    unique_sc_handle() = default;
    explicit unique_sc_handle(SC_HANDLE handle) : _handle(handle) {}
    ~unique_sc_handle() { reset(); }

    unique_sc_handle(const unique_sc_handle&) = delete;
    unique_sc_handle&
    operator=(const unique_sc_handle&) = delete;

    unique_sc_handle(unique_sc_handle&& other) noexcept : _handle(other._handle) { other._handle = nullptr; }
    unique_sc_handle&
    operator=(unique_sc_handle&& other) noexcept
    {
        if (this != &other) {
            reset();
            _handle = other._handle;
            other._handle = nullptr;
        }
        return *this;
    }

    void
    reset(SC_HANDLE handle = nullptr) noexcept
    {
        if (_handle != nullptr) {
            CloseServiceHandle(_handle);
        }
        _handle = handle;
    }

    SC_HANDLE
    get() const noexcept { return _handle; }

    explicit
    operator bool() const noexcept
    {
        return _handle != nullptr;
    }

  private:
    SC_HANDLE _handle{nullptr};
};

/**
 * @brief RAII wrapper for file descriptors.
 */
struct unique_fd
{
    unique_fd() = default;
    explicit unique_fd(int fd) : _fd(fd) {}
    ~unique_fd() { reset(); }

    unique_fd(const unique_fd&) = delete;
    unique_fd&
    operator=(const unique_fd&) = delete;

    unique_fd(unique_fd&& other) noexcept : _fd(other._fd) { other._fd = -1; }
    unique_fd&
    operator=(unique_fd&& other) noexcept
    {
        if (this != &other) {
            reset();
            _fd = other._fd;
            other._fd = -1;
        }
        return *this;
    }

    void
    reset(int fd = -1) noexcept
    {
        if (_fd >= 0) {
            _close(_fd);
        }
        _fd = fd;
    }

    int
    get() const noexcept
    {
        return _fd;
    }

    int
    release() noexcept
    {
        int fd = _fd;
        _fd = -1;
        return fd;
    }

    explicit
    operator bool() const noexcept
    {
        return _fd >= 0;
    }

  private:
    int _fd{-1};
};
