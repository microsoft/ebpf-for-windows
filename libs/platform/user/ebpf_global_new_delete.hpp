// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdint.h>

#pragma once
typedef class _ebpf_platform_new_delete_state
{
  public:
    typedef class _suppress
    {
      public:
        _suppress()
        {
            _ebpf_platform_new_delete_state::disable();
        }
        ~_suppress()
        {
            _ebpf_platform_new_delete_state::enable();
        }
    } suppress_t;
    static void
    enable()
    {
        enabled_count++;
    }
    static void
    disable()
    {
        enabled_count--;
    }
    static bool
    is_enabled()
    {
        return enabled_count > 0;
    }

    static void
    reset()
    {
        enabled_count = 0;
    }
    static thread_local int64_t enabled_count;
} ebpf_platform_new_delete_state_t;

inline thread_local int64_t _ebpf_platform_new_delete_state::enabled_count = 0;
