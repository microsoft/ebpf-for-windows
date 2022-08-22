// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "catch_wrapper.hpp"

#include "ebpf_registry_helper.h"

#include "net_ebpf_ext.h"

ebpf_registry_key_t ebpf_root_registry_key = HKEY_CURRENT_USER;
void** _net_ebpf_ext_driver_device_object;

TEST_CASE("empty_test", "[netebpfext]") {}