// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <stdexcept>
#include "api_common.hpp"
#include "api_internal.h"
#include "crab_verifier_wrapper.hpp"
#include "ebpf_api.h"
#include "helpers.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "windows_platform_common.hpp"
#include "windows_platform_service.hpp"

const ebpf_platform_t g_ebpf_platform_windows_service = {
    get_program_type_windows,
    get_helper_prototype_windows,
    is_helper_usable_windows,
    sizeof(ebpf_map_definition_in_memory_t),
    nullptr, // parse_maps_section_windows,
    get_map_descriptor_windows,
    get_map_type_windows,
};
