// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <cassert>
#include <stdexcept>
#include "api_internal.h"
#include "api_common.hpp"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#include "crab_verifier.hpp"
#pragma warning(pop)
#include "ebpf_api.h"
#undef VOID
#include "ebpf_helpers.h"
#include "helpers.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "windows_platform_service.hpp"
#include "windows_platform_common.hpp"

const ebpf_platform_t g_ebpf_platform_windows_service = {
    get_program_type_windows,
    get_helper_prototype_windows,
    is_helper_usable_windows,
    sizeof(ebpf_maps_section_record_windows),
    nullptr, // parse_maps_section_windows,
    get_map_descriptor_windows,
    get_map_type_windows,
};
