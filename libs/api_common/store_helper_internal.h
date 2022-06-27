// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cassert>
#include <stdexcept>
#include "api_internal.h"
#include "api_common.hpp"
#include "crab_verifier_wrapper.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_protocol.h"
#include "ebpf_serialize.h"
#include "helpers.hpp"
#include "map_descriptors.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "utilities.hpp"
#include "windows_program_type.h"
#include "windows_platform.hpp"
#include "ebpf_registry_helper.h"

ebpf_result_t
ebpf_store_load_program_information(
    _Outptr_result_buffer_maybenull_(*program_info_count) ebpf_program_info_t*** program_info,
    _Out_ uint32_t* program_info_count);

ebpf_result_t
ebpf_store_load_section_information(
    _Outptr_result_buffer_maybenull_(*section_info_count) ebpf_section_definition_t*** section_info,
    _Out_ uint32_t* section_info_count);

ebpf_result_t
ebpf_store_load_global_helper_information(
    _Outptr_result_buffer_maybenull_(*global_helper_info_count) ebpf_helper_function_prototype_t** global_helper_info,
    _Out_ uint32_t* global_helper_info_count);