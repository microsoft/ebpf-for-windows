// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_result.h"
#include "platform.h"
#include "platform.hpp"
#include "windows_platform_common.hpp"

#include <map>
#include <stdexcept>
#include <vector>

static const ebpf_helper_function_prototype_t*
_get_helper_function_prototype(const ebpf_program_info_t* info, unsigned int n)
{
    for (uint32_t i = 0; i < info->count_of_program_type_specific_helpers; i++) {
        if (n == info->program_type_specific_helper_prototype[i].helper_id) {
            return &info->program_type_specific_helper_prototype[i];
        }
    }
    return nullptr;
}

// Check whether a given integer is a valid helper ID.
bool
is_helper_usable_windows(int32_t n)
{
    const ebpf_program_info_t* info = nullptr;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("helper not usable: ") + std::to_string(n));
    }
    return _get_helper_function_prototype(info, n) != nullptr;
}

// Get the prototype for the helper with a given ID.
EbpfHelperPrototype
get_helper_prototype_windows(int32_t n)
{
    const ebpf_program_info_t* info = nullptr;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("program type info not found."));
    }
    EbpfHelperPrototype verifier_prototype = {0};

    verifier_prototype.context_descriptor = info->program_type_descriptor.context_descriptor;

    const ebpf_helper_function_prototype_t* raw_prototype = _get_helper_function_prototype(info, n);
    if (raw_prototype == nullptr) {
        throw std::runtime_error(std::string("helper prototype not found: ") + std::to_string(n));
    }
    verifier_prototype.name = raw_prototype->name;

    verifier_prototype.return_type = raw_prototype->return_type;

    for (int i = 0; i < 5; i++) {
        verifier_prototype.argument_type[i] = raw_prototype->arguments[i];
    }

    return verifier_prototype;
}
