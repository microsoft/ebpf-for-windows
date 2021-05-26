// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "ebpf_program_types.h"
#include "ebpf_result.h"
#include "ebpf_windows.h"
#include "platform.hpp"
#include "Verifier.h"

static ebpf_helper_function_prototype_t*
_get_helper_function_prototype(const ebpf_program_information_t* info, unsigned int n)
{
    for (uint32_t i = 0; i < info->count_of_helpers; i++) {
        if (n == info->helper_prototype[i].helper_id) {
            return &info->helper_prototype[i];
        }
    }
    return nullptr;
}

// Check whether a given integer is a valid helper ID.
bool
is_helper_usable_windows(unsigned int n)
{
    const ebpf_program_information_t* info;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::exception();
    }
    return _get_helper_function_prototype(info, n) != nullptr;
}

// Get the prototype for the helper with a given ID.
EbpfHelperPrototype
get_helper_prototype_windows(unsigned int n)
{
    const ebpf_program_information_t* info;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::exception();
    }
    EbpfHelperPrototype verifier_prototype = {0};

    // TODO (issue #153): remove duplicate struct for ebpf_context_descriptor_t so no cast is needed.
    verifier_prototype.context_descriptor = (EbpfContextDescriptor*)info->program_type_descriptor.context_descriptor;

    ebpf_helper_function_prototype_t* raw_prototype = _get_helper_function_prototype(info, n);
    if (raw_prototype == nullptr) {
        throw std::exception();
    }
    verifier_prototype.name = raw_prototype->name;

    // TODO (issue #153): remove duplicate enum for ebpf_helper_return_type_t so no cast is needed.
    // Today one is a C++ enum class and the other is a C enum, but the values match.
    verifier_prototype.return_type = (EbpfHelperReturnType)raw_prototype->return_type;

    for (int i = 0; i < 5; i++) {
        // TODO (issue #153): remove duplicate enum for ebpf_helper_argument_type_t so no cast is needed.
        // Today one is a C++ enum class and the other is a C enum, but the values match.
        verifier_prototype.argument_type[i] = (EbpfHelperArgumentType)raw_prototype->arguments[i];
    }

    return verifier_prototype;
}
