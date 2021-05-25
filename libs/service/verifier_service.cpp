/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include "api_common.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "platform.hpp"
#include "Verifier.h"
#include "tlv.h"
#include "windows_platform_service.hpp"

static int
analyze(raw_program& raw_prog, const char** error_message, uint32_t* error_message_size = nullptr)
{
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
        *error_message = allocate_error_string(std::get<std::string>(prog_or_error), error_message_size);
        return 1; // Error;
    }
    InstructionSeq& prog = std::get<InstructionSeq>(prog_or_error);

    // First try optimized for the success case.
    ebpf_verifier_options_t options = ebpf_verifier_default_options;
    options.check_termination = true;
    bool res = ebpf_verify_program(std::cout, prog, raw_prog.info, &options);
    if (!res) {
        // On failure, retry to get the more detailed error message.
        std::ostringstream oss;
        options.no_simplify = true;
        options.print_failures = true;
        (void)ebpf_verify_program(oss, prog, raw_prog.info, &options);

        *error_message = allocate_error_string(oss.str(), error_message_size);
        return 1; // Error;
    }
    return 0; // Success.
}

int
verify_byte_code(
    const GUID* program_type,
    const uint8_t* byte_code,
    size_t byte_code_size,
    const char** error_message,
    uint32_t* error_message_size)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows_service;
    std::vector<ebpf_inst> instructions{(ebpf_inst*)byte_code,
                                        (ebpf_inst*)byte_code + byte_code_size / sizeof(ebpf_inst)};
    program_info info{platform};
    std::string section;
    std::string file;
    info.type = get_program_type_windows(*program_type);

    raw_program raw_prog{file, section, instructions, info};

    return analyze(raw_prog, error_message, error_message_size);
}
