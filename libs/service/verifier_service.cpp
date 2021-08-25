// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include "api_common.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_verifier_wrapper.hpp"
#include "platform.hpp"
#include "Verifier.h"
#include "tlv.h"
#include "windows_platform_service.hpp"

static ebpf_result_t
_analyze(raw_program& raw_prog, const char** error_message, uint32_t* error_message_size = nullptr)
{
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
        *error_message = allocate_string(std::get<std::string>(prog_or_error), error_message_size);
        return EBPF_VERIFICATION_FAILED; // Error;
    }
    InstructionSeq& prog = std::get<InstructionSeq>(prog_or_error);

    // First try optimized for the success case.
    ebpf_verifier_options_t options = ebpf_verifier_default_options;
    ebpf_verifier_stats_t stats;
    options.check_termination = true;
    bool res = ebpf_verify_program(std::cout, prog, raw_prog.info, &options, &stats);
    if (!res) {
        // On failure, retry to get the more detailed error message.
        std::ostringstream oss;
        options.no_simplify = true;
        options.print_failures = true;
        (void)ebpf_verify_program(oss, prog, raw_prog.info, &options, &stats);

        *error_message = allocate_string(oss.str(), error_message_size);
        return EBPF_VERIFICATION_FAILED; // Error;
    }
    return EBPF_SUCCESS; // Success.
}

ebpf_result_t
verify_byte_code(
    const GUID* program_type,
    const uint8_t* byte_code,
    size_t byte_code_size,
    const char** error_message,
    uint32_t* error_message_size)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows_service;
    std::vector<ebpf_inst> instructions{
        (ebpf_inst*)byte_code, (ebpf_inst*)byte_code + byte_code_size / sizeof(ebpf_inst)};
    program_info info{platform};
    std::string section;
    std::string file;
    info.type = get_program_type_windows(*program_type);

    raw_program raw_prog{file, section, instructions, info};

    return _analyze(raw_prog, error_message, error_message_size);
}
