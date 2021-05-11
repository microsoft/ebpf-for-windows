/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include "ebpf_api.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_xdp_program_data.h"

#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "platform.hpp"
#include "tlv.h"
#include "windows_platform.hpp"
#include "Verifier.h"

int
get_file_size(const char* filename, size_t* byte_code_size)
{
    int result = 0;
    *byte_code_size = NULL;
    struct stat st = {0};
    result = stat(filename, &st);
    if (!result) {
        std::cout << "file size " << st.st_size << std::endl;
        *byte_code_size = st.st_size;
    }

    return result;
}

static const char*
allocate_error_string(const std::string& str)
{
    char* retval;
    size_t error_message_length = str.size() + 1;
    retval = (char*)malloc(error_message_length);
    if (retval != nullptr) {
        strcpy_s(retval, error_message_length, str.c_str());
    }
    return retval; // Error;
}

static int
analyze(raw_program& raw_prog, const char** error_message)
{
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
        *error_message = allocate_error_string(std::get<std::string>(prog_or_error));
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

        *error_message = allocate_error_string(oss.str());
        return 1; // Error;
    }
    return 0; // Success.
}

int
load_byte_code(
    const char* filename,
    const char* sectionname,
    uint8_t* byte_code,
    size_t* byte_code_size,
    ebpf_program_type_t* program_type,
    const char** error_message)
{
    try {

        ebpf_verifier_options_t verifier_options{false, false, false, false};
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;

        auto raw_progs = read_elf(filename, sectionname, &verifier_options, platform);
        if (raw_progs.size() != 1) {
            return 1; // Error
        }
        raw_program raw_prog = raw_progs.back();

        // Sanity check that we have a program type GUID.
        if (raw_prog.info.type.platform_specific_data == 0) {
            return 1; // Error
        }

        // copy out the bytecode for the jitter
        size_t ebpf_bytes = raw_prog.prog.size() * sizeof(ebpf_inst);
        int i = 0;
        for (ebpf_inst inst : raw_prog.prog) {
            char* buf = (char*)&inst;
            for (int j = 0; j < sizeof(ebpf_inst) && i < ebpf_bytes; i++, j++) {
                byte_code[i] = buf[j];
            }
        }

        *byte_code_size = ebpf_bytes;
        *program_type = *(const GUID*)raw_prog.info.type.platform_specific_data;
    } catch (std::runtime_error& err) {
        auto message = err.what();
        auto message_length = strlen(message) + 1;
        char* error = reinterpret_cast<char*>(calloc(message_length + 1, sizeof(char)));
        if (error) {
            strcpy_s(error, message_length, message);
        }
        *error_message = error;
        return ERROR_INVALID_PARAMETER;
    }

    return 0;
}

int
verify_byte_code(
    const char* path,
    const char* section_name,
    const uint8_t* byte_code,
    size_t byte_code_size,
    const char** error_message)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::vector<ebpf_inst> instructions{
        (ebpf_inst*)byte_code, (ebpf_inst*)byte_code + byte_code_size / sizeof(ebpf_inst)};
    program_info info{platform};
    info.type = platform->get_program_type(section_name, path);

    raw_program raw_prog{path, section_name, instructions, info};

    return analyze(raw_prog, error_message);
}

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions)
{
    std::vector<uint8_t> retval(instructions.size() * sizeof(ebpf_inst));
    memcpy(retval.data(), instructions.data(), retval.size());
    return retval;
}

uint32_t
ebpf_api_elf_enumerate_sections(
    const char* file,
    const char* section,
    bool verbose,
    const struct _tlv_type_length_value** data,
    const char** error_message)
{
    ebpf_verifier_options_t verifier_options{false, false, false, false, true};
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream str;
    try {
        auto raw_programs = read_elf(file, section ? std::string(section) : std::string(), &verifier_options, platform);
        tlv_sequence sequence;
        for (const auto& raw_program : raw_programs) {
            tlv_sequence stats_sequence;
            if (verbose) {
                std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
                if (std::holds_alternative<std::string>(programOrError)) {
                    std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
                    return 1;
                }
                auto& program = std::get<InstructionSeq>(programOrError);
                cfg_t controlFlowGraph = prepare_cfg(program, raw_program.info, true);
                std::map<std::string, int> stats = collect_stats(controlFlowGraph);
                for (const auto& [key, value] : stats) {
                    stats_sequence.emplace_back(tlv_pack<tlv_sequence>({tlv_pack(key.c_str()), tlv_pack(value)}));
                }
            }

            sequence.emplace_back(tlv_pack<tlv_sequence>(
                {tlv_pack(raw_program.section.c_str()),
                 tlv_pack(raw_program.info.type.platform_specific_data),
                 tlv_pack(raw_program.info.map_descriptors.size()),
                 tlv_pack(convert_ebpf_program_to_bytes(raw_program.prog)),
                 tlv_pack(stats_sequence)}));
        }

        auto retval = tlv_pack(sequence);
        auto local_data = reinterpret_cast<tlv_type_length_value_t*>(malloc(retval.size()));
        memcpy(local_data, retval.data(), retval.size());
        *data = local_data;
    } catch (std::runtime_error e) {
        str << "error: " << e.what();
        *error_message = allocate_error_string(str.str());
        return 1;
    }

    return 0;
}

uint32_t
ebpf_api_elf_disassemble_section(
    const char* file, const char* section, const char** disassembly, const char** error_message)
{
    ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream error;
    std::ostringstream output;
    try {
        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        raw_program raw_program = raw_programs.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_error_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);
        print(program, output, {});
        *disassembly = allocate_error_string(output.str());
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_error_string(error.str());
        return 1;
    } catch (std::exception ex) {
        error << "Failed to load eBPF program from " << file;
        *error_message = allocate_error_string(error.str());
        return 1;
    }
    return 0;
}

uint32_t
ebpf_api_elf_verify_section(
    const char* file, const char* section, bool verbose, const char** report, const char** error_message)
{
    std::ostringstream error;

    std::ostringstream output;
    ebpf_error_code_t result;
    ebpf_program_information_t* program_information_xdp = NULL;
    ebpf_program_information_t* program_information_bind = NULL;
    ebpf_helper::ebpf_memory_ptr program_information_xdp_ptr;
    ebpf_helper::ebpf_memory_ptr program_information_bind_ptr;

    result = ebpf_program_information_decode(
        &program_information_bind,
        _ebpf_encoded_bind_program_information_data,
        sizeof(_ebpf_encoded_bind_program_information_data));
    if (result != ERROR_SUCCESS) {
        return result;
    }
    program_information_bind_ptr.reset(program_information_bind);

    result = ebpf_program_information_decode(
        &program_information_xdp,
        _ebpf_encoded_xdp_program_information_data,
        sizeof(_ebpf_encoded_xdp_program_information_data));
    if (result != ERROR_SUCCESS) {
        return result;
    }
    program_information_xdp_ptr.reset(program_information_xdp);

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
        verifier_options.check_termination = true;
        verifier_options.print_invariants = verbose;
        verifier_options.print_failures = true;
        verifier_options.mock_map_fds = true;

        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        raw_program raw_program = raw_programs.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_error_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);

        // Try again without simplifying.
        verifier_options.no_simplify = true;
        bool res = ebpf_verify_program(output, program, raw_program.info, &verifier_options);
        if (!res) {
            error << "Verification failed";
            *error_message = allocate_error_string(error.str());
            *report = allocate_error_string(output.str());
            return 1;
        }

        output << "Verification succeeded";
        *report = allocate_error_string(output.str());
        return 0;
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_error_string(error.str());
        return 1;
    } catch (std::exception ex) {
        error << "Failed to load eBPF program from " << file;
        *error_message = allocate_error_string(error.str());
    }

    return 0;
}

void
ebpf_api_elf_free(const tlv_type_length_value_t* data)
{
    free(const_cast<tlv_type_length_value_t*>(data));
}
